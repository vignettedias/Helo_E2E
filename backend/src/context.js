'use strict';
/**
 * Request context shared by the route modules: authentication, rate limiting,
 * the delivery wake-up queue, and small lookups several routes need.
 *
 * Authentication here proves "this connection controls this account (and,
 * with a device token, this device)". It says nothing about cryptographic
 * peer identity -- that is the clients' job, end to end.
 */

const auth = require('./auth');
const { HttpError } = require('./http');

const now = () => Math.floor(Date.now() / 1000);

/** A device with no request for this long is no longer reported online. */
const ONLINE_GRACE_SECONDS = 35;

function createContext({ db, limiter }) {
  // deviceId -> Set<() => void>: long-poll requests waiting for a message.
  const waiters = new Map();
  // deviceId -> Set<ServerResponse>: SSE wake-up streams.
  const streams = new Map();

  function requireAuth(req) {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) throw new HttpError(401, 'missing_token');
    const session = auth.resolveToken(db, token);
    if (!session) throw new HttpError(401, 'invalid_token');
    if (session.deviceId) {
      const device = db.prepare('SELECT revoked_at FROM devices WHERE device_id = ?')
        .get(session.deviceId);
      if (device && device.revoked_at !== null) {
        throw new HttpError(401, 'device_revoked');
      }
      db.prepare('UPDATE devices SET last_seen_at = ? WHERE device_id = ?')
        .run(now(), session.deviceId);
    }
    return { ...session, token };
  }

  /**
   * Routes that act AS a device (sending, reading a queue, uploading) require
   * a device-bound token. An account token proves only the account, and the
   * relay must never take a device identity from the request body instead.
   */
  function requireDevice(req) {
    const session = requireAuth(req);
    if (!session.deviceId) throw new HttpError(403, 'device_token_required');
    return session;
  }

  function rateLimit(bucket, subject) {
    const result = limiter.check(bucket, subject);
    if (!result.allowed) {
      const err = new HttpError(429, 'rate_limited');
      err.retryAfter = result.retryAfter;
      throw err;
    }
  }

  function recordEvent(accountId, kind, deviceId = null) {
    db.prepare(
      'INSERT INTO security_events (account_id, kind, device_id, created_at) VALUES (?, ?, ?, ?)'
    ).run(accountId, kind, deviceId, now());
  }

  function accountByUsername(username) {
    return db.prepare('SELECT account_id, username FROM accounts WHERE username = ?')
      .get(String(username).toLowerCase()) || null;
  }

  function accountOfDevice(deviceId) {
    return db.prepare(
      `SELECT d.account_id, d.revoked_at, a.username FROM devices d
       JOIN accounts a ON a.account_id = d.account_id WHERE d.device_id = ?`
    ).get(deviceId) || null;
  }

  function isBlocked(blockerAccount, blockedAccount) {
    return db.prepare(
      'SELECT 1 FROM blocks WHERE blocker_account = ? AND blocked_account = ?'
    ).get(blockerAccount, blockedAccount) !== undefined;
  }

  function settingsOf(accountId) {
    const row = db.prepare(
      'SELECT show_online, show_last_seen FROM account_settings WHERE account_id = ?'
    ).get(accountId);
    return {
      show_online: row ? row.show_online === 1 : true,
      show_last_seen: row ? row.show_last_seen === 1 : true,
    };
  }

  // ------------------------------------------------- delivery wake-ups

  /**
   * Wake every long-poll and SSE stream waiting on `deviceId`. The wake-up
   * carries NO message content; the client then fetches over its
   * authenticated request, so a leaky proxy learns only that traffic occurred.
   */
  function notify(deviceId) {
    for (const wake of [...(waiters.get(deviceId) || [])]) wake();
    for (const res of streams.get(deviceId) || []) {
      try { res.write('event: message\ndata: {"pending":true}\n\n'); } catch { /* dropped */ }
    }
  }

  /** Resolve after `ms`, on a notify for `deviceId`, or when `res` closes. */
  function waitForMessage(deviceId, ms, res) {
    return new Promise((resolve) => {
      let set = waiters.get(deviceId);
      if (!set) { set = new Set(); waiters.set(deviceId, set); }
      const wake = () => {
        clearTimeout(timer);
        res.off('close', wake);
        set.delete(wake);
        if (set.size === 0) waiters.delete(deviceId);
        resolve();
      };
      const timer = setTimeout(wake, ms);
      set.add(wake);
      res.on('close', wake);
    });
  }

  function addStream(deviceId, res) {
    if (!streams.has(deviceId)) streams.set(deviceId, new Set());
    streams.get(deviceId).add(res);
  }

  function removeStream(deviceId, res) {
    const set = streams.get(deviceId);
    if (set) { set.delete(res); if (set.size === 0) streams.delete(deviceId); }
  }

  /** Release every pending long-poll, e.g. when the server shuts down. */
  function releaseAll() {
    for (const set of waiters.values()) for (const wake of [...set]) wake();
  }

  /** Online = holding a delivery connection now, or seen very recently. */
  function isOnline(accountId) {
    const devices = db.prepare(
      'SELECT device_id, last_seen_at FROM devices WHERE account_id = ? AND revoked_at IS NULL'
    ).all(accountId);
    const t = now();
    return devices.some((d) => waiters.has(d.device_id) || streams.has(d.device_id)
      || (d.last_seen_at !== null && t - d.last_seen_at <= ONLINE_GRACE_SECONDS));
  }

  function lastSeen(accountId) {
    const row = db.prepare(
      'SELECT MAX(last_seen_at) AS t FROM devices WHERE account_id = ? AND revoked_at IS NULL'
    ).get(accountId);
    return row ? row.t : null;
  }

  return {
    db, limiter, now,
    requireAuth, requireDevice, rateLimit, recordEvent,
    accountByUsername, accountOfDevice, isBlocked, settingsOf,
    notify, waitForMessage, addStream, removeStream, releaseAll, isOnline, lastSeen,
  };
}

module.exports = { createContext, now, ONLINE_GRACE_SECONDS };
