'use strict';
/**
 * User discovery, presence, blocking and reporting.
 *
 * Discovery is EXACT-MATCH only (no prefix search, no listing) and rate
 * limited: knowing a username is required to find its owner. A user who has
 * blocked the requester is indistinguishable from one who does not exist.
 */

const { randomUUID } = require('node:crypto');
const { HttpError, readJson } = require('../http');
const { ValidationError, requireString, ID } = require('../validate');

const REPORT_REASONS = new Set(['spam', 'abuse', 'impersonation', 'other']);

module.exports = function socialRoutes(app) {
  const { db } = app;

  /** Look up a target account as seen by `viewerAccount`; blocked == absent. */
  function visibleAccount(username, viewerAccount) {
    if (!ID.test(String(username))) return null;
    const target = app.accountByUsername(username);
    if (!target || app.isBlocked(target.account_id, viewerAccount)) return null;
    return target;
  }

  return {
    /**
     * Directory lookup: the target's username and the PUBLIC identity of each
     * active device. Clients pin each device's identity on first contact and
     * warn if the relay later reports a different one.
     */
    'GET /users/:username': async (req, ctx) => {
      const session = app.requireAuth(req);
      app.rateLimit('users:lookup', session.accountId);
      const target = visibleAccount(ctx.params.username, session.accountId);
      if (!target) throw new HttpError(404, 'user_not_found');
      const devices = db.prepare(
        `SELECT device_id, identity_json, registered_at FROM devices
         WHERE account_id = ? AND revoked_at IS NULL ORDER BY registered_at`
      ).all(target.account_id);
      return {
        status: 200,
        body: {
          username: target.username,
          devices: devices.map((d) => ({
            device_id: d.device_id,
            identity: JSON.parse(d.identity_json),
            registered_at: d.registered_at,
          })),
        },
      };
    },

    /**
     * Presence, filtered by the TARGET's settings -- and reciprocally by the
     * viewer's: someone who hides their own last-seen cannot see others'.
     * Hidden fields are null; the response shape never varies.
     *
     * Hiding presence here hides only what this endpoint reports. The relay
     * itself still observes connection timing.
     */
    'GET /presence/:username': async (req, ctx) => {
      const session = app.requireAuth(req);
      app.rateLimit('presence:fetch', session.accountId);
      const target = visibleAccount(ctx.params.username, session.accountId);
      if (!target) throw new HttpError(404, 'user_not_found');
      const theirs = app.settingsOf(target.account_id);
      const mine = app.settingsOf(session.accountId);
      return {
        status: 200,
        body: {
          username: target.username,
          online: theirs.show_online && mine.show_online ? app.isOnline(target.account_id) : null,
          last_seen: theirs.show_last_seen && mine.show_last_seen
            ? app.lastSeen(target.account_id) : null,
        },
      };
    },

    'GET /me/blocks': async (req) => {
      const session = app.requireAuth(req);
      const rows = db.prepare(
        `SELECT a.username FROM blocks b JOIN accounts a ON a.account_id = b.blocked_account
         WHERE b.blocker_account = ? ORDER BY b.created_at`
      ).all(session.accountId);
      return { status: 200, body: { blocked: rows.map((r) => r.username) } };
    },

    /**
     * Block a user. Enforced by the relay: their messages to you are dropped
     * (the sender sees an ordinary acceptance), your devices disappear from
     * their directory and prekey lookups, and your presence is hidden.
     */
    'POST /me/blocks': async (req) => {
      const session = app.requireAuth(req);
      const body = await readJson(req);
      const username = requireString(body, 'username', { max: 64, pattern: ID });
      const target = app.accountByUsername(username);
      if (!target) throw new HttpError(404, 'user_not_found');
      if (target.account_id === session.accountId) {
        throw new ValidationError('cannot block yourself', 'username');
      }
      db.prepare(
        `INSERT INTO blocks (blocker_account, blocked_account, created_at) VALUES (?, ?, ?)
         ON CONFLICT DO NOTHING`
      ).run(session.accountId, target.account_id, app.now());
      return { status: 200, body: { blocked: target.username } };
    },

    'DELETE /me/blocks/:username': async (req, ctx) => {
      const session = app.requireAuth(req);
      const target = app.accountByUsername(ctx.params.username);
      if (target) {
        db.prepare('DELETE FROM blocks WHERE blocker_account = ? AND blocked_account = ?')
          .run(session.accountId, target.account_id);
      }
      return { status: 200, body: { unblocked: true } };
    },

    /**
     * Report a user to the operator. The relay holds no message content, so a
     * report carries only who, why, and an optional note the reporter writes.
     */
    'POST /reports': async (req) => {
      const session = app.requireAuth(req);
      app.rateLimit('reports:create', session.accountId);
      const body = await readJson(req);
      const username = requireString(body, 'username', { max: 64, pattern: ID });
      const reason = requireString(body, 'reason', { max: 32 });
      if (!REPORT_REASONS.has(reason)) throw new ValidationError('unknown reason', 'reason');
      const note = body.note === undefined || body.note === null || body.note === ''
        ? null : requireString(body, 'note', { max: 500 });
      const target = app.accountByUsername(username);
      if (!target) throw new HttpError(404, 'user_not_found');
      const id = randomUUID();
      db.prepare(
        `INSERT INTO reports (report_id, reporter_account, reported_account, reason, note, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`
      ).run(id, session.accountId, target.account_id, reason, note, app.now());
      return { status: 201, body: { report_id: id } };
    },
  };
};
