'use strict';
/** The authenticated user's own account: summary, settings, events, deletion. */

const auth = require('../auth');
const log = require('../log');
const { HttpError, readJson } = require('../http');
const { ValidationError, requireString } = require('../validate');

const SETTINGS = ['show_online', 'show_last_seen'];
const EVENT_LIMIT = 50;

module.exports = function accountRoutes(app) {
  const { db } = app;

  return {
    'GET /me': async (req) => {
      const session = app.requireAuth(req);
      const account = db.prepare('SELECT username, created_at FROM accounts WHERE account_id = ?')
        .get(session.accountId);
      if (!account) throw new HttpError(401, 'invalid_token');
      return {
        status: 200,
        body: {
          username: account.username,
          created_at: account.created_at,
          device_id: session.deviceId,
          settings: app.settingsOf(session.accountId),
        },
      };
    },

    'GET /me/settings': async (req) => {
      const session = app.requireAuth(req);
      return { status: 200, body: app.settingsOf(session.accountId) };
    },

    /** Partial update of the settings the relay enforces (presence only). */
    'PUT /me/settings': async (req) => {
      const session = app.requireAuth(req);
      const body = await readJson(req);
      const next = app.settingsOf(session.accountId);
      for (const key of Object.keys(body)) {
        if (!SETTINGS.includes(key)) throw new ValidationError(`unknown setting '${key}'`, key);
        if (typeof body[key] !== 'boolean') throw new ValidationError(`'${key}' must be boolean`, key);
        next[key] = body[key];
      }
      db.prepare(
        `INSERT INTO account_settings (account_id, show_online, show_last_seen) VALUES (?, ?, ?)
         ON CONFLICT(account_id) DO UPDATE SET
           show_online = excluded.show_online, show_last_seen = excluded.show_last_seen`
      ).run(session.accountId, next.show_online ? 1 : 0, next.show_last_seen ? 1 : 0);
      return { status: 200, body: next };
    },

    'GET /me/security-events': async (req) => {
      const session = app.requireAuth(req);
      const rows = db.prepare(
        `SELECT kind, device_id, created_at FROM security_events
         WHERE account_id = ? ORDER BY event_id DESC LIMIT ?`
      ).all(session.accountId, EVENT_LIMIT);
      return { status: 200, body: { events: rows } };
    },

    /**
     * Delete the account and everything the relay holds for it: devices,
     * tokens, prekeys, queued ciphertext, attachments, blocks, settings and
     * events (by cascade). Requires the password, not just a session token.
     */
    'DELETE /me': async (req) => {
      const session = app.requireAuth(req);
      app.rateLimit('auth:password', session.accountId);
      const body = await readJson(req);
      const password = requireString(body, 'password', { max: 512 });
      const account = db.prepare(
        'SELECT password_hash, password_salt FROM accounts WHERE account_id = ?'
      ).get(session.accountId);
      if (!account || !auth.verifyPassword(password, account.password_salt, account.password_hash)) {
        throw new HttpError(401, 'invalid_credentials');
      }
      db.exec('BEGIN');
      try {
        // Messages queued for this account's devices cascade via devices; the
        // ones this account SENT to others carry only a device id with no
        // foreign key, and stay deliverable to their recipients.
        db.prepare('DELETE FROM accounts WHERE account_id = ?').run(session.accountId);
        db.exec('COMMIT');
      } catch (err) {
        db.exec('ROLLBACK');
        throw err;
      }
      log.security('account_deleted', { account_hash: log.hashId(session.accountId) });
      return { status: 200, body: { deleted: true } };
    },
  };
};
