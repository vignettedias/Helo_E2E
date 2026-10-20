'use strict';
/** Account authentication routes. Nothing here touches E2EE key material. */

const { randomUUID } = require('node:crypto');
const auth = require('../auth');
const log = require('../log');
const { HttpError, readJson } = require('../http');
const { requireString, ID, USERNAME } = require('../validate');

const MIN_PASSWORD = 12;

module.exports = function authRoutes(app) {
  const { db } = app;

  function checkNewPassword(password) {
    if (password.length < MIN_PASSWORD) {
      throw new HttpError(400, 'weak_password', `password must be at least ${MIN_PASSWORD} characters`);
    }
  }

  return {
    'POST /auth/register': async (req, ctx) => {
      app.rateLimit('auth:register', ctx.ip);
      const body = await readJson(req);
      // Usernames are case-insensitive: "Alice" and "alice" must not be two
      // accounts, or one could impersonate the other in a contact list.
      const username = requireString(body, 'username', { max: 64, pattern: ID }).toLowerCase();
      if (!USERNAME.test(username)) {
        throw new HttpError(400, 'invalid_username',
          'usernames are 3-32 characters: letters, digits, ".", "_" or "-"');
      }
      const password = requireString(body, 'password', { max: 512 });
      checkNewPassword(password);
      if (app.accountByUsername(username)) throw new HttpError(409, 'username_taken');

      const accountId = randomUUID();
      const { hash, salt } = auth.hashPassword(password);
      db.prepare(
        `INSERT INTO accounts (account_id, username, password_hash, password_salt, created_at)
         VALUES (?, ?, ?, ?, ?)`
      ).run(accountId, username, hash, salt, app.now());
      log.info('account_registered', { account_hash: log.hashId(accountId) });
      return { status: 201, body: { account_id: accountId } };
    },

    'POST /auth/login': async (req, ctx) => {
      app.rateLimit('auth:login', ctx.ip);
      const body = await readJson(req);
      const username = requireString(body, 'username', { max: 64, pattern: ID }).toLowerCase();
      const password = requireString(body, 'password', { max: 512 });

      const account = db.prepare(
        'SELECT account_id, password_hash, password_salt FROM accounts WHERE username = ?'
      ).get(username);

      // Uniform failure: same status and message whether the account exists or
      // the password is wrong, so login is not a username oracle. The failure
      // is recorded for the account owner, which changes nothing the caller sees.
      if (!account || !auth.verifyPassword(password, account.password_salt, account.password_hash)) {
        if (account) app.recordEvent(account.account_id, 'login_failed');
        log.security('login_failed', { outcome: 'rejected' });
        throw new HttpError(401, 'invalid_credentials');
      }
      app.recordEvent(account.account_id, 'login');
      return {
        status: 200,
        body: {
          access_token: auth.issueToken(db, account.account_id, null, 'access'),
          refresh_token: auth.issueToken(db, account.account_id, null, 'refresh'),
          expires_in: auth.ACCESS_TOKEN_TTL,
        },
      };
    },

    'POST /auth/refresh': async (req) => {
      const body = await readJson(req);
      const refresh = requireString(body, 'refresh_token', { max: 256 });
      const session = auth.resolveToken(db, refresh, 'refresh');
      if (!session) throw new HttpError(401, 'invalid_token');
      return {
        status: 200,
        body: {
          access_token: auth.issueToken(db, session.accountId, session.deviceId, 'access'),
          expires_in: auth.ACCESS_TOKEN_TTL,
        },
      };
    },

    'POST /auth/logout': async (req) => {
      const session = app.requireAuth(req);
      auth.revokeToken(db, session.token);
      return { status: 200, body: { revoked: true } };
    },

    /** Revoke every token on the account, this one included. */
    'POST /auth/logout-all': async (req) => {
      const session = app.requireAuth(req);
      const n = db.prepare(
        'UPDATE tokens SET revoked_at = ? WHERE account_id = ? AND revoked_at IS NULL'
      ).run(app.now(), session.accountId).changes;
      app.recordEvent(session.accountId, 'sessions_revoked', session.deviceId);
      return { status: 200, body: { revoked: n } };
    },

    /**
     * Change the account password. Every OTHER token is revoked, so a stolen
     * session does not survive the owner changing their password. The account
     * password never encrypts anything: changing it cannot affect E2EE keys.
     */
    'POST /auth/password': async (req) => {
      const session = app.requireAuth(req);
      app.rateLimit('auth:password', session.accountId);
      const body = await readJson(req);
      const current = requireString(body, 'current_password', { max: 512 });
      const next = requireString(body, 'new_password', { max: 512 });
      checkNewPassword(next);

      const account = db.prepare(
        'SELECT password_hash, password_salt FROM accounts WHERE account_id = ?'
      ).get(session.accountId);
      if (!account || !auth.verifyPassword(current, account.password_salt, account.password_hash)) {
        app.recordEvent(session.accountId, 'password_change_failed', session.deviceId);
        throw new HttpError(401, 'invalid_credentials');
      }
      const { hash, salt } = auth.hashPassword(next);
      db.prepare('UPDATE accounts SET password_hash = ?, password_salt = ? WHERE account_id = ?')
        .run(hash, salt, session.accountId);
      db.prepare(
        `UPDATE tokens SET revoked_at = ?
         WHERE account_id = ? AND revoked_at IS NULL AND token_hash != ?`
      ).run(app.now(), session.accountId, auth.tokenHash(session.token));
      app.recordEvent(session.accountId, 'password_changed', session.deviceId);
      return { status: 200, body: { changed: true } };
    },
  };
};
