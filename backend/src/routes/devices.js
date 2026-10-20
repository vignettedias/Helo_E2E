'use strict';
/** Device registration, listing and revocation. */

const auth = require('../auth');
const log = require('../log');
const { HttpError, readJson } = require('../http');
const { requireString, validateIdentity, ID } = require('../validate');

function sameIdentity(a, b) {
  return a.sig_pub === b.sig_pub && a.dh_pub === b.dh_pub && a.binding_sig === b.binding_sig;
}

module.exports = function deviceRoutes(app) {
  const { db } = app;

  function revoke(deviceId) {
    auth.revokeDevice(db, deviceId);
    // Nothing queued for, or published by, a revoked device has any use left;
    // keeping it would only enlarge what a database compromise yields.
    db.prepare('DELETE FROM one_time_prekeys WHERE device_id = ?').run(deviceId);
    db.prepare('DELETE FROM pq_prekeys WHERE device_id = ?').run(deviceId);
    db.prepare('DELETE FROM messages WHERE recipient_device = ?').run(deviceId);
  }

  return {
    /**
     * Register a device, or obtain a fresh device token for an existing one.
     *
     * An existing device's identity can NOT be replaced here. Accepting a new
     * identity under an old device id would let anyone holding the account
     * token swap the keys peers have pinned for that device; peers would see
     * an identity-change warning, but refusing is better than warning.
     */
    'POST /devices': async (req) => {
      const session = app.requireAuth(req);
      const body = await readJson(req);
      const deviceId = requireString(body, 'device_id', { max: 64, pattern: ID });
      const identity = validateIdentity(body.identity);

      const existing = db.prepare(
        'SELECT account_id, identity_json, revoked_at FROM devices WHERE device_id = ?'
      ).get(deviceId);
      if (existing) {
        if (existing.account_id !== session.accountId) throw new HttpError(409, 'device_id_taken');
        if (existing.revoked_at !== null) throw new HttpError(410, 'device_revoked');
        if (!sameIdentity(JSON.parse(existing.identity_json), identity)) {
          throw new HttpError(409, 'identity_mismatch');
        }
      } else {
        const stored = {
          sig_pub: identity.sig_pub, dh_pub: identity.dh_pub, binding_sig: identity.binding_sig,
        };
        db.prepare(
          `INSERT INTO devices (device_id, account_id, identity_json, registered_at)
           VALUES (?, ?, ?, ?)`
        ).run(deviceId, session.accountId, JSON.stringify(stored), app.now());
        app.recordEvent(session.accountId, 'device_registered', deviceId);
        log.info('device_registered', { device_hash: log.hashId(deviceId) });
      }
      return {
        status: 201,
        body: {
          device_id: deviceId,
          device_token: auth.issueToken(db, session.accountId, deviceId, 'access'),
        },
      };
    },

    'GET /devices': async (req) => {
      const session = app.requireAuth(req);
      const rows = db.prepare(
        `SELECT device_id, registered_at, last_seen_at, revoked_at, identity_json
         FROM devices WHERE account_id = ? ORDER BY registered_at`
      ).all(session.accountId);
      return {
        status: 200,
        body: {
          devices: rows.map((r) => ({
            device_id: r.device_id,
            registered_at: r.registered_at,
            last_seen_at: r.last_seen_at,
            revoked: r.revoked_at !== null,
            current: r.device_id === session.deviceId,
            identity: JSON.parse(r.identity_json),
          })),
        },
      };
    },

    'POST /devices/revoke': async (req) => {
      const session = app.requireAuth(req);
      const body = await readJson(req);
      const deviceId = requireString(body, 'device_id', { max: 64, pattern: ID });
      const device = db.prepare('SELECT account_id FROM devices WHERE device_id = ?')
        .get(deviceId);
      if (!device || device.account_id !== session.accountId) {
        throw new HttpError(403, 'not_your_device');
      }
      revoke(deviceId);
      app.recordEvent(session.accountId, 'device_revoked', deviceId);
      log.security('device_revoked', { device_hash: log.hashId(deviceId) });
      return { status: 200, body: { revoked: true } };
    },
  };
};
