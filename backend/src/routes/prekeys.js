'use strict';
/**
 * Prekey publication and bundle retrieval: X25519 signed and one-time
 * prekeys, plus signed ML-KEM-768 prekeys for the hybrid handshake.
 *
 * The relay stores and serves PUBLIC material only. Every key it serves is
 * either signed by the device's identity key or bound into the session
 * transcript, so substituting one is detected by the client -- the relay's
 * only power is to withhold, which the client's downgrade policy refuses.
 */

const log = require('../log');
const { HttpError, readJson } = require('../http');
const {
  requireString, validateSignedPreKey, validateOneTimePreKeys, validatePqPreKey,
  validatePqPreKeys, ID,
} = require('../validate');

const MAX_PREKEY_BODY = 512 * 1024;

module.exports = function prekeyRoutes(app) {
  const { db } = app;

  function countAvailable(deviceId) {
    const ec = db.prepare(
      'SELECT COUNT(*) AS n FROM one_time_prekeys WHERE device_id = ? AND consumed_at IS NULL'
    ).get(deviceId).n;
    const pq = db.prepare(
      `SELECT COUNT(*) AS n FROM pq_prekeys
       WHERE device_id = ? AND last_resort = 0 AND consumed_at IS NULL`
    ).get(deviceId).n;
    return { ec, pq };
  }

  return {
    'POST /prekeys': async (req) => {
      const session = app.requireAuth(req);
      app.rateLimit('prekeys:publish', session.accountId);
      const body = await readJson(req, MAX_PREKEY_BODY);
      const deviceId = requireString(body, 'device_id', { max: 64, pattern: ID });

      const device = db.prepare('SELECT account_id, revoked_at FROM devices WHERE device_id = ?')
        .get(deviceId);
      if (!device || device.account_id !== session.accountId) {
        throw new HttpError(403, 'not_your_device');
      }
      if (device.revoked_at !== null) throw new HttpError(410, 'device_revoked');

      const signed = validateSignedPreKey(body.signed_prekey);
      const oneTime = validateOneTimePreKeys(body.one_time_prekeys || []);
      const pqLastResort = body.pq_last_resort === undefined
        ? null : validatePqPreKey(body.pq_last_resort, 'pq_last_resort');
      const pqOneTime = validatePqPreKeys(body.pq_one_time_prekeys || []);

      db.exec('BEGIN');
      try {
        db.prepare(
          `INSERT INTO signed_prekeys (device_id, key_id, public_key, signature, created_at)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(device_id, key_id) DO UPDATE SET
             public_key = excluded.public_key, signature = excluded.signature`
        ).run(deviceId, signed.key_id, signed.public, signed.signature, signed.created_at);

        // DO NOTHING on conflict: a key id the relay has seen keeps its FIRST
        // public key. Overwriting could leave a peer holding a public key whose
        // private half the device no longer has.
        const insertOtp = db.prepare(
          `INSERT INTO one_time_prekeys (device_id, key_id, public_key)
           VALUES (?, ?, ?) ON CONFLICT(device_id, key_id) DO NOTHING`
        );
        for (const otp of oneTime) insertOtp.run(deviceId, otp.key_id, otp.public);

        const insertPq = db.prepare(
          `INSERT INTO pq_prekeys (device_id, key_id, public_key, signature, last_resort, created_at)
           VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(device_id, key_id) DO NOTHING`
        );
        if (pqLastResort) {
          // A device has exactly one current last-resort key; older ones retire.
          db.prepare('DELETE FROM pq_prekeys WHERE device_id = ? AND last_resort = 1 AND key_id != ?')
            .run(deviceId, pqLastResort.key_id);
          insertPq.run(deviceId, pqLastResort.key_id, pqLastResort.public,
            pqLastResort.signature, 1, app.now());
        }
        for (const k of pqOneTime) {
          insertPq.run(deviceId, k.key_id, k.public, k.signature, 0, app.now());
        }
        db.exec('COMMIT');
      } catch (err) {
        db.exec('ROLLBACK');
        throw err;
      }

      const available = countAvailable(deviceId);
      log.info('prekeys_published', {
        device_hash: log.hashId(deviceId), prekey_count: available.ec,
      });
      return {
        status: 200,
        body: {
          available_one_time_prekeys: available.ec,
          available_pq_one_time_prekeys: available.pq,
        },
      };
    },

    'GET /prekeys/:deviceId': async (req, ctx) => {
      const session = app.requireAuth(req);
      app.rateLimit('prekeys:fetch', session.accountId);
      const deviceId = ctx.params.deviceId;

      const device = db.prepare(
        'SELECT account_id, identity_json, revoked_at FROM devices WHERE device_id = ?'
      ).get(deviceId);
      // A device whose owner blocked the requester is reported exactly like a
      // nonexistent one, so the response does not reveal the block.
      if (!device || app.isBlocked(device.account_id, session.accountId)) {
        throw new HttpError(404, 'device_not_found');
      }
      if (device.revoked_at !== null) throw new HttpError(410, 'device_revoked');

      const signed = db.prepare(
        `SELECT key_id, public_key, signature, created_at FROM signed_prekeys
         WHERE device_id = ? ORDER BY key_id DESC LIMIT 1`
      ).get(deviceId);
      if (!signed) throw new HttpError(404, 'no_signed_prekey');

      // Atomic single-consumption: UPDATE ... RETURNING claims exactly one
      // prekey. Two concurrent fetchers cannot receive the same one.
      const claimed = db.prepare(
        `UPDATE one_time_prekeys SET consumed_at = ?
         WHERE rowid = (
           SELECT rowid FROM one_time_prekeys
           WHERE device_id = ? AND consumed_at IS NULL
           ORDER BY key_id LIMIT 1)
         RETURNING key_id, public_key`
      ).get(app.now(), deviceId);

      // ML-KEM: a one-time key if any remain, otherwise the last-resort key.
      let pq = db.prepare(
        `UPDATE pq_prekeys SET consumed_at = ?
         WHERE rowid = (
           SELECT rowid FROM pq_prekeys
           WHERE device_id = ? AND last_resort = 0 AND consumed_at IS NULL
           ORDER BY key_id LIMIT 1)
         RETURNING key_id, public_key, signature, last_resort`
      ).get(app.now(), deviceId);
      if (!pq) {
        pq = db.prepare(
          `SELECT key_id, public_key, signature, last_resort FROM pq_prekeys
           WHERE device_id = ? AND last_resort = 1 ORDER BY key_id DESC LIMIT 1`
        ).get(deviceId);
      }

      // DEMO ONLY (routes/demo.js): pretend this device published no ML-KEM
      // key, to show that the sender refuses rather than downgrades.
      if (app.demo.enabled && app.demo.mode === 'strip_pq') pq = null;

      const remaining = countAvailable(deviceId);
      const owner = db.prepare('SELECT username FROM accounts WHERE account_id = ?')
        .get(device.account_id);

      return {
        status: 200,
        body: {
          device_id: deviceId,
          username: owner ? owner.username : null,
          identity: JSON.parse(device.identity_json),
          signed_prekey: {
            key_id: signed.key_id,
            public: signed.public_key,
            signature: signed.signature,
            created_at: signed.created_at,
          },
          one_time_prekey: claimed
            ? { key_id: claimed.key_id, public: claimed.public_key }
            : null,
          // Surfaced so the client can WARN the user that this session falls
          // back to three-DH, rather than silently accepting the downgrade.
          one_time_prekey_available: claimed !== undefined && claimed !== null,
          remaining_one_time_prekeys: remaining.ec,
          pq_prekey: pq
            ? {
              key_id: pq.key_id,
              public: pq.public_key,
              signature: pq.signature,
              one_time: pq.last_resort === 0,
            }
            : null,
          remaining_pq_one_time_prekeys: remaining.pq,
        },
      };
    },
  };
};
