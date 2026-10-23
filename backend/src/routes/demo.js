'use strict';
/**
 * DEMO ONLY: let the relay misbehave on purpose, so a live audience can watch
 * the clients refuse it.
 *
 * This is the one place in the relay that deliberately breaks the contract, so
 * it is fenced off:
 *   - every route here exists ONLY when the process was started with
 *     DEMO_ATTACKS=1 (createServer({demoAttacks: true})). Otherwise this module
 *     registers nothing and `app.demo.enabled` stays false, so the attack hooks
 *     in the other routes can never fire;
 *   - arming an attack requires an authenticated account, so it is not an open
 *     endpoint even in demo mode;
 *   - the active mode is in-memory only: a restart disarms it;
 *   - it NEVER weakens a check. It corrupts, duplicates, strips or swaps what
 *     the relay hands out. Every one of those is something a hostile relay can
 *     really do, and every one must be refused by the client.
 *
 * The attacks mirror the adversarial test suite, which asserts the same
 * rejections automatically (tests/adversarial, mobile/test/crypto_lab_test.dart).
 */

const log = require('../log');
const { readJson } = require('../http');
const { ValidationError } = require('../validate');

/** mode -> what the relay does, and which client defence must catch it. */
const ATTACKS = {
  none: {
    does: 'relay behaves honestly',
    caught_by: '—',
  },
  tamper: {
    does: 'flips one bit of every delivered ciphertext',
    caught_by: 'AES-256-GCM authentication (AuthenticationError)',
  },
  replay: {
    does: 'delivers every queued message twice',
    caught_by: 'consumed message keys (ReplayError)',
  },
  strip_pq: {
    does: 'serves prekey bundles with the ML-KEM key removed',
    caught_by: 'no-downgrade policy (PostQuantumUnavailableError)',
  },
  substitute_identity: {
    does: "serves another account's identity key for a looked-up device",
    caught_by: 'identity pinning: the device is marked conflicted and nothing is sent to it',
  },
};

module.exports = function demoRoutes(app, options = {}) {
  if (options.demoAttacks !== true) return {};

  return {
    'GET /demo/attack': async (req) => {
      app.requireAuth(req);
      return { status: 200, body: { enabled: true, mode: app.demo.mode, attacks: ATTACKS } };
    },

    'POST /demo/attack': async (req) => {
      app.requireAuth(req);
      const body = await readJson(req);
      const mode = String(body.mode || '');
      if (!Object.prototype.hasOwnProperty.call(ATTACKS, mode)) {
        throw new ValidationError(`mode must be one of: ${Object.keys(ATTACKS).join(', ')}`, 'mode');
      }
      app.demo.mode = mode;
      log.info('demo_attack_armed', { kind: mode });
      return { status: 200, body: { mode, attack: ATTACKS[mode] } };
    },
  };
};

module.exports.ATTACKS = ATTACKS;

/**
 * Flip one bit of an envelope's ciphertext (demo `tamper`).
 * Returns a NEW object; the stored row is never modified.
 */
function tamperEnvelope(envelope) {
  const copy = JSON.parse(JSON.stringify(envelope));
  const raw = Buffer.from(String(copy.ciphertext || ''), 'base64');
  if (raw.length === 0) return copy;
  const at = Math.floor(raw.length / 2);
  raw[at] ^= 0x01;
  copy.ciphertext = raw.toString('base64');
  return copy;
}

/**
 * An identity belonging to some OTHER account (demo `substitute_identity`):
 * what a relay that wanted to read a conversation would serve instead of the
 * real one. Returns null when the database has no other account yet.
 */
function otherAccountIdentity(db, accountId) {
  const row = db.prepare(
    `SELECT identity_json FROM devices
     WHERE account_id != ? AND revoked_at IS NULL ORDER BY registered_at LIMIT 1`
  ).get(accountId);
  return row ? JSON.parse(row.identity_json) : null;
}

module.exports.tamperEnvelope = tamperEnvelope;
module.exports.otherAccountIdentity = otherAccountIdentity;
