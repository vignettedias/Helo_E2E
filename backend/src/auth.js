'use strict';
/**
 * Account and device authentication.
 *
 * CRITICAL SEPARATION OF CONCERNS: this layer authenticates that a request
 * comes from a registered account. It says NOTHING about cryptographic peer
 * identity. A valid access token proves "this connection controls this
 * account", never "this is really Alice". Conflating the two is exactly how
 * systems end up trusting a server-asserted identity, so the two are kept in
 * separate modules and the messaging layer never consults this one.
 */

const { randomBytes, scryptSync, timingSafeEqual, createHash } = require('node:crypto');

const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1, keylen: 64 };
const ACCESS_TOKEN_TTL = 60 * 60;            // 1 hour
const REFRESH_TOKEN_TTL = 30 * 24 * 60 * 60; // 30 days

const now = () => Math.floor(Date.now() / 1000);

function hashPassword(password, salt = randomBytes(16).toString('hex')) {
  const hash = scryptSync(password, salt, SCRYPT_PARAMS.keylen, SCRYPT_PARAMS)
    .toString('hex');
  return { hash, salt };
}

function verifyPassword(password, salt, expectedHash) {
  const { hash } = hashPassword(password, salt);
  const a = Buffer.from(hash, 'hex');
  const b = Buffer.from(expectedHash, 'hex');
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/** Tokens are random; only their hash is persisted. */
function issueToken(db, accountId, deviceId, kind) {
  const token = randomBytes(32).toString('base64url');
  const ttl = kind === 'refresh' ? REFRESH_TOKEN_TTL : ACCESS_TOKEN_TTL;
  db.prepare(
    `INSERT INTO tokens (token_hash, account_id, device_id, kind, issued_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).run(tokenHash(token), accountId, deviceId, kind, now(), now() + ttl);
  return token;
}

function tokenHash(token) {
  return createHash('sha256').update(token).digest('hex');
}

function resolveToken(db, token, kind = 'access') {
  if (typeof token !== 'string' || token.length < 16) return null;
  const row = db.prepare(
    `SELECT account_id, device_id, kind, expires_at, revoked_at
     FROM tokens WHERE token_hash = ?`
  ).get(tokenHash(token));
  if (!row) return null;
  if (row.kind !== kind) return null;
  if (row.revoked_at !== null) return null;
  if (row.expires_at < now()) return null;
  return { accountId: row.account_id, deviceId: row.device_id };
}

function revokeToken(db, token) {
  return db.prepare('UPDATE tokens SET revoked_at = ? WHERE token_hash = ?')
    .run(now(), tokenHash(token)).changes > 0;
}

/** Revoke every token for a device -- used on logout and device revocation. */
function revokeDevice(db, deviceId) {
  db.prepare('UPDATE tokens SET revoked_at = ? WHERE device_id = ? AND revoked_at IS NULL')
    .run(now(), deviceId);
  db.prepare('UPDATE devices SET revoked_at = ? WHERE device_id = ?')
    .run(now(), deviceId);
}

module.exports = {
  hashPassword, verifyPassword, issueToken, resolveToken, revokeToken,
  revokeDevice, tokenHash, ACCESS_TOKEN_TTL, REFRESH_TOKEN_TTL,
};
