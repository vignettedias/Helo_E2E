'use strict';
/**
 * Relay storage schema.
 *
 * TRUST POSTURE: this database is assumed COMPROMISED. Every design decision
 * below assumes an attacker has a full dump. That is why there is no column
 * anywhere in this file capable of holding plaintext or a session key -- not
 * "we promise not to write one", but no column that could receive one.
 *
 * DATA CLASSIFICATION (per THREAT_MODEL.md):
 *   PUBLIC       safe to disclose
 *   METADATA     sensitive; discloses social graph / timing
 *   CRYPTO       public cryptographic material (never a private half)
 *   CIPHERTEXT   opaque to the relay
 *   SECRET       server-side credential material (hashed, never recoverable)
 */

const { DatabaseSync } = require('node:sqlite');

const SCHEMA = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------- accounts
CREATE TABLE IF NOT EXISTS accounts (
  account_id     TEXT PRIMARY KEY,           -- METADATA
  username       TEXT UNIQUE NOT NULL,       -- METADATA
  password_hash  TEXT NOT NULL,              -- SECRET (scrypt, salted)
  password_salt  TEXT NOT NULL,              -- SECRET
  created_at     INTEGER NOT NULL            -- METADATA
);

-- ----------------------------------------------------------------- devices
CREATE TABLE IF NOT EXISTS devices (
  device_id      TEXT PRIMARY KEY,           -- METADATA
  account_id     TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
  identity_json  TEXT NOT NULL,              -- CRYPTO (public identity only)
  registered_at  INTEGER NOT NULL,           -- METADATA
  last_seen_at   INTEGER,                    -- METADATA
  revoked_at     INTEGER                     -- METADATA
);
CREATE INDEX IF NOT EXISTS idx_devices_account ON devices(account_id);

-- ------------------------------------------------------------- auth tokens
-- Tokens are stored HASHED. A database dump does not yield usable tokens.
CREATE TABLE IF NOT EXISTS tokens (
  token_hash     TEXT PRIMARY KEY,           -- SECRET (SHA-256 of the token)
  account_id     TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
  device_id      TEXT REFERENCES devices(device_id) ON DELETE CASCADE,
  kind           TEXT NOT NULL,              -- 'access' | 'refresh'
  issued_at      INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL,
  revoked_at     INTEGER
);
CREATE INDEX IF NOT EXISTS idx_tokens_account ON tokens(account_id);

-- ---------------------------------------------------------- signed prekeys
CREATE TABLE IF NOT EXISTS signed_prekeys (
  device_id      TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
  key_id         INTEGER NOT NULL,           -- CRYPTO
  public_key     TEXT NOT NULL,              -- CRYPTO (public half only)
  signature      TEXT NOT NULL,              -- CRYPTO
  created_at     INTEGER NOT NULL,
  PRIMARY KEY (device_id, key_id)
);

-- -------------------------------------------------------- one-time prekeys
-- consumed_at makes consumption observable and single-use at the SQL level.
CREATE TABLE IF NOT EXISTS one_time_prekeys (
  device_id      TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
  key_id         INTEGER NOT NULL,           -- CRYPTO
  public_key     TEXT NOT NULL,              -- CRYPTO (public half only)
  consumed_at    INTEGER,                    -- METADATA
  PRIMARY KEY (device_id, key_id)
);
CREATE INDEX IF NOT EXISTS idx_otp_available
  ON one_time_prekeys(device_id, consumed_at);

-- -------------------------------------------------------------- messages
-- envelope_json is CIPHERTEXT plus an authenticated header. The relay parses
-- it ONLY to validate structure and size; it never interprets the payload.
CREATE TABLE IF NOT EXISTS messages (
  -- seq is a monotonic queue position. queued_at has one-second granularity
  -- and is NOT a sufficient sort key on its own: messages queued within the
  -- same second would otherwise fall back to ordering by random UUID, which
  -- scrambles FIFO delivery. The protocol tolerates out-of-order delivery, so
  -- this defect is invisible in testing unless explicitly checked -- which is
  -- precisely why the ordering key is explicit here.
  seq             INTEGER PRIMARY KEY AUTOINCREMENT,
  message_id      TEXT UNIQUE NOT NULL,      -- METADATA
  recipient_device TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
  sender_device   TEXT NOT NULL,             -- METADATA
  envelope_json   TEXT NOT NULL,             -- CIPHERTEXT
  size_bytes      INTEGER NOT NULL,          -- METADATA
  queued_at       INTEGER NOT NULL,          -- METADATA
  delivered_at    INTEGER,                   -- METADATA
  acked_at        INTEGER                    -- METADATA
);
CREATE INDEX IF NOT EXISTS idx_messages_queue
  ON messages(recipient_device, acked_at, seq);

-- ------------------------------------------------------------- push tokens
CREATE TABLE IF NOT EXISTS push_tokens (
  device_id      TEXT PRIMARY KEY REFERENCES devices(device_id) ON DELETE CASCADE,
  token          TEXT NOT NULL,              -- SECRET (platform push token)
  platform       TEXT NOT NULL,
  updated_at     INTEGER NOT NULL
);
`;

/**
 * Retention policy. Enforced by sweep(), not merely documented.
 *
 * Undelivered messages expire after 30 days -- an unbounded queue is both a
 * storage liability and a metadata liability. Acked messages are deleted
 * immediately: the relay has no reason to retain a delivered ciphertext, and
 * retaining it only increases what a future compromise yields.
 */
const RETENTION = {
  UNDELIVERED_MESSAGE_SECONDS: 30 * 24 * 60 * 60,
  CONSUMED_PREKEY_SECONDS: 7 * 24 * 60 * 60,
  EXPIRED_TOKEN_SECONDS: 24 * 60 * 60,
};

function openDatabase(path = ':memory:') {
  const db = new DatabaseSync(path);
  db.exec(SCHEMA);
  return db;
}

/** Delete data past its retention window. Called periodically by the server. */
function sweep(db, now = Math.floor(Date.now() / 1000)) {
  const removed = {};
  removed.ackedMessages = db
    .prepare('DELETE FROM messages WHERE acked_at IS NOT NULL')
    .run().changes;
  removed.expiredMessages = db
    .prepare('DELETE FROM messages WHERE queued_at < ?')
    .run(now - RETENTION.UNDELIVERED_MESSAGE_SECONDS).changes;
  removed.consumedPrekeys = db
    .prepare('DELETE FROM one_time_prekeys WHERE consumed_at IS NOT NULL AND consumed_at < ?')
    .run(now - RETENTION.CONSUMED_PREKEY_SECONDS).changes;
  removed.expiredTokens = db
    .prepare('DELETE FROM tokens WHERE expires_at < ?')
    .run(now - RETENTION.EXPIRED_TOKEN_SECONDS).changes;
  return removed;
}

module.exports = { openDatabase, sweep, SCHEMA, RETENTION };
