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

const SCHEMA_V1 = `
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
  account_id     TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,  -- METADATA
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
  account_id     TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,  -- METADATA
  device_id      TEXT REFERENCES devices(device_id) ON DELETE CASCADE,  -- METADATA
  kind           TEXT NOT NULL,              -- METADATA ('access' | 'refresh')
  issued_at      INTEGER NOT NULL,  -- METADATA
  expires_at     INTEGER NOT NULL,  -- METADATA
  revoked_at     INTEGER  -- METADATA
);
CREATE INDEX IF NOT EXISTS idx_tokens_account ON tokens(account_id);

-- ---------------------------------------------------------- signed prekeys
CREATE TABLE IF NOT EXISTS signed_prekeys (
  device_id      TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,  -- METADATA
  key_id         INTEGER NOT NULL,           -- CRYPTO
  public_key     TEXT NOT NULL,              -- CRYPTO (public half only)
  signature      TEXT NOT NULL,              -- CRYPTO
  created_at     INTEGER NOT NULL,  -- METADATA
  PRIMARY KEY (device_id, key_id)
);

-- -------------------------------------------------------- one-time prekeys
-- consumed_at makes consumption observable and single-use at the SQL level.
CREATE TABLE IF NOT EXISTS one_time_prekeys (
  device_id      TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,  -- METADATA
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
  seq             INTEGER PRIMARY KEY AUTOINCREMENT,  -- METADATA
  message_id      TEXT UNIQUE NOT NULL,      -- METADATA
  recipient_device TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,  -- METADATA
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
  device_id      TEXT PRIMARY KEY REFERENCES devices(device_id) ON DELETE CASCADE,  -- METADATA
  token          TEXT NOT NULL,              -- SECRET (platform push token)
  platform       TEXT NOT NULL,  -- METADATA
  updated_at     INTEGER NOT NULL  -- METADATA
);
`;

/**
 * v2 (HELO 2.0). Additive only: nothing in v1 is altered or dropped, so a v1
 * database upgrades in place with every account, device and queued message
 * intact.
 */
const SCHEMA_V2 = `
-- ------------------------------------------------- post-quantum prekeys
-- Signed ML-KEM-768 public prekeys. One-time keys are claimed atomically like
-- the EC one-time prekeys; the last-resort key is reused when none remain.
CREATE TABLE IF NOT EXISTS pq_prekeys (
  device_id      TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,  -- METADATA
  key_id         INTEGER NOT NULL,           -- CRYPTO
  public_key     TEXT NOT NULL,              -- CRYPTO (Encode(PQPK), public only)
  signature      TEXT NOT NULL,              -- CRYPTO
  last_resort    INTEGER NOT NULL DEFAULT 0, -- PUBLIC
  created_at     INTEGER NOT NULL,           -- METADATA
  consumed_at    INTEGER,                    -- METADATA
  PRIMARY KEY (device_id, key_id)
);
CREATE INDEX IF NOT EXISTS idx_pq_available
  ON pq_prekeys(device_id, last_resort, consumed_at);

-- --------------------------------------------------------- attachments
-- Ciphertext only. The content key travels inside an E2EE message and never
-- reaches the relay; without it this blob is indistinguishable from noise.
CREATE TABLE IF NOT EXISTS attachments (
  attachment_id   TEXT PRIMARY KEY,          -- PUBLIC (random 128-bit)
  uploader_device TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,  -- METADATA
  size_bytes      INTEGER NOT NULL,          -- METADATA (ciphertext size)
  data            BLOB NOT NULL,             -- CIPHERTEXT
  created_at      INTEGER NOT NULL           -- METADATA
);
CREATE TABLE IF NOT EXISTS attachment_recipients (
  attachment_id  TEXT NOT NULL REFERENCES attachments(attachment_id) ON DELETE CASCADE,  -- METADATA
  device_id      TEXT NOT NULL,              -- METADATA
  PRIMARY KEY (attachment_id, device_id)
);

-- ------------------------------------------------------------ blocking
CREATE TABLE IF NOT EXISTS blocks (
  blocker_account TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,  -- METADATA
  blocked_account TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,  -- METADATA
  created_at      INTEGER NOT NULL,          -- METADATA
  PRIMARY KEY (blocker_account, blocked_account)
);

-- ------------------------------------------------------------- reports
-- A report names an account and a reason. It never contains message content:
-- the relay has none to attach.
CREATE TABLE IF NOT EXISTS reports (
  report_id        TEXT PRIMARY KEY,  -- METADATA
  reporter_account TEXT REFERENCES accounts(account_id) ON DELETE SET NULL,  -- METADATA
  reported_account TEXT REFERENCES accounts(account_id) ON DELETE SET NULL,  -- METADATA
  reason           TEXT NOT NULL,            -- METADATA (fixed vocabulary)
  note             TEXT,                     -- METADATA (user-written, <= 500 chars)
  created_at       INTEGER NOT NULL  -- METADATA
);

-- ---------------------------------------------------- privacy settings
-- Only the settings the RELAY must enforce live here. Read receipts and typing
-- indicators are end-to-end encrypted messages; the client enforces those.
CREATE TABLE IF NOT EXISTS account_settings (
  account_id      TEXT PRIMARY KEY REFERENCES accounts(account_id) ON DELETE CASCADE,  -- METADATA
  show_online     INTEGER NOT NULL DEFAULT 1,  -- METADATA
  show_last_seen  INTEGER NOT NULL DEFAULT 1  -- METADATA
);

-- ------------------------------------------------------ security events
-- What a user needs to notice an attack on their account. No secrets, no IPs.
CREATE TABLE IF NOT EXISTS security_events (
  event_id    INTEGER PRIMARY KEY AUTOINCREMENT,  -- METADATA
  account_id  TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,  -- METADATA
  kind        TEXT NOT NULL,                 -- METADATA
  device_id   TEXT,                          -- METADATA
  created_at  INTEGER NOT NULL  -- METADATA
);
CREATE INDEX IF NOT EXISTS idx_events_account ON security_events(account_id, event_id);
`;

/** Ordered, additive migrations. `user_version` records the last applied. */
const MIGRATIONS = [
  { version: 1, sql: SCHEMA_V1 },
  { version: 2, sql: SCHEMA_V2 },
];
const SCHEMA_VERSION = MIGRATIONS[MIGRATIONS.length - 1].version;

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
  ATTACHMENT_SECONDS: 30 * 24 * 60 * 60,
  REPORT_SECONDS: 90 * 24 * 60 * 60,
  SECURITY_EVENT_SECONDS: 90 * 24 * 60 * 60,
};

/** Apply every migration newer than the database, each in its own transaction. */
function migrate(db) {
  const current = db.prepare('PRAGMA user_version').get().user_version;
  for (const m of MIGRATIONS) {
    if (m.version <= current) continue;
    db.exec('BEGIN');
    try {
      db.exec(m.sql);
      db.exec(`PRAGMA user_version = ${m.version}`);
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
      throw err;
    }
  }
  return db.prepare('PRAGMA user_version').get().user_version;
}

function openDatabase(path = ':memory:') {
  const db = new DatabaseSync(path);
  db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
  migrate(db);
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
  removed.consumedPqPrekeys = db
    .prepare('DELETE FROM pq_prekeys WHERE consumed_at IS NOT NULL AND consumed_at < ?')
    .run(now - RETENTION.CONSUMED_PREKEY_SECONDS).changes;
  removed.attachments = db
    .prepare('DELETE FROM attachments WHERE created_at < ?')
    .run(now - RETENTION.ATTACHMENT_SECONDS).changes;
  removed.reports = db
    .prepare('DELETE FROM reports WHERE created_at < ?')
    .run(now - RETENTION.REPORT_SECONDS).changes;
  removed.securityEvents = db
    .prepare('DELETE FROM security_events WHERE created_at < ?')
    .run(now - RETENTION.SECURITY_EVENT_SECONDS).changes;
  return removed;
}

module.exports = {
  openDatabase, migrate, sweep, SCHEMA_V1, SCHEMA_V2, SCHEMA_VERSION, RETENTION,
};
