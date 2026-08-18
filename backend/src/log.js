'use strict';
/**
 * Relay logging with an allowlist, mirroring the client's secure_log.py.
 *
 * The relay handles ciphertext all day. A single `console.log(req.body)` in a
 * debug session would write user ciphertext and auth tokens into log
 * aggregation, where retention and access control are usually far weaker than
 * the database's. So the logger physically cannot emit an undeclared field.
 */

const SAFE_FIELDS = new Set([
  'event', 'method', 'path', 'status', 'duration_ms', 'account_hash',
  'device_hash', 'recipient_hash', 'sender_hash', 'message_count',
  'size_bytes', 'prekey_count', 'outcome', 'error_class', 'rate_limited',
  'queue_depth', 'removed',
]);

const { createHash } = require('node:crypto');

/** Truncated hash: correlate log lines without exposing the identifier. */
function hashId(value) {
  return createHash('sha256')
    .update('Helo_RelayLogId_v1' + String(value))
    .digest('hex')
    .slice(0, 16);
}

function redact(fields) {
  const out = {};
  for (const [k, v] of Object.entries(fields)) {
    out[k] = SAFE_FIELDS.has(k) ? v : '<redacted>';
  }
  return out;
}

function emit(level, event, fields = {}) {
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    level,
    ...redact({ event, ...fields }),
  });
  if (level === 'error' || level === 'warn') process.stderr.write(line + '\n');
  else process.stdout.write(line + '\n');
}

module.exports = {
  hashId,
  redact,
  info: (event, f) => emit('info', event, f),
  warn: (event, f) => emit('warn', event, f),
  error: (event, f) => emit('error', event, f),
  security: (event, f) => emit('warn', event, f),
  SAFE_FIELDS,
};
