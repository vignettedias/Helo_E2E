'use strict';
/**
 * Request validation.
 *
 * The relay's job is to move opaque blobs. Its validation therefore checks
 * STRUCTURE and SIZE and nothing else -- it must not develop opinions about
 * message content, because any such opinion would require understanding the
 * content, which is precisely what it must not be able to do.
 *
 * Note the envelope validator REJECTS unknown fields. If a future client bug
 * started attaching a plaintext preview or a debug field, the relay refuses it
 * rather than silently storing it. Fail closed, at the boundary.
 */

const MAX_ENVELOPE_BYTES = 96 * 1024;
const MAX_CIPHERTEXT_B64 = 90 * 1024;
const MAX_PREKEY_BATCH = 200;
const ALLOWED_ENVELOPE_FIELDS = new Set([
  'v', 'type', 'session_id', 'sender_device_id', 'header', 'ciphertext', 'x3dh',
]);

class ValidationError extends Error {
  constructor(message, field) {
    super(message);
    this.name = 'ValidationError';
    this.field = field;
    this.status = 400;
  }
}

const B64 = /^[A-Za-z0-9+/]*={0,2}$/;
const ID = /^[A-Za-z0-9._-]{1,64}$/;

function requireString(obj, field, { max = 256, pattern = null } = {}) {
  const value = obj?.[field];
  if (typeof value !== 'string' || value.length === 0 || value.length > max) {
    throw new ValidationError(`field '${field}' must be a non-empty string`, field);
  }
  if (pattern && !pattern.test(value)) {
    throw new ValidationError(`field '${field}' has an invalid format`, field);
  }
  return value;
}

function requireBase64(obj, field, maxLen) {
  const value = requireString(obj, field, { max: maxLen });
  if (!B64.test(value)) {
    throw new ValidationError(`field '${field}' must be base64`, field);
  }
  return value;
}

function requireInt(obj, field, { min = 0, max = 2 ** 31 } = {}) {
  const value = obj?.[field];
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new ValidationError(`field '${field}' must be an integer in range`, field);
  }
  return value;
}

/**
 * Validate a message envelope WITHOUT interpreting it.
 *
 * The relay checks that `ciphertext` is well-formed base64 of a bounded size.
 * It cannot and does not check that it decrypts -- it has no key.
 */
function validateEnvelope(raw) {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new ValidationError('envelope must be an object');
  }
  for (const key of Object.keys(raw)) {
    if (!ALLOWED_ENVELOPE_FIELDS.has(key)) {
      throw new ValidationError(`unexpected envelope field '${key}'`, key);
    }
  }
  if (raw.v !== 1) throw new ValidationError('unsupported envelope version', 'v');
  if (raw.type !== 'prekey' && raw.type !== 'normal') {
    throw new ValidationError('invalid envelope type', 'type');
  }
  requireString(raw, 'session_id', { max: 64, pattern: /^[a-f0-9]{1,64}$/ });
  requireString(raw, 'sender_device_id', { max: 64, pattern: ID });
  requireBase64(raw, 'header', 128);
  requireBase64(raw, 'ciphertext', MAX_CIPHERTEXT_B64);

  if (raw.type === 'prekey') {
    if (typeof raw.x3dh !== 'object' || raw.x3dh === null) {
      throw new ValidationError('prekey envelope requires x3dh header', 'x3dh');
    }
  } else if (raw.x3dh !== undefined) {
    throw new ValidationError('normal envelope must not carry x3dh', 'x3dh');
  }

  const serialized = JSON.stringify(raw);
  if (Buffer.byteLength(serialized) > MAX_ENVELOPE_BYTES) {
    throw new ValidationError('envelope exceeds maximum size');
  }
  return { envelope: raw, serialized, sizeBytes: Buffer.byteLength(serialized) };
}

function validateIdentity(raw) {
  if (typeof raw !== 'object' || raw === null) {
    throw new ValidationError('identity must be an object', 'identity');
  }
  requireBase64(raw, 'sig_pub', 64);
  requireBase64(raw, 'dh_pub', 64);
  requireBase64(raw, 'binding_sig', 128);
  return raw;
}

function validateSignedPreKey(raw) {
  if (typeof raw !== 'object' || raw === null) {
    throw new ValidationError('signed_prekey must be an object', 'signed_prekey');
  }
  requireInt(raw, 'key_id');
  requireBase64(raw, 'public', 64);
  requireBase64(raw, 'signature', 128);
  requireInt(raw, 'created_at');
  return raw;
}

function validateOneTimePreKeys(raw) {
  if (!Array.isArray(raw)) {
    throw new ValidationError('one_time_prekeys must be an array', 'one_time_prekeys');
  }
  if (raw.length > MAX_PREKEY_BATCH) {
    throw new ValidationError(`at most ${MAX_PREKEY_BATCH} prekeys per request`);
  }
  for (const item of raw) {
    requireInt(item, 'key_id');
    requireBase64(item, 'public', 64);
  }
  return raw;
}

module.exports = {
  ValidationError, validateEnvelope, validateIdentity, validateSignedPreKey,
  validateOneTimePreKeys, requireString, requireInt, requireBase64,
  MAX_ENVELOPE_BYTES, MAX_PREKEY_BATCH, ID,
};
