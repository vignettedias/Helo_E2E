'use strict';
/**
 * HTTP plumbing shared by every route module: the error type, the security
 * headers, and size-bounded body readers.
 */

const MAX_JSON_BYTES = 128 * 1024;

const SECURITY_HEADERS = {
  'Content-Type': 'application/json',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
};

class HttpError extends Error {
  constructor(status, code, message) {
    super(message || code);
    this.status = status;
    this.code = code;
  }
}

/**
 * Read a request body into a Buffer, refusing anything over `limit` bytes.
 *
 * Do NOT destroy the socket on overflow. Destroying it means the client sees a
 * connection reset rather than a 413, which is indistinguishable from the
 * server being down and gives an honest client no way to learn its request
 * was simply too large. Stop buffering, drain the remainder, and let the
 * dispatcher send a proper response.
 */
function readRaw(req, limit) {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers['content-length']);
    if (Number.isFinite(declared) && declared > limit) {
      req.resume();
      reject(new HttpError(413, 'payload_too_large'));
      return;
    }
    let size = 0;
    let overflowed = false;
    const chunks = [];
    req.on('data', (chunk) => {
      if (overflowed) return; // draining; discard
      size += chunk.length;
      if (size > limit) {
        overflowed = true;
        chunks.length = 0;
        reject(new HttpError(413, 'payload_too_large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (!overflowed) resolve(Buffer.concat(chunks));
    });
    req.on('error', reject);
  });
}

async function readJson(req, limit = MAX_JSON_BYTES) {
  const raw = await readRaw(req, limit);
  if (raw.length === 0) return {};
  try {
    return JSON.parse(raw.toString('utf8'));
  } catch {
    throw new HttpError(400, 'invalid_json');
  }
}

module.exports = { HttpError, SECURITY_HEADERS, MAX_JSON_BYTES, readRaw, readJson };
