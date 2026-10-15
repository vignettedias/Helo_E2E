'use strict';
/**
 * Helo relay server.
 *
 * ARCHITECTURAL INVARIANT: there is no cryptographic key anywhere in this
 * process capable of decrypting a message. The relay imports no protocol code
 * -- it cannot perform X3DH, it has no ratchet, it holds no session state. Its
 * entire relationship with a message is: validate shape, store bytes, hand
 * bytes to the recipient, delete bytes.
 *
 * This is enforced structurally rather than by policy: grep this directory for
 * an AES call and you will not find one.
 *
 * Zero npm dependencies (node:http, node:crypto, node:sqlite only). Every
 * dependency is a supply-chain path into a service that handles ciphertext for
 * every user, so the dependency count is deliberately zero.
 */

const http = require('node:http');
const { randomUUID, randomBytes } = require('node:crypto');

const { openDatabase, sweep } = require('./db');
const auth = require('./auth');
const log = require('./log');
const {
  ValidationError, validateEnvelope, validateIdentity, validateSignedPreKey,
  validateOneTimePreKeys, requireString, ID, MAX_ENVELOPE_BYTES,
} = require('./validate');
const { RateLimiter } = require('./ratelimit');

const now = () => Math.floor(Date.now() / 1000);
const MAX_BODY_BYTES = 128 * 1024;
const MESSAGE_FETCH_LIMIT = 100;

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

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    let overflowed = false;
    const chunks = [];
    req.on('data', (chunk) => {
      if (overflowed) return; // draining; discard
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        // Do NOT destroy the socket here. Destroying it means the client sees
        // a connection reset rather than a 413, which is indistinguishable
        // from the server being down and gives an honest client no way to
        // learn its request was simply too large. Stop buffering, drain the
        // remainder, and let the dispatcher send a proper response.
        overflowed = true;
        chunks.length = 0;
        reject(new HttpError(413, 'payload_too_large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (overflowed) return; // already rejected
      if (chunks.length === 0) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new HttpError(400, 'invalid_json'));
      }
    });
    req.on('error', reject);
  });
}

/**
 * Parse a CORS allowlist. Exact origins only -- there is deliberately no
 * wildcard. A literal '*' is dropped rather than honoured, so a careless
 * CORS_ORIGINS=* disables CORS instead of opening it to every site.
 */
function parseCorsOrigins(value) {
  const list = Array.isArray(value) ? value : String(value || '').split(',');
  return new Set(list.map((o) => String(o).trim()).filter((o) => o && o !== '*'));
}

function createServer(options = {}) {
  const db = options.db || openDatabase(options.dbPath || ':memory:');
  const limiter = options.limiter || new RateLimiter();
  const streams = new Map(); // deviceId -> Set<ServerResponse>

  // CORS exists only so a browser build of the client can reach the relay.
  // It is OFF unless origins are allowlisted, and it is not a security
  // boundary here: authentication is a bearer token, never a cookie, so a
  // foreign page gains nothing it could not already do with a stolen token.
  // Native mobile clients never send an Origin and are unaffected.
  const corsOrigins = parseCorsOrigins(options.corsOrigins);

  function corsHeaders(req) {
    if (corsOrigins.size === 0) return {};
    const origin = req.headers.origin;
    if (!origin || !corsOrigins.has(origin)) return { Vary: 'Origin' };
    return {
      Vary: 'Origin',
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Methods': 'GET, POST',
      'Access-Control-Allow-Headers': 'Authorization, Content-Type',
      'Access-Control-Max-Age': '600',
    };
  }

  // ---------------------------------------------------------------- helpers

  function requireAuth(req) {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) throw new HttpError(401, 'missing_token');
    const session = auth.resolveToken(db, token);
    if (!session) throw new HttpError(401, 'invalid_token');
    if (session.deviceId) {
      const device = db.prepare('SELECT revoked_at FROM devices WHERE device_id = ?')
        .get(session.deviceId);
      if (device && device.revoked_at !== null) {
        throw new HttpError(401, 'device_revoked');
      }
      db.prepare('UPDATE devices SET last_seen_at = ? WHERE device_id = ?')
        .run(now(), session.deviceId);
    }
    return { ...session, token };
  }

  function rateLimit(bucket, subject) {
    const result = limiter.check(bucket, subject);
    if (!result.allowed) {
      const err = new HttpError(429, 'rate_limited');
      err.retryAfter = result.retryAfter;
      throw err;
    }
  }

  function notifyStream(deviceId) {
    const set = streams.get(deviceId);
    if (!set) return;
    // The push carries NO message content -- only a wake-up. The client then
    // fetches over the authenticated channel. A leaky SSE proxy therefore
    // cannot learn ciphertext, only that traffic occurred.
    for (const res of set) {
      try { res.write(`event: message\ndata: {"pending":true}\n\n`); } catch { /* dropped */ }
    }
  }

  // ----------------------------------------------------------------- routes

  const routes = {
    'POST /auth/register': async (req, ctx) => {
      rateLimit('auth:register', ctx.ip);
      const body = await readBody(req);
      const username = requireString(body, 'username', { max: 64, pattern: ID });
      const password = requireString(body, 'password', { max: 512 });
      if (password.length < 12) {
        throw new HttpError(400, 'weak_password', 'password must be at least 12 characters');
      }
      const existing = db.prepare('SELECT 1 FROM accounts WHERE username = ?').get(username);
      if (existing) throw new HttpError(409, 'username_taken');

      const accountId = randomUUID();
      const { hash, salt } = auth.hashPassword(password);
      db.prepare(
        `INSERT INTO accounts (account_id, username, password_hash, password_salt, created_at)
         VALUES (?, ?, ?, ?, ?)`
      ).run(accountId, username, hash, salt, now());
      log.info('account_registered', { account_hash: log.hashId(accountId) });
      return { status: 201, body: { account_id: accountId } };
    },

    'POST /auth/login': async (req, ctx) => {
      rateLimit('auth:login', ctx.ip);
      const body = await readBody(req);
      const username = requireString(body, 'username', { max: 64, pattern: ID });
      const password = requireString(body, 'password', { max: 512 });

      const account = db.prepare(
        'SELECT account_id, password_hash, password_salt FROM accounts WHERE username = ?'
      ).get(username);

      // Uniform failure: same status and message whether the account exists or
      // the password is wrong, so login is not a username oracle.
      if (!account || !auth.verifyPassword(password, account.password_salt, account.password_hash)) {
        log.security('login_failed', { outcome: 'rejected' });
        throw new HttpError(401, 'invalid_credentials');
      }
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
      const body = await readBody(req);
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
      const session = requireAuth(req);
      auth.revokeToken(db, session.token);
      return { status: 200, body: { revoked: true } };
    },

    'POST /devices': async (req) => {
      const session = requireAuth(req);
      const body = await readBody(req);
      const deviceId = requireString(body, 'device_id', { max: 64, pattern: ID });
      const identity = validateIdentity(body.identity);

      const existing = db.prepare('SELECT account_id FROM devices WHERE device_id = ?')
        .get(deviceId);
      if (existing && existing.account_id !== session.accountId) {
        throw new HttpError(409, 'device_id_taken');
      }
      db.prepare(
        `INSERT INTO devices (device_id, account_id, identity_json, registered_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(device_id) DO UPDATE SET identity_json = excluded.identity_json`
      ).run(deviceId, session.accountId, JSON.stringify(identity), now());

      log.info('device_registered', { device_hash: log.hashId(deviceId) });
      return {
        status: 201,
        body: {
          device_id: deviceId,
          device_token: auth.issueToken(db, session.accountId, deviceId, 'access'),
        },
      };
    },

    'GET /devices': async (req) => {
      const session = requireAuth(req);
      const rows = db.prepare(
        `SELECT device_id, registered_at, last_seen_at, revoked_at, identity_json
         FROM devices WHERE account_id = ?`
      ).all(session.accountId);
      return {
        status: 200,
        body: {
          devices: rows.map((r) => ({
            device_id: r.device_id,
            registered_at: r.registered_at,
            last_seen_at: r.last_seen_at,
            revoked: r.revoked_at !== null,
            identity: JSON.parse(r.identity_json),
          })),
        },
      };
    },

    'POST /prekeys': async (req) => {
      const session = requireAuth(req);
      rateLimit('prekeys:publish', session.accountId);
      const body = await readBody(req);
      const deviceId = requireString(body, 'device_id', { max: 64, pattern: ID });

      const device = db.prepare('SELECT account_id FROM devices WHERE device_id = ?')
        .get(deviceId);
      if (!device || device.account_id !== session.accountId) {
        throw new HttpError(403, 'not_your_device');
      }

      const signed = validateSignedPreKey(body.signed_prekey);
      const oneTime = validateOneTimePreKeys(body.one_time_prekeys || []);

      db.prepare(
        `INSERT INTO signed_prekeys (device_id, key_id, public_key, signature, created_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(device_id, key_id) DO UPDATE SET
           public_key = excluded.public_key, signature = excluded.signature`
      ).run(deviceId, signed.key_id, signed.public, signed.signature, signed.created_at);

      const insert = db.prepare(
        `INSERT INTO one_time_prekeys (device_id, key_id, public_key)
         VALUES (?, ?, ?) ON CONFLICT(device_id, key_id) DO NOTHING`
      );
      for (const otp of oneTime) insert.run(deviceId, otp.key_id, otp.public);

      const available = db.prepare(
        'SELECT COUNT(*) AS n FROM one_time_prekeys WHERE device_id = ? AND consumed_at IS NULL'
      ).get(deviceId).n;

      log.info('prekeys_published', {
        device_hash: log.hashId(deviceId), prekey_count: available,
      });
      return { status: 200, body: { available_one_time_prekeys: available } };
    },

    'GET /prekeys/:deviceId': async (req, ctx) => {
      const session = requireAuth(req);
      rateLimit('prekeys:fetch', session.accountId);
      const deviceId = ctx.params.deviceId;

      const device = db.prepare(
        'SELECT identity_json, revoked_at FROM devices WHERE device_id = ?'
      ).get(deviceId);
      if (!device) throw new HttpError(404, 'device_not_found');
      if (device.revoked_at !== null) throw new HttpError(410, 'device_revoked');

      const signed = db.prepare(
        `SELECT key_id, public_key, signature, created_at FROM signed_prekeys
         WHERE device_id = ? ORDER BY key_id DESC LIMIT 1`
      ).get(deviceId);
      if (!signed) throw new HttpError(404, 'no_signed_prekey');

      // Atomic single-consumption: the UPDATE ... RETURNING claims exactly one
      // prekey. Two concurrent fetchers cannot receive the same one.
      const claimed = db.prepare(
        `UPDATE one_time_prekeys SET consumed_at = ?
         WHERE rowid = (
           SELECT rowid FROM one_time_prekeys
           WHERE device_id = ? AND consumed_at IS NULL
           ORDER BY key_id LIMIT 1)
         RETURNING key_id, public_key`
      ).get(now(), deviceId);

      const remaining = db.prepare(
        'SELECT COUNT(*) AS n FROM one_time_prekeys WHERE device_id = ? AND consumed_at IS NULL'
      ).get(deviceId).n;

      return {
        status: 200,
        body: {
          device_id: deviceId,
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
          remaining_one_time_prekeys: remaining,
        },
      };
    },

    'POST /messages': async (req) => {
      const session = requireAuth(req);
      rateLimit('messages:send', session.accountId);
      const body = await readBody(req);
      const recipient = requireString(body, 'recipient_device_id', { max: 64, pattern: ID });

      // The ONLY thing done with the envelope: shape and size validation.
      const { serialized, sizeBytes } = validateEnvelope(body.envelope);

      const device = db.prepare('SELECT revoked_at FROM devices WHERE device_id = ?')
        .get(recipient);
      if (!device) throw new HttpError(404, 'recipient_not_found');
      if (device.revoked_at !== null) throw new HttpError(410, 'recipient_revoked');

      const messageId = randomUUID();
      db.prepare(
        `INSERT INTO messages
           (message_id, recipient_device, sender_device, envelope_json, size_bytes, queued_at)
         VALUES (?, ?, ?, ?, ?, ?)`
      ).run(messageId, recipient, body.envelope.sender_device_id, serialized, sizeBytes, now());

      notifyStream(recipient);
      log.info('message_queued', {
        recipient_hash: log.hashId(recipient), size_bytes: sizeBytes,
      });
      return { status: 202, body: { message_id: messageId, queued_at: now() } };
    },

    'GET /messages': async (req) => {
      const session = requireAuth(req);
      if (!session.deviceId) throw new HttpError(403, 'device_token_required');
      rateLimit('messages:fetch', session.deviceId);

      const rows = db.prepare(
        `SELECT message_id, sender_device, envelope_json, queued_at FROM messages
         WHERE recipient_device = ? AND acked_at IS NULL
         ORDER BY seq LIMIT ?`
      ).all(session.deviceId, MESSAGE_FETCH_LIMIT);

      if (rows.length > 0) {
        const mark = db.prepare(
          'UPDATE messages SET delivered_at = COALESCE(delivered_at, ?) WHERE message_id = ?'
        );
        for (const row of rows) mark.run(now(), row.message_id);
      }

      return {
        status: 200,
        body: {
          messages: rows.map((r) => ({
            message_id: r.message_id,
            sender_device_id: r.sender_device,
            queued_at: r.queued_at,
            envelope: JSON.parse(r.envelope_json),
          })),
        },
      };
    },

    'POST /delivery/ack': async (req) => {
      const session = requireAuth(req);
      if (!session.deviceId) throw new HttpError(403, 'device_token_required');
      const body = await readBody(req);
      if (!Array.isArray(body.message_ids) || body.message_ids.length > 500) {
        throw new ValidationError('message_ids must be an array of at most 500 ids');
      }
      // Acked messages are DELETED, not flagged. A delivered ciphertext has no
      // further purpose on the relay, and retaining it only enlarges what a
      // future database compromise yields.
      const del = db.prepare(
        'DELETE FROM messages WHERE message_id = ? AND recipient_device = ?'
      );
      let removed = 0;
      for (const id of body.message_ids) {
        if (typeof id === 'string') removed += del.run(id, session.deviceId).changes;
      }
      return { status: 200, body: { acknowledged: removed } };
    },

    'POST /devices/revoke': async (req) => {
      const session = requireAuth(req);
      const body = await readBody(req);
      const deviceId = requireString(body, 'device_id', { max: 64, pattern: ID });
      const device = db.prepare('SELECT account_id FROM devices WHERE device_id = ?')
        .get(deviceId);
      if (!device || device.account_id !== session.accountId) {
        throw new HttpError(403, 'not_your_device');
      }
      auth.revokeDevice(db, deviceId);
      db.prepare('DELETE FROM one_time_prekeys WHERE device_id = ?').run(deviceId);
      log.security('device_revoked', { device_hash: log.hashId(deviceId) });
      return { status: 200, body: { revoked: true } };
    },

    'GET /health': async () => ({
      status: 200,
      body: {
        status: 'ok',
        service: 'helo-relay',
        // Deliberately minimal: version and queue depth are operational data,
        // but user counts and device lists are metadata and are NOT exposed.
        protocol_version: 1,
      },
    }),
  };

  // ------------------------------------------------------------- dispatcher

  function matchRoute(method, pathname) {
    const direct = `${method} ${pathname}`;
    if (routes[direct]) return { handler: routes[direct], params: {} };
    for (const key of Object.keys(routes)) {
      const [routeMethod, routePath] = key.split(' ');
      if (routeMethod !== method || !routePath.includes(':')) continue;
      const routeParts = routePath.split('/');
      const pathParts = pathname.split('/');
      if (routeParts.length !== pathParts.length) continue;
      const params = {};
      let ok = true;
      for (let i = 0; i < routeParts.length; i += 1) {
        if (routeParts[i].startsWith(':')) params[routeParts[i].slice(1)] = pathParts[i];
        else if (routeParts[i] !== pathParts[i]) { ok = false; break; }
      }
      if (ok) return { handler: routes[key], params };
    }
    return null;
  }

  const server = http.createServer(async (req, res) => {
    const started = Date.now();
    const url = new URL(req.url, 'http://relay.invalid');
    const ip = req.socket.remoteAddress || 'unknown';
    const cors = corsHeaders(req);
    const baseHeaders = { ...SECURITY_HEADERS, ...cors };

    // CORS preflight. Answered only for an allowlisted origin; anything else
    // falls through to the router and receives an ordinary 404.
    if (req.method === 'OPTIONS' && cors['Access-Control-Allow-Origin']) {
      res.writeHead(204, baseHeaders);
      res.end();
      return;
    }

    // Realtime delivery notification stream (SSE).
    if (req.method === 'GET' && url.pathname === '/messages/stream') {
      let session;
      try {
        session = requireAuth(req);
      } catch (err) {
        res.writeHead(err.status || 401, baseHeaders);
        res.end(JSON.stringify({ error: err.code || 'unauthorized' }));
        return;
      }
      if (!session.deviceId) {
        res.writeHead(403, baseHeaders);
        res.end(JSON.stringify({ error: 'device_token_required' }));
        return;
      }
      res.writeHead(200, {
        ...baseHeaders,
        'Content-Type': 'text/event-stream',
        Connection: 'keep-alive',
      });
      res.write('event: ready\ndata: {}\n\n');
      if (!streams.has(session.deviceId)) streams.set(session.deviceId, new Set());
      streams.get(session.deviceId).add(res);
      req.on('close', () => {
        const set = streams.get(session.deviceId);
        if (set) { set.delete(res); if (set.size === 0) streams.delete(session.deviceId); }
      });
      return;
    }

    const match = matchRoute(req.method, url.pathname);
    let status = 404;
    let payload = { error: 'not_found' };

    if (match) {
      try {
        const result = await match.handler(req, { params: match.params, ip, url });
        status = result.status;
        payload = result.body;
      } catch (err) {
        if (err instanceof ValidationError) {
          status = 400;
          payload = { error: 'validation_failed', field: err.field, message: err.message };
        } else if (err instanceof HttpError) {
          status = err.status;
          payload = { error: err.code };
          if (err.retryAfter) payload.retry_after = err.retryAfter;
        } else {
          // Never leak an internal stack trace to a client.
          status = 500;
          payload = { error: 'internal_error' };
          log.error('unhandled_error', { error_class: err?.constructor?.name || 'Error' });
        }
      }
    }

    const headers = { ...baseHeaders };
    if (status === 429 && payload.retry_after) headers['Retry-After'] = String(payload.retry_after);

    res.writeHead(status, headers);
    res.end(JSON.stringify(payload));

    log.info('request', {
      method: req.method, path: url.pathname, status,
      duration_ms: Date.now() - started, rate_limited: status === 429,
    });
  });

  const sweepTimer = setInterval(() => {
    try {
      const removed = sweep(db);
      limiter.prune();
      const total = Object.values(removed).reduce((a, b) => a + b, 0);
      if (total > 0) log.info('retention_sweep', { removed: total });
    } catch (err) {
      log.error('sweep_failed', { error_class: err?.constructor?.name });
    }
  }, 60_000);
  sweepTimer.unref?.();

  server.on('close', () => clearInterval(sweepTimer));
  server.db = db;
  server.limiter = limiter;
  return server;
}

module.exports = { createServer, parseCorsOrigins, HttpError, SECURITY_HEADERS };

if (require.main === module) {
  const port = Number(process.env.PORT || 8443);
  const host = process.env.HOST || '0.0.0.0';
  const dbPath = process.env.DB_PATH || './data/helo.db';
  const corsOrigins = parseCorsOrigins(process.env.CORS_ORIGINS);
  const server = createServer({ dbPath, corsOrigins: [...corsOrigins] });
  server.listen(port, host, () => {
    log.info('relay_started', { status: port });
    process.stdout.write(
      `helo-relay listening on ${host}:${port} (db: ${dbPath})\n` +
      (corsOrigins.size
        ? `CORS allowlist: ${[...corsOrigins].join(', ')}\n`
        : 'CORS disabled (set CORS_ORIGINS to allow a browser client)\n') +
      'NOTE: terminate TLS in front of this process. It speaks plain HTTP by design.\n'
    );
  });
}
