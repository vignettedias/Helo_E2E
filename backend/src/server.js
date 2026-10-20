'use strict';
/**
 * Helo relay server.
 *
 * ARCHITECTURAL INVARIANT: there is no cryptographic key anywhere in this
 * process capable of decrypting a message or an attachment. The relay imports
 * no protocol code -- it cannot perform X3DH or PQXDH, it has no ratchet, it
 * holds no session state. Its relationship with a message is: authenticate the
 * sending device, validate shape, store bytes, hand bytes to the recipient,
 * delete bytes.
 *
 * Zero npm dependencies (node:http, node:crypto, node:sqlite only). Every
 * dependency is a supply-chain path into a service that handles ciphertext for
 * every user, so the dependency count is deliberately zero.
 *
 * Routes live in ./routes/*; this file wires them, applies CORS and security
 * headers, maps errors to responses, and runs the retention sweep.
 */

const http = require('node:http');

const { openDatabase, sweep } = require('./db');
const log = require('./log');
const { RateLimiter } = require('./ratelimit');
const { ValidationError } = require('./validate');
const { HttpError, SECURITY_HEADERS } = require('./http');
const { createContext } = require('./context');

const ROUTE_MODULES = [
  require('./routes/auth'),
  require('./routes/devices'),
  require('./routes/prekeys'),
  require('./routes/messages'),
  require('./routes/attachments'),
  require('./routes/social'),
  require('./routes/account'),
];

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
  const app = createContext({ db, limiter });

  const routes = {
    'GET /health': async () => ({
      status: 200,
      body: {
        status: 'ok',
        service: 'helo-relay',
        // Deliberately minimal: user counts and device lists are metadata and
        // are NOT exposed.
        protocol_version: 1,
      },
    }),
  };
  for (const make of ROUTE_MODULES) Object.assign(routes, make(app, options));

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
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE',
      'Access-Control-Allow-Headers': 'Authorization, Content-Type, X-Helo-Recipients',
      'Access-Control-Max-Age': '600',
    };
  }

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
        if (routeParts[i].startsWith(':')) {
          try {
            params[routeParts[i].slice(1)] = decodeURIComponent(pathParts[i]);
          } catch {
            ok = false;
            break;
          }
        } else if (routeParts[i] !== pathParts[i]) { ok = false; break; }
      }
      if (ok) return { handler: routes[key], params };
    }
    return null;
  }

  function handleStream(req, res, baseHeaders) {
    let session;
    try {
      session = app.requireDevice(req);
    } catch (err) {
      res.writeHead(err.status || 401, baseHeaders);
      res.end(JSON.stringify({ error: err.code || 'unauthorized' }));
      return;
    }
    res.writeHead(200, {
      ...baseHeaders,
      'Content-Type': 'text/event-stream',
      Connection: 'keep-alive',
    });
    res.write('event: ready\ndata: {}\n\n');
    app.addStream(session.deviceId, res);
    req.on('close', () => app.removeStream(session.deviceId, res));
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

    // Realtime delivery notification stream (SSE): a wake-up only, no content.
    if (req.method === 'GET' && url.pathname === '/messages/stream') {
      handleStream(req, res, baseHeaders);
      return;
    }

    const match = matchRoute(req.method, url.pathname);
    let status = 404;
    let payload = { error: 'not_found' };
    let raw = null;
    let contentType = null;

    if (match) {
      try {
        const result = await match.handler(req, { params: match.params, ip, url, res });
        status = result.status;
        payload = result.body;
        raw = result.raw || null;
        contentType = result.contentType || null;
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

    if (res.destroyed) return; // a long-poll whose client went away

    const headers = { ...baseHeaders };
    if (status === 429 && payload && payload.retry_after) {
      headers['Retry-After'] = String(payload.retry_after);
    }
    if (raw) {
      headers['Content-Type'] = contentType || 'application/octet-stream';
      headers['Content-Length'] = String(raw.length);
      res.writeHead(status, headers);
      res.end(raw);
    } else {
      res.writeHead(status, headers);
      res.end(JSON.stringify(payload));
    }

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

  server.on('close', () => {
    clearInterval(sweepTimer);
    app.releaseAll();
  });
  server.db = db;
  server.limiter = limiter;
  server.app = app;
  return server;
}

module.exports = { createServer, parseCorsOrigins, HttpError, SECURITY_HEADERS };

if (require.main === module) {
  const port = Number(process.env.PORT || 8443);
  const host = process.env.HOST || '0.0.0.0';
  const dbPath = process.env.DB_PATH || './data/helo.db';
  const corsOrigins = parseCorsOrigins(process.env.CORS_ORIGINS);
  const maxAttachmentBytes = Number(process.env.MAX_ATTACHMENT_BYTES) || undefined;
  const server = createServer({ dbPath, corsOrigins: [...corsOrigins], maxAttachmentBytes });
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
