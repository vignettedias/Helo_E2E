'use strict';
/**
 * Relay test suite.
 *
 * The important tests here are not "does the API work" but "can the relay be
 * made to do something it must not do" -- serve a prekey twice, accept an
 * unknown field, leak a username through login timing behaviour, or store
 * anything it can read.
 */

const test = require('node:test');
const assert = require('node:assert');
const { createServer, parseCorsOrigins } = require('../src/server');
const { RateLimiter } = require('../src/ratelimit');

// --------------------------------------------------------------- test client

async function start(options = {}) {
  const server = createServer(options);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const base = `http://127.0.0.1:${port}`;

  const call = async (method, path, { body, token, headers: extra } = {}) => {
    const headers = { 'Content-Type': 'application/json', ...extra };
    if (token) headers.Authorization = `Bearer ${token}`;
    const res = await fetch(base + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    let json = null;
    try { json = await res.json(); } catch { /* empty body */ }
    return { status: res.status, body: json, headers: res.headers };
  };

  return {
    server, base, call,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

const PASSWORD = 'correct-horse-battery-staple';

async function registerAndLogin(client, username) {
  await client.call('POST', '/auth/register', { body: { username, password: PASSWORD } });
  const login = await client.call('POST', '/auth/login', {
    body: { username, password: PASSWORD },
  });
  return login.body.access_token;
}

const FAKE_IDENTITY = {
  sig_pub: Buffer.alloc(32, 1).toString('base64'),
  dh_pub: Buffer.alloc(32, 2).toString('base64'),
  binding_sig: Buffer.alloc(64, 3).toString('base64'),
};

function fakeEnvelope(sender = 'alice-device', sessionId = 'abc123') {
  return {
    v: 1,
    type: 'normal',
    session_id: sessionId,
    sender_device_id: sender,
    header: Buffer.alloc(41, 7).toString('base64'),
    ciphertext: Buffer.alloc(64, 9).toString('base64'),
  };
}

async function registerDevice(client, token, deviceId) {
  const res = await client.call('POST', '/devices', {
    token, body: { device_id: deviceId, identity: FAKE_IDENTITY },
  });
  return res.body.device_token;
}

// ----------------------------------------------------------------- auth

test('registration and login issue usable tokens', async (t) => {
  const c = await start();
  t.after(() => c.close());

  const reg = await c.call('POST', '/auth/register', {
    body: { username: 'alice', password: PASSWORD },
  });
  assert.strictEqual(reg.status, 201);

  const login = await c.call('POST', '/auth/login', {
    body: { username: 'alice', password: PASSWORD },
  });
  assert.strictEqual(login.status, 200);
  assert.ok(login.body.access_token);
  assert.ok(login.body.refresh_token);
});

test('login failure is identical for unknown user and wrong password', async (t) => {
  const c = await start();
  t.after(() => c.close());
  await c.call('POST', '/auth/register', { body: { username: 'alice', password: PASSWORD } });

  const wrongPassword = await c.call('POST', '/auth/login', {
    body: { username: 'alice', password: 'wrong-password-here' },
  });
  const unknownUser = await c.call('POST', '/auth/login', {
    body: { username: 'nobody', password: PASSWORD },
  });

  // If these differed, login would be a username enumeration oracle.
  assert.strictEqual(wrongPassword.status, unknownUser.status);
  assert.deepStrictEqual(wrongPassword.body, unknownUser.body);
});

test('weak passwords are rejected', async (t) => {
  const c = await start();
  t.after(() => c.close());
  const res = await c.call('POST', '/auth/register', {
    body: { username: 'bob', password: 'short' },
  });
  assert.strictEqual(res.status, 400);
});

test('protected routes require a valid token', async (t) => {
  const c = await start();
  t.after(() => c.close());

  assert.strictEqual((await c.call('GET', '/devices')).status, 401);
  assert.strictEqual(
    (await c.call('GET', '/devices', { token: 'garbage' })).status, 401);
});

test('logout revokes the token immediately', async (t) => {
  const c = await start();
  t.after(() => c.close());
  const token = await registerAndLogin(c, 'alice');

  assert.strictEqual((await c.call('GET', '/devices', { token })).status, 200);
  await c.call('POST', '/auth/logout', { token });
  assert.strictEqual((await c.call('GET', '/devices', { token })).status, 401);
});

test('database stores no recoverable password or token', async (t) => {
  const c = await start();
  t.after(() => c.close());
  const token = await registerAndLogin(c, 'alice');

  const accounts = c.server.db.prepare('SELECT * FROM accounts').all();
  const tokens = c.server.db.prepare('SELECT * FROM tokens').all();
  const dump = JSON.stringify({ accounts, tokens });

  assert.ok(!dump.includes(PASSWORD), 'password must not be stored');
  assert.ok(!dump.includes(token), 'raw token must not be stored');
});

// -------------------------------------------------------------- prekeys

test('a one-time prekey is served to exactly one requester', async (t) => {
  const c = await start();
  t.after(() => c.close());

  const bobToken = await registerAndLogin(c, 'bob');
  await registerDevice(c, bobToken, 'bob-device');
  await c.call('POST', '/prekeys', {
    token: bobToken,
    body: {
      device_id: 'bob-device',
      signed_prekey: {
        key_id: 1, public: Buffer.alloc(32, 4).toString('base64'),
        signature: Buffer.alloc(64, 5).toString('base64'), created_at: 1700000000,
      },
      one_time_prekeys: [
        { key_id: 1, public: Buffer.alloc(32, 6).toString('base64') },
        { key_id: 2, public: Buffer.alloc(32, 7).toString('base64') },
      ],
    },
  });

  const aliceToken = await registerAndLogin(c, 'alice');
  const first = await c.call('GET', '/prekeys/bob-device', { token: aliceToken });
  const second = await c.call('GET', '/prekeys/bob-device', { token: aliceToken });
  const third = await c.call('GET', '/prekeys/bob-device', { token: aliceToken });

  assert.notStrictEqual(first.body.one_time_prekey.key_id,
    second.body.one_time_prekey.key_id, 'same prekey served twice');
  assert.strictEqual(third.body.one_time_prekey, null,
    'exhausted store must return null, not reuse');
  assert.strictEqual(third.body.one_time_prekey_available, false);
});

test('prekey exhaustion is surfaced so the client can warn about downgrade', async (t) => {
  const c = await start();
  t.after(() => c.close());
  const bobToken = await registerAndLogin(c, 'bob');
  await registerDevice(c, bobToken, 'bob-device');
  await c.call('POST', '/prekeys', {
    token: bobToken,
    body: {
      device_id: 'bob-device',
      signed_prekey: {
        key_id: 1, public: Buffer.alloc(32, 4).toString('base64'),
        signature: Buffer.alloc(64, 5).toString('base64'), created_at: 1700000000,
      },
      one_time_prekeys: [],
    },
  });
  const aliceToken = await registerAndLogin(c, 'alice');
  const res = await c.call('GET', '/prekeys/bob-device', { token: aliceToken });
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.body.one_time_prekey_available, false);
});

test('a device cannot publish prekeys for another account', async (t) => {
  const c = await start();
  t.after(() => c.close());
  const bobToken = await registerAndLogin(c, 'bob');
  await registerDevice(c, bobToken, 'bob-device');
  const mallory = await registerAndLogin(c, 'mallory');

  const res = await c.call('POST', '/prekeys', {
    token: mallory,
    body: {
      device_id: 'bob-device',
      signed_prekey: {
        key_id: 99, public: Buffer.alloc(32, 4).toString('base64'),
        signature: Buffer.alloc(64, 5).toString('base64'), created_at: 1700000000,
      },
      one_time_prekeys: [],
    },
  });
  assert.strictEqual(res.status, 403);
});

// -------------------------------------------------------------- messages

test('messages relay end to end and are deleted on acknowledgement', async (t) => {
  const c = await start();
  t.after(() => c.close());

  const bobToken = await registerAndLogin(c, 'bob');
  const bobDevice = await registerDevice(c, bobToken, 'bob-device');
  const aliceToken = await registerAndLogin(c, 'alice');

  const send = await c.call('POST', '/messages', {
    token: aliceToken,
    body: { recipient_device_id: 'bob-device', envelope: fakeEnvelope() },
  });
  assert.strictEqual(send.status, 202);

  const fetched = await c.call('GET', '/messages', { token: bobDevice });
  assert.strictEqual(fetched.body.messages.length, 1);
  assert.deepStrictEqual(fetched.body.messages[0].envelope, fakeEnvelope());

  await c.call('POST', '/delivery/ack', {
    token: bobDevice,
    body: { message_ids: [fetched.body.messages[0].message_id] },
  });

  const after = await c.call('GET', '/messages', { token: bobDevice });
  assert.strictEqual(after.body.messages.length, 0);
  const rows = c.server.db.prepare('SELECT COUNT(*) AS n FROM messages').get();
  assert.strictEqual(rows.n, 0, 'acked message must be deleted, not retained');
});

test('offline queue preserves messages until the recipient connects', async (t) => {
  const c = await start();
  t.after(() => c.close());
  const bobToken = await registerAndLogin(c, 'bob');
  const bobDevice = await registerDevice(c, bobToken, 'bob-device');
  const aliceToken = await registerAndLogin(c, 'alice');

  for (let i = 0; i < 5; i += 1) {
    await c.call('POST', '/messages', {
      token: aliceToken,
      body: { recipient_device_id: 'bob-device', envelope: fakeEnvelope('alice-device', 'abc12' + i) },
    });
  }
  const fetched = await c.call('GET', '/messages', { token: bobDevice });
  assert.strictEqual(fetched.body.messages.length, 5);
});

test('envelope with an unexpected field is rejected', async (t) => {
  const c = await start();
  t.after(() => c.close());
  const bobToken = await registerAndLogin(c, 'bob');
  await registerDevice(c, bobToken, 'bob-device');
  const aliceToken = await registerAndLogin(c, 'alice');

  // A client bug attaching a plaintext preview must be refused at the boundary.
  const bad = { ...fakeEnvelope(), preview: 'hi bob' };
  const res = await c.call('POST', '/messages', {
    token: aliceToken, body: { recipient_device_id: 'bob-device', envelope: bad },
  });
  assert.strictEqual(res.status, 400);
  assert.strictEqual(res.body.field, 'preview');
});

test('oversized and malformed envelopes are rejected', async (t) => {
  const c = await start();
  t.after(() => c.close());
  const bobToken = await registerAndLogin(c, 'bob');
  await registerDevice(c, bobToken, 'bob-device');
  const aliceToken = await registerAndLogin(c, 'alice');

  const cases = [
    { ...fakeEnvelope(), ciphertext: 'not base64!!' },
    { ...fakeEnvelope(), v: 2 },
    { ...fakeEnvelope(), type: 'plaintext' },
    { ...fakeEnvelope(), ciphertext: 'A'.repeat(200 * 1024) },
    { ...fakeEnvelope(), x3dh: { some: 'thing' } },
  ];
  for (const envelope of cases) {
    const res = await c.call('POST', '/messages', {
      token: aliceToken, body: { recipient_device_id: 'bob-device', envelope },
    });
    assert.ok(res.status === 400 || res.status === 413,
      `expected rejection, got ${res.status}`);
  }
});

test('a device cannot fetch another device queue', async (t) => {
  const c = await start();
  t.after(() => c.close());
  const bobToken = await registerAndLogin(c, 'bob');
  await registerDevice(c, bobToken, 'bob-device');
  const aliceToken = await registerAndLogin(c, 'alice');
  const aliceDevice = await registerDevice(c, aliceToken, 'alice-device');

  await c.call('POST', '/messages', {
    token: aliceToken,
    body: { recipient_device_id: 'bob-device', envelope: fakeEnvelope() },
  });
  const res = await c.call('GET', '/messages', { token: aliceDevice });
  assert.strictEqual(res.body.messages.length, 0, 'queues must not cross devices');
});

// ------------------------------------------------------- revocation

test('a revoked device cannot authenticate or receive messages', async (t) => {
  const c = await start();
  t.after(() => c.close());
  const bobToken = await registerAndLogin(c, 'bob');
  const bobDevice = await registerDevice(c, bobToken, 'bob-device');
  const aliceToken = await registerAndLogin(c, 'alice');

  await c.call('POST', '/devices/revoke', {
    token: bobToken, body: { device_id: 'bob-device' },
  });

  assert.strictEqual((await c.call('GET', '/messages', { token: bobDevice })).status, 401);
  const send = await c.call('POST', '/messages', {
    token: aliceToken, body: { recipient_device_id: 'bob-device', envelope: fakeEnvelope() },
  });
  assert.strictEqual(send.status, 410);
  const prekeys = await c.call('GET', '/prekeys/bob-device', { token: aliceToken });
  assert.strictEqual(prekeys.status, 410);
});

// ------------------------------------------------------- rate limiting

test('login attempts are rate limited', async (t) => {
  const c = await start();
  t.after(() => c.close());
  await c.call('POST', '/auth/register', { body: { username: 'alice', password: PASSWORD } });

  let limited = false;
  for (let i = 0; i < 15; i += 1) {
    const res = await c.call('POST', '/auth/login', {
      body: { username: 'alice', password: 'wrong-password-x' },
    });
    if (res.status === 429) { limited = true; break; }
  }
  assert.ok(limited, 'credential stuffing must be rate limited');
});

test('prekey fetches are rate limited to slow prekey exhaustion', async (t) => {
  const c = await start();
  t.after(() => c.close());
  const bobToken = await registerAndLogin(c, 'bob');
  await registerDevice(c, bobToken, 'bob-device');
  await c.call('POST', '/prekeys', {
    token: bobToken,
    body: {
      device_id: 'bob-device',
      signed_prekey: {
        key_id: 1, public: Buffer.alloc(32, 4).toString('base64'),
        signature: Buffer.alloc(64, 5).toString('base64'), created_at: 1700000000,
      },
      one_time_prekeys: [],
    },
  });
  const aliceToken = await registerAndLogin(c, 'alice');

  let limited = false;
  for (let i = 0; i < 60; i += 1) {
    const res = await c.call('GET', '/prekeys/bob-device', { token: aliceToken });
    if (res.status === 429) {
      limited = true;
      assert.ok(res.headers.get('retry-after'), 'must advertise Retry-After');
      break;
    }
  }
  assert.ok(limited, 'prekey draining must be rate limited');
});

// ------------------------------------------------------- hardening

test('security headers are present on every response', async (t) => {
  const c = await start();
  t.after(() => c.close());
  const res = await c.call('GET', '/health');
  for (const header of ['x-content-type-options', 'x-frame-options',
    'content-security-policy', 'referrer-policy', 'cache-control']) {
    assert.ok(res.headers.get(header), `missing ${header}`);
  }
});

test('health endpoint leaks no user metadata', async (t) => {
  const c = await start();
  t.after(() => c.close());
  await registerAndLogin(c, 'alice');
  const res = await c.call('GET', '/health');
  const body = JSON.stringify(res.body);
  assert.ok(!body.includes('alice'));
  assert.ok(!/user_count|device_count|accounts/.test(body));
});

test('internal errors never leak a stack trace', async (t) => {
  const c = await start();
  t.after(() => c.close());
  const res = await c.call('POST', '/auth/login', { body: null });
  assert.ok(res.status >= 400);
  const body = JSON.stringify(res.body);
  assert.ok(!body.includes('at Object.'), 'stack trace leaked');
  assert.ok(!body.includes('/src/'), 'file path leaked');
});

test('rate limiter refills over time', () => {
  let clock = 0;
  const limiter = new RateLimiter(() => clock);
  for (let i = 0; i < 5; i += 1) {
    assert.strictEqual(limiter.check('auth:login', 'ip').allowed, true);
  }
  assert.strictEqual(limiter.check('auth:login', 'ip').allowed, false);
  clock += 3600;
  assert.strictEqual(limiter.check('auth:login', 'ip').allowed, true);
});

test('queue preserves strict FIFO order within the same second', async (t) => {
  // Regression test. Messages queued in one second previously fell back to
  // ordering by random UUID. The protocol tolerates out-of-order delivery, so
  // this defect decrypted correctly and was invisible until checked directly.
  const c = await start();
  t.after(() => c.close());
  const bobToken = await registerAndLogin(c, 'bob');
  const bobDevice = await registerDevice(c, bobToken, 'bob-device');
  const aliceToken = await registerAndLogin(c, 'alice');

  const sent = [];
  for (let i = 0; i < 20; i += 1) {
    const sessionId = i.toString(16).padStart(8, '0');
    const res = await c.call('POST', '/messages', {
      token: aliceToken,
      body: {
        recipient_device_id: 'bob-device',
        envelope: fakeEnvelope('alice-device', sessionId),
      },
    });
    sent.push(res.body.message_id);
  }

  const fetched = await c.call('GET', '/messages', { token: bobDevice });
  const order = fetched.body.messages.map((m) => m.message_id);
  assert.deepStrictEqual(order, sent, 'queue must deliver in strict send order');
});

// ------------------------------------------------------------------ CORS

test('CORS is off by default: no browser origin is granted access', async (t) => {
  const c = await start();
  t.after(() => c.close());
  const origin = { Origin: 'http://localhost:5000' };

  const preflight = await c.call('OPTIONS', '/auth/login', { headers: origin });
  assert.strictEqual(preflight.status, 404);
  assert.strictEqual(preflight.headers.get('access-control-allow-origin'), null);

  const health = await c.call('GET', '/health', { headers: origin });
  assert.strictEqual(health.headers.get('access-control-allow-origin'), null);
});

test('an allowlisted origin gets a preflight and CORS headers; others do not', async (t) => {
  const c = await start({ corsOrigins: ['http://localhost:5000'] });
  t.after(() => c.close());

  const preflight = await c.call('OPTIONS', '/messages', {
    headers: { Origin: 'http://localhost:5000' },
  });
  assert.strictEqual(preflight.status, 204);
  assert.strictEqual(
    preflight.headers.get('access-control-allow-origin'), 'http://localhost:5000');
  assert.match(preflight.headers.get('access-control-allow-headers'), /Authorization/);
  // Security headers still apply to preflight responses.
  assert.ok(preflight.headers.get('x-content-type-options'));

  const ok = await c.call('GET', '/health', { headers: { Origin: 'http://localhost:5000' } });
  assert.strictEqual(ok.headers.get('access-control-allow-origin'), 'http://localhost:5000');

  const foreign = await c.call('GET', '/health', { headers: { Origin: 'http://evil.example' } });
  assert.strictEqual(foreign.headers.get('access-control-allow-origin'), null);
  const foreignPreflight = await c.call('OPTIONS', '/messages', {
    headers: { Origin: 'http://evil.example' },
  });
  assert.strictEqual(foreignPreflight.status, 404);
});

test('a wildcard CORS origin is refused rather than honoured', () => {
  assert.deepStrictEqual([...parseCorsOrigins('*')], []);
  assert.deepStrictEqual(
    [...parseCorsOrigins(' http://a.test , *,http://b.test ')],
    ['http://a.test', 'http://b.test']);
});
