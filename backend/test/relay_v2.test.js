'use strict';
/**
 * HELO 2.0 relay tests: device-bound sending, directory, long-polling,
 * batching, post-quantum prekeys, attachments, blocking, presence, account
 * security, and schema migration.
 *
 * As in relay.test.js, the important questions are what the relay must
 * REFUSE: a forged sender, a cross-user attachment fetch, a blocked sender's
 * message, an identity swap under an existing device id.
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const { openDatabase, SCHEMA_V1, SCHEMA_VERSION } = require('../src/db');
const {
  PASSWORD, start, fakeIdentity, fakeEnvelope, registerAndLogin, registerDevice, user,
  SIGNED_PREKEY, pqKey,
} = require('./helpers');

// ------------------------------------------------- sender binding (A1)

test('a forged sender device id is refused', async (t) => {
  const c = await start();
  t.after(() => c.close());
  const alice = await user(c, 'alice');
  await user(c, 'bob');
  const mallory = await user(c, 'mallory');

  // Mallory, authenticated as her own device, claims to be Alice's device.
  const forged = await c.call('POST', '/messages', {
    token: mallory.device,
    body: { recipient_device_id: 'bob-device', envelope: fakeEnvelope('alice-device') },
  });
  assert.strictEqual(forged.status, 403);
  assert.strictEqual(forged.body.error, 'sender_mismatch');

  // An account token cannot send at all: it proves no device.
  const accountOnly = await c.call('POST', '/messages', {
    token: alice.account,
    body: { recipient_device_id: 'bob-device', envelope: fakeEnvelope('alice-device') },
  });
  assert.strictEqual(accountOnly.status, 403);
  assert.strictEqual(accountOnly.body.error, 'device_token_required');
});

test('fetched messages carry the relay-asserted sender username', async (t) => {
  const c = await start();
  t.after(() => c.close());
  const alice = await user(c, 'alice');
  const bob = await user(c, 'bob');
  await c.call('POST', '/messages', {
    token: alice.device,
    body: { recipient_device_id: 'bob-device', envelope: fakeEnvelope('alice-device') },
  });
  const res = await c.call('GET', '/messages', { token: bob.device });
  assert.strictEqual(res.body.messages[0].sender_username, 'alice');
  assert.strictEqual(res.body.messages[0].sender_device_id, 'alice-device');
});

// ----------------------------------------------------------- long-poll

test('a long-poll returns as soon as a message is queued', async (t) => {
  const c = await start();
  t.after(() => c.close());
  const alice = await user(c, 'alice');
  const bob = await user(c, 'bob');

  const started = Date.now();
  const pending = c.call('GET', '/messages?wait=10', { token: bob.device });
  await new Promise((r) => setTimeout(r, 150));
  await c.call('POST', '/messages', {
    token: alice.device,
    body: { recipient_device_id: 'bob-device', envelope: fakeEnvelope('alice-device') },
  });
  const res = await pending;
  const elapsed = Date.now() - started;
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.body.messages.length, 1);
  assert.ok(elapsed < 3000, `long-poll took ${elapsed} ms; it must wake on delivery`);
});

test('a long-poll with nothing queued returns empty after the wait', async (t) => {
  const c = await start();
  t.after(() => c.close());
  const bob = await user(c, 'bob');
  const started = Date.now();
  const res = await c.call('GET', '/messages?wait=1', { token: bob.device });
  assert.strictEqual(res.status, 200);
  assert.deepStrictEqual(res.body.messages, []);
  assert.ok(Date.now() - started >= 900);
});

// --------------------------------------------------------------- batch

test('batch fan-out accepts good items and rejects bad ones individually', async (t) => {
  const c = await start();
  t.after(() => c.close());
  const alice = await user(c, 'alice');
  const bob = await user(c, 'bob');
  const res = await c.call('POST', '/messages/batch', {
    token: alice.device,
    body: {
      messages: [
        { recipient_device_id: 'bob-device', envelope: fakeEnvelope('alice-device') },
        { recipient_device_id: 'nobody-device', envelope: fakeEnvelope('alice-device') },
        { recipient_device_id: 'bob-device', envelope: fakeEnvelope('bob-device') },
        null,
      ],
    },
  });
  assert.strictEqual(res.status, 200);
  assert.deepStrictEqual(res.body.results.map((r) => r.status), [202, 404, 403, 400]);
  const queue = await c.call('GET', '/messages', { token: bob.device });
  assert.strictEqual(queue.body.messages.length, 1);
});

// -------------------------------------------------- directory & devices

test('the directory resolves usernames to active devices, exact match only', async (t) => {
  const c = await start();
  t.after(() => c.close());
  const alice = await user(c, 'alice');
  await user(c, 'bob');

  const res = await c.call('GET', '/users/bob', { token: alice.account });
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.body.username, 'bob');
  assert.deepStrictEqual(res.body.devices.map((d) => d.device_id), ['bob-device']);
  assert.ok(res.body.devices[0].identity.sig_pub);

  assert.strictEqual((await c.call('GET', '/users/BOB', { token: alice.account })).status, 200,
    'usernames are case-insensitive');
  assert.strictEqual((await c.call('GET', '/users/bo', { token: alice.account })).status, 404,
    'no prefix matching');
  assert.strictEqual((await c.call('GET', '/users/bob')).status, 401);
});

test('usernames are case-insensitive and validated at registration', async (t) => {
  const c = await start();
  t.after(() => c.close());
  assert.strictEqual((await c.call('POST', '/auth/register', {
    body: { username: 'Alice', password: PASSWORD },
  })).status, 201);
  assert.strictEqual((await c.call('POST', '/auth/register', {
    body: { username: 'alice', password: PASSWORD },
  })).status, 409);
  const short = await c.call('POST', '/auth/register', { body: { username: 'ab', password: PASSWORD } });
  assert.strictEqual(short.status, 400);
  const login = await c.call('POST', '/auth/login', { body: { username: 'ALICE', password: PASSWORD } });
  assert.strictEqual(login.status, 200);
});

test("an existing device's identity cannot be swapped by re-registration", async (t) => {
  const c = await start();
  t.after(() => c.close());
  const account = await registerAndLogin(c, 'alice');
  await registerDevice(c, account, 'alice-device', fakeIdentity(1));

  const swap = await c.call('POST', '/devices', {
    token: account, body: { device_id: 'alice-device', identity: fakeIdentity(40) },
  });
  assert.strictEqual(swap.status, 409);
  assert.strictEqual(swap.body.error, 'identity_mismatch');

  const renew = await c.call('POST', '/devices', {
    token: account, body: { device_id: 'alice-device', identity: fakeIdentity(1) },
  });
  assert.strictEqual(renew.status, 201, 'same identity may obtain a fresh device token');
  assert.ok(renew.body.device_token);
});

// ------------------------------------------------- post-quantum prekeys

test('PQ one-time prekeys are served once each, then the last-resort key', async (t) => {
  const c = await start();
  t.after(() => c.close());
  const bob = await user(c, 'bob');
  const alice = await user(c, 'alice');
  const pub = await c.call('POST', '/prekeys', {
    token: bob.account,
    body: {
      device_id: 'bob-device',
      signed_prekey: SIGNED_PREKEY,
      one_time_prekeys: [],
      pq_last_resort: pqKey(100, 0x30),
      pq_one_time_prekeys: [pqKey(1, 0x10), pqKey(2, 0x20)],
    },
  });
  assert.strictEqual(pub.status, 200);
  assert.strictEqual(pub.body.available_pq_one_time_prekeys, 2);

  const seen = [];
  for (let i = 0; i < 4; i += 1) {
    const res = await c.call('GET', '/prekeys/bob-device', { token: alice.account });
    seen.push([res.body.pq_prekey.key_id, res.body.pq_prekey.one_time]);
  }
  assert.deepStrictEqual(seen, [[1, true], [2, true], [100, false], [100, false]]);
});

test('a device without PQ prekeys returns pq_prekey null, never a fabricated key', async (t) => {
  const c = await start();
  t.after(() => c.close());
  const bob = await user(c, 'bob');
  const alice = await user(c, 'alice');
  await c.call('POST', '/prekeys', {
    token: bob.account,
    body: { device_id: 'bob-device', signed_prekey: SIGNED_PREKEY, one_time_prekeys: [] },
  });
  const res = await c.call('GET', '/prekeys/bob-device', { token: alice.account });
  assert.strictEqual(res.body.pq_prekey, null);
});

// --------------------------------------------------------- attachments

test('attachments are served only to the uploader and listed recipients', async (t) => {
  const c = await start();
  t.after(() => c.close());
  const alice = await user(c, 'alice');
  const bob = await user(c, 'bob');
  const mallory = await user(c, 'mallory');
  const blob = Buffer.from('opaque ciphertext bytes \x00\x01\x02');

  const up = await c.call('POST', '/attachments', {
    token: alice.device, raw: blob, headers: { 'X-Helo-Recipients': 'bob-device' },
  });
  assert.strictEqual(up.status, 201);
  const id = up.body.attachment_id;
  assert.match(id, /^[a-f0-9]{32}$/);

  const forBob = await c.call('GET', `/attachments/${id}`, { token: bob.device });
  assert.strictEqual(forBob.status, 200);
  assert.deepStrictEqual(forBob.bytes, blob);
  assert.strictEqual((await c.call('GET', `/attachments/${id}`, { token: alice.device })).status, 200);

  const forMallory = await c.call('GET', `/attachments/${id}`, { token: mallory.device });
  assert.strictEqual(forMallory.status, 404, 'cross-user fetch must look like a missing id');
  assert.strictEqual((await c.call('GET', `/attachments/${id}`, { token: bob.account })).status, 403);
  assert.strictEqual((await c.call('GET', '/attachments/../../etc', { token: bob.device })).status, 404);

  assert.strictEqual((await c.call('DELETE', `/attachments/${id}`, { token: bob.device })).status, 404,
    'only the uploader may delete');
  assert.strictEqual((await c.call('DELETE', `/attachments/${id}`, { token: alice.device })).status, 200);
  assert.strictEqual((await c.call('GET', `/attachments/${id}`, { token: bob.device })).status, 404);
});

test('attachment uploads are size-limited and require a recipient list', async (t) => {
  const c = await start({ maxAttachmentBytes: 1024 });
  t.after(() => c.close());
  const alice = await user(c, 'alice');
  await user(c, 'bob');

  const big = await c.call('POST', '/attachments', {
    token: alice.device, raw: Buffer.alloc(2048), headers: { 'X-Helo-Recipients': 'bob-device' },
  });
  assert.strictEqual(big.status, 413);
  const noRecipients = await c.call('POST', '/attachments', { token: alice.device, raw: Buffer.alloc(10) });
  assert.strictEqual(noRecipients.status, 400);
  const json = await c.call('POST', '/attachments', {
    token: alice.device, body: { x: 1 }, headers: { 'X-Helo-Recipients': 'bob-device' },
  });
  assert.strictEqual(json.status, 415);
});

// ------------------------------------------------------------ blocking

test('blocking drops messages silently and hides the blocker', async (t) => {
  const c = await start();
  t.after(() => c.close());
  const alice = await user(c, 'alice');
  const bob = await user(c, 'bob');
  await c.call('POST', '/prekeys', {
    token: bob.account,
    body: { device_id: 'bob-device', signed_prekey: SIGNED_PREKEY, one_time_prekeys: [] },
  });

  assert.strictEqual((await c.call('POST', '/me/blocks', {
    token: bob.account, body: { username: 'alice' },
  })).status, 200);

  const send = await c.call('POST', '/messages', {
    token: alice.device,
    body: { recipient_device_id: 'bob-device', envelope: fakeEnvelope('alice-device') },
  });
  assert.strictEqual(send.status, 202, 'the sender must not learn of the block');
  assert.strictEqual((await c.call('GET', '/messages', { token: bob.device })).body.messages.length, 0);
  assert.strictEqual((await c.call('GET', '/users/bob', { token: alice.account })).status, 404);
  assert.strictEqual((await c.call('GET', '/prekeys/bob-device', { token: alice.account })).status, 404);
  assert.strictEqual((await c.call('GET', '/presence/bob', { token: alice.account })).status, 404);
  assert.deepStrictEqual((await c.call('GET', '/me/blocks', { token: bob.account })).body.blocked, ['alice']);

  await c.call('DELETE', '/me/blocks/alice', { token: bob.account });
  assert.strictEqual((await c.call('GET', '/users/bob', { token: alice.account })).status, 200);
});

test('reports accept a fixed reason vocabulary and carry no message content', async (t) => {
  const c = await start();
  t.after(() => c.close());
  const alice = await user(c, 'alice');
  await user(c, 'bob');
  const ok = await c.call('POST', '/reports', {
    token: alice.account, body: { username: 'bob', reason: 'spam', note: 'unsolicited links' },
  });
  assert.strictEqual(ok.status, 201);
  const bad = await c.call('POST', '/reports', {
    token: alice.account, body: { username: 'bob', reason: 'i-dont-like-them' },
  });
  assert.strictEqual(bad.status, 400);
  const row = c.server.db.prepare('SELECT * FROM reports').get();
  assert.deepStrictEqual(Object.keys(row).sort(),
    ['created_at', 'note', 'reason', 'report_id', 'reported_account', 'reporter_account']);
});

// ------------------------------------------------------------ presence

test('presence honours the target settings and is reciprocal', async (t) => {
  const c = await start();
  t.after(() => c.close());
  const alice = await user(c, 'alice');
  const bob = await user(c, 'bob');
  await c.call('GET', '/messages', { token: bob.device }); // bob was just active

  let res = await c.call('GET', '/presence/bob', { token: alice.account });
  assert.strictEqual(res.body.online, true);
  assert.ok(res.body.last_seen);

  await c.call('PUT', '/me/settings', { token: bob.account, body: { show_online: false } });
  res = await c.call('GET', '/presence/bob', { token: alice.account });
  assert.strictEqual(res.body.online, null);
  assert.ok(res.body.last_seen, 'last-seen is a separate setting');

  await c.call('PUT', '/me/settings', { token: alice.account, body: { show_last_seen: false } });
  res = await c.call('GET', '/presence/bob', { token: alice.account });
  assert.strictEqual(res.body.last_seen, null, 'hiding your own last-seen hides others\' from you');

  const bad = await c.call('PUT', '/me/settings', { token: bob.account, body: { read_receipts: false } });
  assert.strictEqual(bad.status, 400, 'the relay stores only settings it enforces');
});

// ---------------------------------------------------- account security

test('a password change revokes every other session', async (t) => {
  const c = await start();
  t.after(() => c.close());
  const current = await registerAndLogin(c, 'alice');
  const other = (await c.call('POST', '/auth/login', {
    body: { username: 'alice', password: PASSWORD },
  })).body.access_token;

  const wrong = await c.call('POST', '/auth/password', {
    token: current, body: { current_password: 'not-the-password', new_password: 'another-long-password' },
  });
  assert.strictEqual(wrong.status, 401);

  const change = await c.call('POST', '/auth/password', {
    token: current, body: { current_password: PASSWORD, new_password: 'another-long-password' },
  });
  assert.strictEqual(change.status, 200);
  assert.strictEqual((await c.call('GET', '/me', { token: other })).status, 401);
  assert.strictEqual((await c.call('GET', '/me', { token: current })).status, 200);
  assert.strictEqual((await c.call('POST', '/auth/login', {
    body: { username: 'alice', password: PASSWORD },
  })).status, 401);

  const kinds = (await c.call('GET', '/me/security-events', { token: current })).body.events
    .map((e) => e.kind);
  assert.ok(kinds.includes('password_changed'));
  assert.ok(kinds.includes('password_change_failed'));
  assert.ok(kinds.includes('login_failed'));
});

test('logout-all revokes every session of the account', async (t) => {
  const c = await start();
  t.after(() => c.close());
  const alice = await user(c, 'alice');
  await c.call('POST', '/auth/logout-all', { token: alice.account });
  assert.strictEqual((await c.call('GET', '/me', { token: alice.account })).status, 401);
  assert.strictEqual((await c.call('GET', '/messages', { token: alice.device })).status, 401);
});

test('account deletion requires the password and removes the account data', async (t) => {
  const c = await start();
  t.after(() => c.close());
  const alice = await user(c, 'alice');
  const bob = await user(c, 'bob');
  await c.call('POST', '/messages', {
    token: bob.device,
    body: { recipient_device_id: 'alice-device', envelope: fakeEnvelope('bob-device') },
  });

  assert.strictEqual((await c.call('DELETE', '/me', {
    token: alice.account, body: { password: 'wrong-password-123' },
  })).status, 401);
  assert.strictEqual((await c.call('DELETE', '/me', {
    token: alice.account, body: { password: PASSWORD },
  })).status, 200);

  const db = c.server.db;
  const left = (sql) => db.prepare(sql).get().n;
  assert.strictEqual(left("SELECT COUNT(*) AS n FROM accounts WHERE username = 'alice'"), 0);
  assert.strictEqual(left("SELECT COUNT(*) AS n FROM devices WHERE device_id = 'alice-device'"), 0);
  assert.strictEqual(left("SELECT COUNT(*) AS n FROM messages WHERE recipient_device = 'alice-device'"), 0);
  assert.strictEqual((await c.call('GET', '/users/alice', { token: bob.account })).status, 404);
});

// ----------------------------------------------------------- migration

test('a v1 database upgrades in place without losing data', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'helo-migrate-'));
  const file = path.join(dir, 'v1.db');
  const v1 = new DatabaseSync(file);
  v1.exec(SCHEMA_V1);
  v1.prepare(
    `INSERT INTO accounts (account_id, username, password_hash, password_salt, created_at)
     VALUES ('acc-1', 'legacy', 'h', 's', 1)`
  ).run();
  v1.prepare(
    `INSERT INTO devices (device_id, account_id, identity_json, registered_at)
     VALUES ('legacy-device', 'acc-1', '{}', 1)`
  ).run();
  assert.strictEqual(v1.prepare('PRAGMA user_version').get().user_version, 0);
  v1.close();

  const db = openDatabase(file);
  assert.strictEqual(db.prepare('PRAGMA user_version').get().user_version, SCHEMA_VERSION);
  assert.strictEqual(db.prepare("SELECT username FROM accounts WHERE account_id = 'acc-1'").get().username,
    'legacy');
  assert.ok(db.prepare("SELECT 1 FROM devices WHERE device_id = 'legacy-device'").get());
  assert.ok(db.prepare("SELECT 1 FROM sqlite_master WHERE name = 'pq_prekeys'").get());
  db.close();

  // Re-opening an up-to-date database is a no-op.
  const again = openDatabase(file);
  assert.strictEqual(again.prepare('PRAGMA user_version').get().user_version, SCHEMA_VERSION);
  again.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

test('X-Forwarded-For is honoured only from a loopback proxy, and only when enabled', () => {
  const { clientIp } = require('../src/server');
  const req = (peer, fwd) => ({ socket: { remoteAddress: peer }, headers: fwd ? { 'x-forwarded-for': fwd } : {} });
  // Off by default: the TCP peer, whatever the header says.
  assert.strictEqual(clientIp(req('127.0.0.1', '10.0.0.7'), false), '127.0.0.1');
  // On: a loopback proxy names the client; the LAST entry is the proxy's.
  assert.strictEqual(clientIp(req('127.0.0.1', '10.0.0.7'), true), '10.0.0.7');
  assert.strictEqual(clientIp(req('::1', '1.2.3.4, 10.0.0.7'), true), '10.0.0.7');
  // A remote client can never pick its own bucket.
  assert.strictEqual(clientIp(req('203.0.113.9', '10.0.0.7'), true), '203.0.113.9');
  // Garbage is ignored.
  assert.strictEqual(clientIp(req('127.0.0.1', 'not an ip'), true), '127.0.0.1');
  assert.strictEqual(clientIp(req('127.0.0.1', 'x'.repeat(300)), true), '127.0.0.1');
});
