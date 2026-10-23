'use strict';
/**
 * The demo attack switch (src/routes/demo.js).
 *
 * Two things matter here. First, that it is genuinely absent unless the
 * process was started with DEMO_ATTACKS=1 — a relay that could be told to
 * corrupt traffic by anyone who found the endpoint would be a vulnerability,
 * not a demo. Second, that when it IS on, the relay really does misbehave, so
 * the client-side refusals shown to an audience are refusals of real attacks.
 */

const test = require('node:test');
const assert = require('node:assert');

const {
  start, user, fakeEnvelope, fakeIdentity, registerAndLogin, registerDevice, SIGNED_PREKEY, pqKey,
} = require('./helpers');

async function armed(c, token, mode) {
  const res = await c.call('POST', '/demo/attack', { body: { mode }, token });
  assert.strictEqual(res.status, 200, JSON.stringify(res.body));
  return res.body;
}

async function publishPrekeys(c, u) {
  await c.call('POST', '/prekeys', {
    token: u.account,
    body: {
      device_id: u.deviceId,
      signed_prekey: SIGNED_PREKEY,
      one_time_prekeys: [{ key_id: 1, public: Buffer.alloc(32, 6).toString('base64') }],
      pq_last_resort: pqKey(1),
    },
  });
}

test('without DEMO_ATTACKS the switch does not exist at all', async (t) => {
  const c = await start();
  t.after(() => c.close());
  const alice = await user(c, 'alice');

  for (const [method, body] of [['GET', undefined], ['POST', { mode: 'tamper' }]]) {
    const res = await c.call(method, '/demo/attack', { body, token: alice.account });
    assert.strictEqual(res.status, 404, `${method} /demo/attack must not exist`);
    assert.strictEqual(res.body.error, 'not_found');
  }

  // And traffic is untouched: the bytes out are the bytes in.
  const bob = await user(c, 'bob');
  const envelope = fakeEnvelope('alice-device');
  await c.call('POST', '/messages', {
    token: alice.device,
    body: { recipient_device_id: bob.deviceId, envelope },
  });
  const got = await c.call('GET', '/messages', { token: bob.device });
  assert.strictEqual(got.body.messages.length, 1);
  assert.deepStrictEqual(got.body.messages[0].envelope, envelope);
});

test('arming requires authentication and a known mode', async (t) => {
  const c = await start({ demoAttacks: true });
  t.after(() => c.close());
  const alice = await user(c, 'alice');

  const anonymous = await c.call('POST', '/demo/attack', { body: { mode: 'tamper' } });
  assert.strictEqual(anonymous.status, 401);

  const nonsense = await c.call('POST', '/demo/attack',
    { body: { mode: 'delete_everything' }, token: alice.account });
  assert.strictEqual(nonsense.status, 400);
  assert.strictEqual(nonsense.body.field, 'mode');

  const state = await c.call('GET', '/demo/attack', { token: alice.account });
  assert.strictEqual(state.body.mode, 'none', 'an invalid mode must not have been applied');
  assert.ok(state.body.attacks.tamper.caught_by.includes('AuthenticationError'));
});

test('tamper flips a ciphertext bit, and only the delivered copy', async (t) => {
  const c = await start({ demoAttacks: true });
  t.after(() => c.close());
  const alice = await user(c, 'alice');
  const bob = await user(c, 'bob');
  const envelope = fakeEnvelope('alice-device');
  await c.call('POST', '/messages', {
    token: alice.device,
    body: { recipient_device_id: bob.deviceId, envelope },
  });

  await armed(c, alice.account, 'tamper');
  const attacked = await c.call('GET', '/messages', { token: bob.device });
  const served = attacked.body.messages[0].envelope;
  assert.notStrictEqual(served.ciphertext, envelope.ciphertext, 'ciphertext must have changed');
  assert.strictEqual(served.header, envelope.header, 'only the ciphertext is touched');

  const a = Buffer.from(envelope.ciphertext, 'base64');
  const b = Buffer.from(served.ciphertext, 'base64');
  assert.strictEqual(a.length, b.length);
  let differing = 0;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) differing++;
  assert.strictEqual(differing, 1, 'exactly one byte differs (one flipped bit)');

  // Disarming serves the stored bytes again: the row itself was never changed.
  await armed(c, alice.account, 'none');
  const honest = await c.call('GET', '/messages', { token: bob.device });
  assert.deepStrictEqual(honest.body.messages[0].envelope, envelope);
});

test('replay delivers every queued message twice', async (t) => {
  const c = await start({ demoAttacks: true });
  t.after(() => c.close());
  const alice = await user(c, 'alice');
  const bob = await user(c, 'bob');
  await c.call('POST', '/messages', {
    token: alice.device,
    body: { recipient_device_id: bob.deviceId, envelope: fakeEnvelope('alice-device') },
  });

  await armed(c, alice.account, 'replay');
  const got = await c.call('GET', '/messages', { token: bob.device });
  assert.strictEqual(got.body.messages.length, 2);
  assert.deepStrictEqual(got.body.messages[0], got.body.messages[1]);
});

test('strip_pq serves a bundle with no ML-KEM key', async (t) => {
  const c = await start({ demoAttacks: true });
  t.after(() => c.close());
  const alice = await user(c, 'alice');
  const bob = await user(c, 'bob');
  await publishPrekeys(c, bob);

  const honest = await c.call('GET', `/prekeys/${bob.deviceId}`, { token: alice.account });
  assert.ok(honest.body.pq_prekey, 'bob really did publish one');

  await armed(c, alice.account, 'strip_pq');
  const attacked = await c.call('GET', `/prekeys/${bob.deviceId}`, { token: alice.account });
  assert.strictEqual(attacked.status, 200);
  assert.strictEqual(attacked.body.pq_prekey, null, 'the relay hides it rather than erroring');
  assert.ok(attacked.body.signed_prekey, 'the classical half is still offered — that is the bait');
});

test('substitute_identity serves another account\'s key for a looked-up device', async (t) => {
  const c = await start({ demoAttacks: true });
  t.after(() => c.close());
  const alice = await user(c, 'alice');
  // A distinct identity, so the swap is visible (the helper's default is shared).
  const bobAccount = await registerAndLogin(c, 'bob');
  await registerDevice(c, bobAccount, 'bob-device', fakeIdentity(40));

  const honest = await c.call('GET', '/users/alice', { token: alice.account });
  const real = honest.body.devices[0].identity;

  await armed(c, alice.account, 'substitute_identity');
  const attacked = await c.call('GET', '/users/alice', { token: alice.account });
  assert.notDeepStrictEqual(attacked.body.devices[0].identity, real);
  assert.strictEqual(attacked.body.devices[0].device_id, 'alice-device',
    'the device id is unchanged: only the key under it was swapped');
});
