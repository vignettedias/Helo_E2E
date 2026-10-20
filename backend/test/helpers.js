'use strict';
/** Shared helpers for the relay test suites. */

const { createServer } = require('../src/server');

const PASSWORD = 'correct-horse-battery-staple';

async function start(options = {}) {
  const server = createServer(options);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const base = `http://127.0.0.1:${port}`;

  const call = async (method, path, { body, token, headers: extra, raw } = {}) => {
    const headers = { 'Content-Type': raw ? 'application/octet-stream' : 'application/json', ...extra };
    if (token) headers.Authorization = `Bearer ${token}`;
    const res = await fetch(base + path, {
      method,
      headers,
      body: raw !== undefined ? raw : body === undefined ? undefined : JSON.stringify(body),
    });
    const type = res.headers.get('content-type') || '';
    let json = null;
    let bytes = null;
    if (type.startsWith('application/octet-stream')) {
      bytes = Buffer.from(await res.arrayBuffer());
    } else {
      try { json = await res.json(); } catch { /* empty body */ }
    }
    return { status: res.status, body: json, bytes, headers: res.headers };
  };

  return {
    server, base, call,
    close: () => new Promise((resolve) => {
      server.close(resolve);
      server.closeAllConnections();
    }),
  };
}

function fakeIdentity(seed = 1) {
  return {
    sig_pub: Buffer.alloc(32, seed).toString('base64'),
    dh_pub: Buffer.alloc(32, seed + 1).toString('base64'),
    binding_sig: Buffer.alloc(64, seed + 2).toString('base64'),
  };
}

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

async function registerAndLogin(c, username) {
  await c.call('POST', '/auth/register', { body: { username, password: PASSWORD } });
  const login = await c.call('POST', '/auth/login', { body: { username, password: PASSWORD } });
  return login.body.access_token;
}

async function registerDevice(c, token, deviceId, identity = fakeIdentity()) {
  const res = await c.call('POST', '/devices', { token, body: { device_id: deviceId, identity } });
  return res.body.device_token;
}

/** Account + one device, returning both tokens. */
async function user(c, name) {
  const account = await registerAndLogin(c, name);
  const device = await registerDevice(c, account, `${name}-device`);
  return { account, device, deviceId: `${name}-device` };
}

const SIGNED_PREKEY = {
  key_id: 1,
  public: Buffer.alloc(32, 4).toString('base64'),
  signature: Buffer.alloc(64, 5).toString('base64'),
  created_at: 1700000000,
};

function pqKey(id, fill = 0x11) {
  return {
    key_id: id,
    public: Buffer.alloc(1185, fill).toString('base64'),
    signature: Buffer.alloc(64, fill + 1).toString('base64'),
  };
}

module.exports = {
  PASSWORD, start, fakeIdentity, fakeEnvelope, registerAndLogin, registerDevice, user,
  SIGNED_PREKEY, pqKey,
};
