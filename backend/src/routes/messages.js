'use strict';
/**
 * The ciphertext queue.
 *
 * The relay's entire relationship with a message: check who is sending it,
 * validate its shape and size, store the bytes, wake the recipient, hand the
 * bytes over, delete them on acknowledgement.
 */

const { randomUUID } = require('node:crypto');
const log = require('../log');
const { HttpError, readJson } = require('../http');
const { ValidationError, validateEnvelope, requireString, ID } = require('../validate');

const MESSAGE_FETCH_LIMIT = 100;
const MAX_BATCH = 100;
const MAX_BATCH_BODY = 1024 * 1024;
const MAX_WAIT_SECONDS = 30;

module.exports = function messageRoutes(app) {
  const { db } = app;

  /**
   * Queue one envelope from an authenticated device.
   *
   * The sender is the device the TOKEN belongs to. `envelope.sender_device_id`
   * must name that same device: the recipient's client uses it to pick a
   * session, so letting a request body choose it would let any account
   * masquerade as any device id on first contact (audit finding A1).
   */
  function enqueue(session, sender, recipientId, envelope) {
    const recipient = requireString({ r: recipientId }, 'r', { max: 64, pattern: ID });
    const { serialized, sizeBytes } = validateEnvelope(envelope);
    if (envelope.sender_device_id !== session.deviceId) {
      throw new HttpError(403, 'sender_mismatch');
    }

    const device = db.prepare('SELECT account_id, revoked_at FROM devices WHERE device_id = ?')
      .get(recipient);
    if (!device) throw new HttpError(404, 'recipient_not_found');
    if (device.revoked_at !== null) throw new HttpError(410, 'recipient_revoked');

    const messageId = randomUUID();
    // Blocked: answer exactly as for a delivered message and store nothing,
    // so the sender cannot tell they have been blocked.
    if (app.isBlocked(device.account_id, sender.account_id)) {
      log.info('message_dropped', { outcome: 'blocked' });
      return { message_id: messageId, queued_at: app.now() };
    }

    db.prepare(
      `INSERT INTO messages
         (message_id, recipient_device, sender_device, envelope_json, size_bytes, queued_at)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).run(messageId, recipient, session.deviceId, serialized, sizeBytes, app.now());
    app.notify(recipient);
    log.info('message_queued', { recipient_hash: log.hashId(recipient), size_bytes: sizeBytes });
    return { message_id: messageId, queued_at: app.now() };
  }

  function sender(session) {
    const s = app.accountOfDevice(session.deviceId);
    if (!s) throw new HttpError(401, 'invalid_token');
    return s;
  }

  function fetchQueue(deviceId) {
    return db.prepare(
      `SELECT m.message_id, m.sender_device, m.envelope_json, m.queued_at, a.username
       FROM messages m
       LEFT JOIN devices d ON d.device_id = m.sender_device
       LEFT JOIN accounts a ON a.account_id = d.account_id
       WHERE m.recipient_device = ? AND m.acked_at IS NULL
       ORDER BY m.seq LIMIT ?`
    ).all(deviceId, MESSAGE_FETCH_LIMIT);
  }

  return {
    'POST /messages': async (req) => {
      const session = app.requireDevice(req);
      app.rateLimit('messages:send', session.accountId);
      const body = await readJson(req);
      const result = enqueue(session, sender(session), body.recipient_device_id, body.envelope);
      return { status: 202, body: result };
    },

    /**
     * Fan-out: one request carrying one envelope per recipient device. Each
     * item succeeds or fails on its own; a bad item never rejects the others,
     * because the client has already advanced its ratchet for every one.
     */
    'POST /messages/batch': async (req) => {
      const session = app.requireDevice(req);
      const body = await readJson(req, MAX_BATCH_BODY);
      if (!Array.isArray(body.messages) || body.messages.length === 0
          || body.messages.length > MAX_BATCH) {
        throw new ValidationError(`messages must be an array of 1-${MAX_BATCH} items`, 'messages');
      }
      const from = sender(session);
      const results = body.messages.map((item) => {
        const valid = item !== null && typeof item === 'object';
        const recipient = valid ? item.recipient_device_id : undefined;
        try {
          app.rateLimit('messages:send', session.accountId);
          return { recipient_device_id: recipient, status: 202,
            ...enqueue(session, from, recipient, valid ? item.envelope : undefined) };
        } catch (err) {
          if (err instanceof ValidationError) {
            return { recipient_device_id: recipient, status: 400, error: 'validation_failed', field: err.field };
          }
          if (err instanceof HttpError) {
            return { recipient_device_id: recipient, status: err.status, error: err.code };
          }
          throw err;
        }
      });
      return { status: 200, body: { results } };
    },

    /**
     * Fetch this device's queue. With `?wait=N` (N <= 30) the request is held
     * open until a message arrives or N seconds pass: long-polling, which gives
     * real-time delivery with no extra dependency and no token in a URL.
     *
     * `sender_username` is asserted by the RELAY from the authenticated sender
     * device -- never taken from the envelope.
     */
    'GET /messages': async (req, ctx) => {
      const session = app.requireDevice(req);
      app.rateLimit('messages:fetch', session.deviceId);
      const wait = Math.min(MAX_WAIT_SECONDS, Math.max(0, Number(ctx.url.searchParams.get('wait')) || 0));

      let rows = fetchQueue(session.deviceId);
      if (rows.length === 0 && wait > 0) {
        await app.waitForMessage(session.deviceId, wait * 1000, ctx.res);
        if (ctx.res.destroyed) return { status: 499, body: {} };
        rows = fetchQueue(session.deviceId);
      }

      if (rows.length > 0) {
        const mark = db.prepare(
          'UPDATE messages SET delivered_at = COALESCE(delivered_at, ?) WHERE message_id = ?'
        );
        for (const row of rows) mark.run(app.now(), row.message_id);
      }

      return {
        status: 200,
        body: {
          messages: rows.map((r) => ({
            message_id: r.message_id,
            sender_device_id: r.sender_device,
            sender_username: r.username || null,
            queued_at: r.queued_at,
            envelope: JSON.parse(r.envelope_json),
          })),
        },
      };
    },

    'POST /delivery/ack': async (req) => {
      const session = app.requireDevice(req);
      const body = await readJson(req);
      if (!Array.isArray(body.message_ids) || body.message_ids.length > 500) {
        throw new ValidationError('message_ids must be an array of at most 500 ids');
      }
      // Acked messages are DELETED, not flagged. A delivered ciphertext has no
      // further purpose on the relay, and retaining it only enlarges what a
      // future database compromise yields.
      const del = db.prepare('DELETE FROM messages WHERE message_id = ? AND recipient_device = ?');
      let removed = 0;
      for (const id of body.message_ids) {
        if (typeof id === 'string') removed += del.run(id, session.deviceId).changes;
      }
      return { status: 200, body: { acknowledged: removed } };
    },
  };
};
