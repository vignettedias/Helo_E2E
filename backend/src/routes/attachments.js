'use strict';
/**
 * Encrypted attachment blobs.
 *
 * The relay receives ciphertext produced on the sender's device under a fresh
 * random key. That key travels only inside an end-to-end encrypted message, so
 * the relay stores bytes it cannot read. It still enforces WHO may fetch them:
 * the uploader and the recipient devices named at upload time. An unguessable
 * id is defence in depth, not the access control.
 */

const { randomBytes } = require('node:crypto');
const log = require('../log');
const { HttpError, readRaw } = require('../http');
const { ValidationError, ID } = require('../validate');

const ATTACHMENT_ID = /^[a-f0-9]{32}$/;
const MAX_RECIPIENTS = 256;
const DEFAULT_MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024;

module.exports = function attachmentRoutes(app, options = {}) {
  const { db } = app;
  const maxBytes = options.maxAttachmentBytes || DEFAULT_MAX_ATTACHMENT_BYTES;

  function parseRecipients(header) {
    const ids = String(header || '').split(',').map((s) => s.trim()).filter(Boolean);
    if (ids.length === 0 || ids.length > MAX_RECIPIENTS) {
      throw new ValidationError(
        `x-helo-recipients must list 1-${MAX_RECIPIENTS} device ids`, 'x-helo-recipients');
    }
    for (const id of ids) {
      if (!ID.test(id)) throw new ValidationError('invalid recipient device id', 'x-helo-recipients');
    }
    return [...new Set(ids)];
  }

  function requireId(ctx) {
    const id = ctx.params.id;
    if (!ATTACHMENT_ID.test(id)) throw new HttpError(404, 'attachment_not_found');
    return id;
  }

  /** Authorized readers: the uploader and the listed recipients. Else 404. */
  function authorizedRow(id, deviceId) {
    const row = db.prepare(
      'SELECT attachment_id, uploader_device, data, size_bytes FROM attachments WHERE attachment_id = ?'
    ).get(id);
    if (!row) return null;
    if (row.uploader_device === deviceId) return row;
    const listed = db.prepare(
      'SELECT 1 FROM attachment_recipients WHERE attachment_id = ? AND device_id = ?'
    ).get(id, deviceId);
    return listed ? row : null;
  }

  return {
    'POST /attachments': async (req) => {
      const session = app.requireDevice(req);
      app.rateLimit('attachments:upload', session.deviceId);
      const contentType = String(req.headers['content-type'] || '').split(';')[0].trim();
      if (contentType !== 'application/octet-stream') {
        throw new HttpError(415, 'unsupported_media_type');
      }
      const recipients = parseRecipients(req.headers['x-helo-recipients']);
      const data = await readRaw(req, maxBytes);
      if (data.length === 0) throw new ValidationError('empty attachment', 'body');

      const id = randomBytes(16).toString('hex');
      db.exec('BEGIN');
      try {
        db.prepare(
          `INSERT INTO attachments (attachment_id, uploader_device, size_bytes, data, created_at)
           VALUES (?, ?, ?, ?, ?)`
        ).run(id, session.deviceId, data.length, data, app.now());
        const add = db.prepare(
          'INSERT INTO attachment_recipients (attachment_id, device_id) VALUES (?, ?)'
        );
        for (const r of recipients) add.run(id, r);
        db.exec('COMMIT');
      } catch (err) {
        db.exec('ROLLBACK');
        throw err;
      }
      log.info('attachment_stored', { size_bytes: data.length, message_count: recipients.length });
      return { status: 201, body: { attachment_id: id, size_bytes: data.length } };
    },

    'GET /attachments/:id': async (req, ctx) => {
      const session = app.requireDevice(req);
      app.rateLimit('attachments:fetch', session.deviceId);
      const row = authorizedRow(requireId(ctx), session.deviceId);
      // Unauthorized and nonexistent are indistinguishable.
      if (!row) throw new HttpError(404, 'attachment_not_found');
      return { status: 200, raw: Buffer.from(row.data), contentType: 'application/octet-stream' };
    },

    'DELETE /attachments/:id': async (req, ctx) => {
      const session = app.requireDevice(req);
      const id = requireId(ctx);
      const n = db.prepare(
        'DELETE FROM attachments WHERE attachment_id = ? AND uploader_device = ?'
      ).run(id, session.deviceId).changes;
      if (n === 0) throw new HttpError(404, 'attachment_not_found');
      return { status: 200, body: { deleted: true } };
    },
  };
};

module.exports.DEFAULT_MAX_ATTACHMENT_BYTES = DEFAULT_MAX_ATTACHMENT_BYTES;
