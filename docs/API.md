# Relay HTTP API (v2)

The relay is `backend/src/server.js`, with routes in `backend/src/routes/*.js`. It stores and forwards ciphertext and never sees plaintext or private keys.
It speaks plain HTTP by design, so put TLS in front of it in any real deployment.
All bodies are JSON. Errors look like `{"error": "<code>"}` with a 4xx/5xx status. A 429 response carries `Retry-After`.

## Authentication

| Token | Obtained from | Accepted by |
|---|---|---|
| **account token** (access) | `POST /auth/login`, `POST /auth/refresh` | routes marked *account* |
| **device token** | `POST /devices` (registering a device under the account) | routes marked *account* and routes marked *device* |

Send either as `Authorization: Bearer <token>`. Tokens are stored hashed (SHA-256), so a database dump does not yield usable tokens.
*Device* routes reject an account token with `403 device_token_required`. Sending and receiving are bound to the authenticated device: the relay checks `envelope.sender_device_id` against the token (audit finding A1) and sets `sender_username` itself.
A revoked device gets `401 device_revoked`.

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/health` | none | liveness only (`status`, `service`); no user or device counts |
| POST | `/auth/register` | none | create an account (`username`, `password`; the password is hashed with scrypt on the server) |
| POST | `/auth/login` | none | returns `access_token` and `refresh_token` |
| POST | `/auth/refresh` | refresh token in body | new access token |
| POST | `/auth/logout` | account | revoke this token |
| POST | `/auth/logout-all` | account | revoke every token of the account |
| POST | `/auth/password` | account | change password (revokes the other sessions) |
| POST | `/devices` | account | register a device: `device_id` and public `identity`; returns `device_token`. Re-registering an existing id with a *different* identity is refused |
| GET | `/devices` | account | list this account's devices |
| POST | `/devices/revoke` | account | revoke a device |
| POST | `/prekeys` | account | publish a signed prekey, one-time prekeys, a PQ last-resort key and PQ one-time keys; signatures are validated |
| GET | `/prekeys/:deviceId` | account | fetch a bundle; consumes one EC one-time prekey and one PQ one-time key when available, otherwise falls back to the PQ last-resort key |
| GET | `/users/:username` | account | directory: the user's active devices and their public identities (exact username only, no search) |
| GET | `/presence/:username` | account | online / last seen, subject to both sides' privacy settings and blocks |
| POST | `/messages` | device | queue one envelope for `recipient_device_id` |
| POST | `/messages/batch` | device | queue many envelopes; each item succeeds or fails on its own |
| GET | `/messages?wait=N` | device | fetch up to 100 queued envelopes; `wait` (0–30 s) long-polls until something arrives |
| GET | `/messages/stream` | device | Server-Sent Events wake-up signal only (no content) |
| POST | `/delivery/ack` | device | acknowledge `message_ids`; acknowledged messages are deleted |
| POST | `/attachments` | device | upload an encrypted blob (STREAM AES-256-GCM, client-side) for a list of recipient devices |
| GET | `/attachments/:id` | device | download, only by a listed recipient or the uploader |
| DELETE | `/attachments/:id` | device | uploader deletes |
| GET | `/me` | account | account summary |
| GET/PUT | `/me/settings` | account | the privacy settings the relay must enforce (`show_online`, `show_last_seen`) |
| GET | `/me/security-events` | account | last 50 security events (logins, devices, password changes) |
| DELETE | `/me` | account | delete the account and everything the relay holds for it |
| GET | `/me/blocks` | account | list blocked users |
| POST | `/me/blocks` | account | block a user (the relay then refuses their messages to you) |
| DELETE | `/me/blocks/:username` | account | unblock |
| POST | `/reports` | account | report an account (fixed reason vocabulary plus an optional note; never message content) |

Read receipts, typing indicators, reactions, edits, deletes, profiles, disappearing-message timers and group changes are **not** relay endpoints.
They are kinds of end-to-end-encrypted `AppPayload` carried inside ordinary envelopes (see `mobile/lib/protocol/payload.dart`).

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8443` | listen port |
| `HOST` | `0.0.0.0` | bind address |
| `DB_PATH` | `./data/helo.db` | SQLite file (`node:sqlite`; migrations via `PRAGMA user_version`) |
| `CORS_ORIGINS` | empty (CORS off) | comma-separated exact origins allowed to call the relay from a browser |
| `TRUST_PROXY_LOOPBACK` | `0` | `1` = for requests arriving FROM loopback only, take the client address for rate limiting from the last `X-Forwarded-For` entry (set by a reverse proxy on the same machine, e.g. `run_demo.py --lan`). Requests from any other address always use the TCP peer. |
| `MAX_ATTACHMENT_BYTES` | 26214400 (25 MiB) | upper bound for one encrypted attachment |

See `.env.example`.
