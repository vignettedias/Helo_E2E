# Project Audit — Helo → HELO 2.0

**Date:** 2026-10-16 · **Method:** source inspection of every module listed
below plus execution of every existing test suite. README claims were treated
as unverified until confirmed in code.

> This audit was performed *after* a stabilization pass on 2026-10-15 (client
> restart persistence, token renewal, safety-number ordering, crash-before-send
> key reuse, CORS for a browser client). Those fixes are recorded in
> `RESEARCH_METHODOLOGY.md` → "Defects found" (items 5–8). The baseline below is
> the post-stabilization state.

---

## 1. Environment

| Tool | Version found | Used by |
|---|---|---|
| Python | 3.14.6 | reference implementation, tests, scripts |
| pyca/cryptography | 50.0.0 (OpenSSL 4.0.1) | reference primitives; **exposes ML-KEM-768/1024** |
| Node.js | 24.16.0 | relay (`node:sqlite`, `node:http`, `node:crypto`); **exposes ML-KEM** |
| Flutter / Dart | 3.47.0 / 3.13.0 (at `C:\flutter`, not on PATH) | client |
| Docker | 29.6.1 | deployment |
| Android SDK | **absent** | — Android builds cannot be produced here |
| Visual Studio C++ | **incomplete** | — Windows desktop builds cannot be produced here |

## 2. Repository structure (as found)

```
helo/
├── crypto/reference/helo_ref/   Python protocol implementation (normative), 10 modules
├── tests/{unit,adversarial,property,integration}/  pytest suites
├── tests/vectors/helo_vectors.json   deterministic cross-implementation vectors
├── scripts/                     generate_test_vectors, integration_e2e, benchmark, run_demo
├── backend/src/                 relay: server, db, auth, validate, ratelimit, log (zero npm deps)
├── backend/test/relay.test.js   node:test suite
├── mobile/lib/                  Flutter client: crypto/ (Dart port), data/, domain/, storage/, ui/
├── mobile/test/                 vector conformance + SessionManager tests
├── mobile/{android,ios,web,windows}/  generated platform projects
├── docker/                      Dockerfile, docker-compose.yml, Caddyfile
├── .github/workflows/ci.yml     CI: lint, tests, vectors, e2e, secrets, container, flutter
└── *.md                         README, PROTOCOL, ARCHITECTURE, THREAT_MODEL, SECURITY,
                                 SECURITY_CLAIMS, PRIVACY, RESEARCH_METHODOLOGY, RUNNING
```

## 3. Technologies — verified against code

| Item | Present? | Evidence |
|---|---|---|
| Flutter & Dart | ✅ | `mobile/pubspec.yaml`, `mobile/lib/main.dart` |
| Node.js relay | ✅ | `backend/src/server.js` (`node:http`) |
| SQLite | ✅ relay only | `backend/src/db.js` (`node:sqlite` `DatabaseSync`); client does **not** use SQLite |
| Python reference | ✅ | `crypto/reference/helo_ref/` |
| X3DH | ✅ | `x3dh.py` / `x3dh.dart`: DH1–DH4, `F = 0xFF×32`, HKDF info `Helo_X3DH_v1` |
| Double Ratchet | ✅ | `ratchet.py` / `ratchet.dart`: root KDF (HKDF), chain KDF (HMAC 0x01/0x02), skipped keys, `MAX_SKIP` |
| X25519 | ✅ | pyca `X25519PrivateKey`; Dart `package:cryptography` `X25519` |
| Ed25519 | ✅ | separate signing identity key (`IK_sig`) — deliberate deviation from XEdDSA |
| HKDF-SHA-256 | ✅ | `primitives.hkdf` (both) |
| AES-256-GCM | ✅ | `primitives.aes256gcm_*`; nonce **derived** from message key, not transmitted |
| Test vectors | ✅ | `tests/vectors/helo_vectors.json`, reproduced byte-exactly by `generate_test_vectors.py --check` |
| Docker | ✅ | non-root, read-only rootfs, caps dropped, Caddy TLS |
| ML-KEM / PQXDH | ❌ | only a documented seam (`x3dh.KeyEstablishment`); **no PQ code** |
| WebSocket | ❌ | relay has an SSE wake-up endpoint (`/messages/stream`); client polls every 3 s |
| Message padding | ❌ | ciphertext length = plaintext length + 57 bytes exactly |
| Attachments | ❌ | none |
| Groups | ❌ | none |

## 4. Baseline test results (executed 2026-10-16)

| Suite | Command | Result |
|---|---|---|
| Python protocol | `python -m pytest -q` | **99 passed** (47 unit, 29 adversarial, 13 property, 10 integration) |
| Vector reproducibility | `python scripts/generate_test_vectors.py --check` | **OK** (20072 bytes) |
| Relay | `node --test test/relay.test.js` | **25 passed** |
| Cross-stack E2E | `python scripts/integration_e2e.py` | **24/24 checks**, exit 0 |
| Flutter | `flutter test` | **28 passed** |
| Flutter analyze | `flutter analyze` | **no issues** |
| Lint | `ruff check crypto/ tests/ scripts/` | clean |

## 5. Features implemented (verified)

**Relay:** account registration (scrypt), login (uniform failure), access/refresh
tokens (hashed at rest), logout/revocation, device registration & revocation,
signed-prekey and one-time-prekey publication, atomic single-use OTP claim,
ciphertext queue with FIFO order, delete-on-ack, 30-day retention sweep,
token-bucket rate limits, security headers, allowlist logging, opt-in CORS.

**Protocol (reference + Dart port):** identity keys, fingerprints, 60-digit
safety numbers, X3DH (3-DH and 4-DH), Double Ratchet with out-of-order
handling and bounded skipping, atomic decrypt (copy-on-write state), replay
classification, encrypted session-state persistence, state machine with a
terminal revoked state, low-order-point rejection.

**Client:** identity generation and secure storage, registration, prekey
publication and replenishment, 1:1 sessions **addressed by device id**,
encrypted local history, safety-number screen with QR display, verification
status, identity-change and 3-DH-downgrade warnings, diagnostics, reset,
token renewal, restart persistence.

## 6. Partially implemented

| Feature | State |
|---|---|
| Multi-device | An account may register many devices, but a conversation is bound to **one device**; nothing fans out to a user's other devices. |
| Real-time | SSE endpoint exists but is unusable from browsers (EventSource cannot send an `Authorization` header); client polls. |
| Identity verification | Display only; QR cannot be scanned. |
| Account security | Password change, active-session listing and security events do not exist. |

## 7. Defects and vulnerabilities found in this audit

| # | Severity | Finding | Evidence |
|---|---|---|---|
| A1 | **High** | **Relay trusts a client-supplied sender id.** `POST /messages` stores `envelope.sender_device_id` as given, authenticated only by an *account* token. A malicious account can send a prekey message claiming to be `alice-device`; a recipient with no session for that id establishes one bound to the attacker's identity key **under Alice's device id**. Safety numbers would differ, but first contact is TOFU, so this is a practical impersonation path. | `server.js` `POST /messages`; `session_manager.dart` `receive()` keys conversations by relay-reported sender |
| A2 | Medium | Client cannot discover another user's devices; users must exchange opaque device ids out of band. | no lookup endpoint |
| A3 | Medium | `run_demo.py --lan` cannot work: browsers expose WebCrypto (`crypto.subtle`, used by the web key store) only in secure contexts, and `http://<LAN-IP>` is not one. | WebCrypto secure-context rule |
| A4 | Low | Exact plaintext length is visible to the relay (no padding). Documented, not mitigated. | `PRIVACY.md` |
| A5 | Low | Web client stores keys and refresh token in browser storage encrypted under a WebCrypto key held by the same browser — not hardware-backed. Documented in README. | `flutter_secure_storage` web backend |

## 8. Cryptographic mechanisms in detail

See `PROTOCOL.md` (accurate against the code at audit time). Notable verified
properties: domain-separated HKDF info strings; nonce derived from the message
key (structural nonce uniqueness); AEAD associated data binds both identities
and the ratchet header; signatures verified before any DH; ephemeral key not
returned from the handshake; `MAX_SKIP = 1000`, `MAX_SKIPPED_KEYS = 2000`
checked before derivation.

## 9. Existing test coverage

Strong at the protocol layer (unit, adversarial, Hypothesis property tests,
vectors, cross-stack E2E with database inspection). Relay tests cover auth,
prekey single-use, validation, rate limits, headers, CORS. Client tests cover
crypto conformance and SessionManager persistence. **No tests exist** for
anything above 1:1 text messaging, because nothing above it exists.

## 10. Components that must be preserved

- The Python reference as the **normative** protocol definition, and the vector
  mechanism that keeps the Dart port honest.
- All existing domain-separation strings (frozen — see README "A note on the
  protocol name"). New schemes get **new** strings, never edited old ones.
- Relay posture: zero npm dependencies, allowlist logging, delete-on-ack,
  hashed tokens, no plaintext-capable column.
- Every existing test. None may be deleted to make a change pass.

## 11. Gap analysis against the HELO 2.0 feature list

Status at audit time (before HELO 2.0 work). The live status is maintained in
`docs/IMPLEMENTATION_ROADMAP.md`.

| # | Feature | At audit |
|---|---|---|
| 1–3 | Register / login / logout | ✅ implemented |
| 4–5 | Profiles, avatars | ❌ |
| 6 | Username discovery | ❌ (device ids only) |
| 7 | Contacts | ❌ |
| 8 | 1:1 conversations | ⚠️ per device |
| 9 | Real-time | ⚠️ 3 s polling |
| 10 | Offline delivery | ✅ |
| 11 | Encrypted history | ✅ (client) |
| 12 | Sent/delivered/read | ❌ (sent only) |
| 13–14 | Typing, presence | ❌ |
| 15–20 | Reply, react, edit, delete, forward, message search | ❌ |
| 21–24 | Conversation search, pin, archive, mute | ❌ |
| 25–26 | Block, report | ❌ |
| 27 | Disappearing messages | ❌ |
| 28–32 | Attachments, voice | ❌ |
| 33–37 | Groups | ❌ |
| 38 | Devices/sessions | ⚠️ register/revoke API only |
| 39–40 | Verification, security notices | ⚠️ safety numbers + warnings |
| 41–43 | Privacy / notification / secure config settings | ❌ |
| 44 | Responsive UI | ⚠️ single column |
| 45 | Error handling | ⚠️ partial |
