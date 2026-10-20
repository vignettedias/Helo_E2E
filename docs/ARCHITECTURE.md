# HELO 2.0 Architecture

This document describes the architecture **as found** (§1) and the **target**
architecture for HELO 2.0 (§2 onwards), with the reason for every structural
change. Where the implementation and this document disagree, the
implementation status in `IMPLEMENTATION_ROADMAP.md` is authoritative and this
file is out of date — please fix it.

---

## 1. Architecture as found (2026-10-16)

```
Flutter client ──HTTPS/JSON──► Node relay (zero deps) ──► SQLite
  crypto/  Dart port of the protocol           validates shape/size, stores
  domain/  SessionManager (plaintext boundary) ciphertext, deletes on ack
  data/    RelayClient (ciphertext only)
  ui/      single-column screens
Python reference (normative) + vectors ─ keep the Dart port byte-exact
```

The stack is sound and is **kept**. No framework is replaced. Every change
below extends an existing layer.

## 2. Target layering

```
┌──────────────────────────── Flutter client ────────────────────────────┐
│ ui/            responsive shell (sidebar · chat · info panel), themes  │
│ domain/        Messenger (orchestration), LocalStore (sealed state),   │
│                Directory (username→devices), Groups, Attachments       │
│ protocol/      app payload codec (JSON kinds) + padding                 │
│ crypto/        identity · PQXDH/X3DH · Double Ratchet · AEAD · STREAM   │
│ storage/       CryptoStorage (Keystore / Keychain / browser)           │
│ data/          RelayClient (ciphertext + routing only)                 │
└────────────────────────────────────────────────────────────────────────┘
                    │ HTTPS (TLS at Caddy) — long-poll + JSON
┌──────────────────────────── Node relay ────────────────────────────────┐
│ auth · directory · prekeys (EC + PQ) · message queue · long-poll       │
│ attachments (ciphertext blobs) · blocks · reports · presence · events  │
│ SQLite with versioned migrations                                       │
└────────────────────────────────────────────────────────────────────────┘
```

**The plaintext boundary does not move.** `domain/` is the only layer that
holds plaintext; `data/` and the relay see envelopes, encrypted attachment
blobs, and routing metadata.

## 3. Protocol stack (v2)

```
Account authentication      password → relay tokens        (relay only; never E2EE keys)
Device identity             IK_sig (Ed25519) + IK_dh (X25519), one per device
Session establishment       PQXDH-hybrid: X25519 DH1–DH4 + ML-KEM-768   (default)
                            X3DH classical                               (explicit opt-in only)
Double Ratchet              unchanged (frozen v1 strings)
Padded plaintext            payload ‖ 0x80 ‖ 0x00*   to a size bucket
App payload                 versioned JSON: msg / react / edit / del / rcpt / typing /
                            profile / timer / group
Envelope                    v1 wire format (relay validator unchanged)
```

### 3.1 Hybrid post-quantum session establishment

**Construction:** the structure of Signal's **PQXDH** specification — the
classical X3DH DH outputs and an ML-KEM shared secret are the input keying
material of one HKDF invocation with a scheme-specific info string. It is a
*published, analysed* construction, not an ad-hoc concatenation. Our
instantiation differs from Signal's (separate Ed25519 signing key, ML-KEM-768,
our own encodings); **that instantiation has not been formally analysed.**

```
Bob publishes:  IK_B, SPK_B + sig, OPK_B (optional),
                PQPK_B = PQ one-time prekey (preferred) or PQ last-resort prekey,
                sig_IK_sig("Helo_PQPreKey_v1" ‖ u32(id) ‖ lp(Encode(PQPK_B)))
Encode(PQPK) = u8(0x01 = ML-KEM-768) ‖ ek          (binds the KEM type into the signature)

Alice:  verify identity binding, SPK sig, PQPK sig      — all BEFORE any DH or KEM
        (CT, SS) = ML-KEM-768.Encaps(ek)
        SK = HKDF-SHA256(ikm  = 0xFF×32 ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4] ‖ SS,
                         salt = 0x00×32,
                         info = "Helo_PQXDH_X25519_SHA-256_ML-KEM-768_v1")
        initial header v2 carries pq = {key_id, ct}
Bob:    decapsulate (implicit rejection), derive SK; delete PQOPK if one-time
```

- **Library:** Python reference — `pyca/cryptography` 50 (OpenSSL 4.0.1,
  FIPS 203 ML-KEM). Dart client — `pqcrypto` (pure Dart). The Dart library is
  checked against OpenSSL by vectors: seeded key generation must reproduce the
  OpenSSL public key byte-for-byte and decapsulation must reproduce the
  OpenSSL shared secret.
- **Negotiation & downgrade:** there is no in-band negotiation an attacker can
  edit. The mode is fixed by the bundle (signed PQ prekey present or not) and
  the header version, and is enforced by **policy on both sides**:
  `pq_required` (default) refuses a bundle without a valid PQ prekey and
  refuses a classical initial message. Stripping the PQ fields therefore causes
  a refusal, never a silent classical session. Classical sessions exist only if
  the user explicitly enables "allow classical contacts", and are then labelled
  in the UI. Editing the header mode in flight makes the two sides derive
  different keys, so the first message fails authentication.
- **What it does not give:** the Double Ratchet that follows is classical
  X25519. A quantum adversary recording traffic gains nothing from the initial
  handshake, but post-compromise recovery steps are classical. **There is no
  post-quantum ratchet.** The system is not described as "post-quantum secure".

### 3.2 Padding

Before encryption every app payload is padded ISO/IEC 7816-4 style
(`payload ‖ 0x80 ‖ 0x00…`) up to a bucket: `block-256` by default (also
implemented: `none`, `pow2`, `padme` — compared in `research/`). Unpadding
rejects any input that is not `… 0x80 0x00*`. Because receipts, typing events
and short texts all land in the same 256-byte bucket, the relay cannot tell
them apart by size. This is a measurable reduction of length leakage, **not**
protection against traffic analysis.

### 3.3 App payload (inside the encryption)

```json
{"v":1,"id":"<32 hex>","ts":<ms>,"k":"<kind>","conv":{"t":"d"}|{"t":"g","gid":"…"}, …}
```

| kind | fields | authorization (enforced by the receiving client) |
|---|---|---|
| `msg` | `body`, `reply?`, `att?[]`, `fwd?`, `exp?` | sender must be a conversation member |
| `react` | `target`, `emoji` (`""` removes) | member |
| `edit` | `target`, `body` | sender must be the target's author |
| `del` | `target` | sender must be the target's author |
| `rcpt` | `kind: delivered\|read`, `targets[]` | member |
| `typing` | `on` | member |
| `profile` | `name`, `avatar?` | any peer (applies to that peer only) |
| `timer` | `seconds` | member |
| `group` | `op`, `gid`, `ver`, state snapshot | admins only (except `leave`) |

Sender identity is **never** taken from the payload. It is the account the
relay authenticated for the sending device (`sender_username`), bound on first
contact to that device's identity key, which the session itself authenticates.

## 4. Real-time transport: long-polling

`GET /messages?wait=N` holds the request open until a message is queued for the
device (or N ≤ 30 s elapse). Chosen over WebSocket because:

1. browsers cannot attach an `Authorization` header to `EventSource` or
   `WebSocket`, which would force tokens into URLs (and logs);
2. it needs **no new dependency** on either side — the relay stays at zero npm
   dependencies;
3. it passes unchanged through the existing Caddy configuration.

Typing indicators and receipts are E2EE messages on the same queue, so they are
delivered with the same latency as messages.

## 5. Multi-device

Each device has its own identity and its own pairwise session with every peer
device. Sending to a user encrypts **once per active device** of that user
(fan-out). The client refreshes a peer's device list from the relay directory
on conversation open and periodically. A new device of a contact appears as an
**unverified** device with a visible notice. Sync of one's own sent messages to
one's own other devices is **not implemented** (see roadmap).

## 6. Groups

Pairwise fan-out over the existing sessions — no group key and no new group
cryptography. Group state (`gid`, name, avatar, members, admins, `ver`) is
changed only by **E2EE messages from an admin's authenticated device**, each
carrying a full state snapshot with `ver+1`. Removed
members are simply not encrypted to afterwards; new members receive no history
because they were never encrypted to before. MLS (RFC 9420) was evaluated and
is out of scope (no maintained Dart implementation); limitations — notably that
a malicious admin can equivocate (show different members different states) —
are documented in `SECURITY_MODEL.md`.

## 7. Attachments

```
client: K ← 32 random bytes
        ciphertext = STREAM-AES-256-GCM(K, file)    64 KiB chunks
          nonce_i = 0x00×7 ‖ u32(i) ‖ u8(is_final)   AD = "Helo_Attachment_v1"
        digest = SHA-256(ciphertext)
        POST /attachments  (ciphertext only, recipient device list)
        E2EE msg carries {id, key K, digest, size, mime, name}
relay:  stores ciphertext blob; serves it only to the uploader and listed
        recipient devices; deletes after 30 days
```

STREAM (Hoang, Reyhanitabar, Rogaway, Vizár 2015; as used by `age` and Tink's
streaming AEAD) makes truncation, reordering and chunk removal detectable. K is
fresh per attachment, so a counter nonce never repeats under a key.

## 8. Relay data model (v2 additions, by migration)

| Table | Purpose | Classification |
|---|---|---|
| `pq_prekeys` | signed ML-KEM public prekeys, one-time + last-resort | CRYPTO |
| `attachments` | ciphertext blobs + allowed device list | CIPHERTEXT / METADATA |
| `blocks` | blocker → blocked account | METADATA |
| `reports` | reporter, reported, reason | METADATA |
| `account_settings` | presence visibility | METADATA |
| `security_events` | per-account event log (no secrets) | METADATA |
| `messages.sender_account` | sender, **as authenticated** (not client-supplied) | METADATA |

Migrations are additive (`PRAGMA user_version`); nothing is dropped.

## 9. Changes and their justification

| Change | Why |
|---|---|
| Sending requires a **device** token; relay checks `envelope.sender_device_id` | Fixes audit finding A1 (sender impersonation). |
| Username directory (`GET /users/:name`) | Users cannot reasonably exchange device ids. |
| PQXDH-hybrid default | Research contribution A; protects first messages against harvest-now-decrypt-later. |
| Padding + app payload kinds | Research contribution B; all rich messaging features ride inside E2EE. |
| Long-poll | Real-time delivery without new dependencies (§4). |
| `domain/` split (Messenger, Directory, LocalStore) | `SessionManager` mixed device sessions, history and transport; groups and fan-out need them separate. |
| Verification report + dashboard | Research contribution C: statuses come from executed tests, never hard-coded. |
