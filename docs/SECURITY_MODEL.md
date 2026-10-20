# HELO 2.0 Security Model

Companion to `THREAT_MODEL.md` (protocol-level threats T1–T12) and
`SECURITY_CLAIMS.md` (claim → test mapping). This document covers the whole
application. Every protection is marked with its **evidence status**:

- **TESTED** — implemented and exercised by a named passing test
- **IMPLEMENTED** — present in code, not (fully) covered by tests
- **PLANNED** — not implemented

Statuses are updated as phases complete; `IMPLEMENTATION_ROADMAP.md` is the
live tracker.

---

## 1. Assets

| Asset | Where it lives | Must never be at |
|---|---|---|
| Message plaintext, attachment plaintext | client memory; sealed local store | relay, logs |
| Identity private keys (IK_sig seed, IK_dh) | client secure storage | relay, logs, backups |
| Prekey private keys (EC + ML-KEM seeds) | client secure storage | relay |
| Ratchet state (root/chain/message keys) | client, sealed | relay |
| Attachment content keys | inside E2EE messages; client store | relay, URLs |
| Account password | user's head; scrypt hash on relay | anywhere in clear |
| Relay bearer tokens | client storage (hashed on relay) | logs, URLs |
| Social graph & timing metadata | relay (unavoidably, in part) | logs beyond retention |

## 2. Trust boundaries

```
[ device A: trusted ] ──TLS──► [ Caddy: untrusted ] ──► [ relay + SQLite: untrusted ] ──► [ device B: trusted ]
```

Everything outside the two endpoints is assumed hostile. The relay is an
**untrusted ciphertext relay**: it can drop, delay, reorder, replay and
substitute anything it stores. It is never described as "zero knowledge".

## 3. Attack surfaces

Relay HTTP API (every route), the envelope parser on the client, the app
payload parser, the padding decoder, attachment upload/download, prekey bundle
parsing, group-state messages, local storage at rest, the browser runtime (web
client), the build/dependency supply chain.

## 4. Security assumptions

1. The audited primitives behave as specified (OpenSSL via pyca; Dart
   `cryptography`; `pqcrypto` for ML-KEM in the Dart client).
2. The OS / browser CSPRNG is sound.
3. Endpoints are not compromised while in use.
4. Users who want authentication of *people* compare safety numbers out of band.
5. The installed client is the genuine client (no client-integrity guarantee).

## 5. Adversaries (Section 22)

| # | Adversary | Can access / attempt | Protections | Evidence | Still possible | Assumes |
|---|---|---|---|---|---|---|
| 1 | Honest-but-curious relay | all stored rows, timing, sizes, routing | E2EE; delete-on-ack; hashed tokens; no plaintext-capable column; padding | E2E DB scan TESTED; padding TESTED and measured (research E1/E3) | social graph, timing, bucketed sizes | client not compromised |
| 2 | Compromised relay | modify/replay/drop/inject envelopes, substitute keys | AEAD + authenticated header; signed prekeys; signatures before DH; replay classification; atomic decrypt | TESTED (adversarial suite) | drop/delay (DoS); first-contact MITM unless safety numbers compared | TOFU caveat |
| 3 | Ciphertext modifier | flip bits in ciphertext/header/attachment | AES-GCM; header in AD; attachment digest + STREAM | message: TESTED; attachments: TESTED (STREAM unit + property tests) | — | — |
| 4 | Replayer | resend any envelope | consumed message keys, skipped-key consumption, superseded-chain tracking, OPK destruction; app-level id dedupe | TESTED (protocol); dedupe TESTED (`a payload delivered twice … is shown once`) | replay into a *new* session when OPKs exhausted (documented) | — |
| 5 | Malicious authenticated user | forge sender id, spam, enumerate users, drain prekeys | sender bound to authenticated device (A1 fix); rate limits; uniform 404s | A1 fix TESTED (relay + end-to-end impersonation attempt) | username existence is discoverable by exact lookup (rate limited) | — |
| 6 | Malicious group member | edit others' messages, change membership, keep reading after removal | author-only edit/delete; admin-only group ops; removed members not encrypted to | TESTED (Dart group tests) | a malicious **admin** can equivocate group state; a member can screenshot | pairwise fan-out |
| 7 | Contact impersonator | present own key under someone's name | safety numbers; identity-change detection; verified state lost on change | TESTED | first contact is TOFU | users verify |
| 8 | Local database reader | read the device's storage | sealed session state + history (AES-GCM under a keystore-held key) | TESTED (persistence); browser: weak | web: key is in the same browser | platform keystore |
| 9 | Compromised client device | everything on the device | none can help; forward secrecy limits *past* exposure | FS TESTED | full plaintext exposure while compromised | — |
| 10 | Network observer | TLS metadata, IPs, timing, sizes | TLS (Caddy); padding | TLS config only; padding measured (E1) | IP, timing, volume | — |
| 11 | Malicious dependency | code execution in relay/client | relay has zero npm deps (CI-enforced); few audited client deps | CI gate | client deps (Flutter packages) are trusted | supply chain |
| 12 | Unauthorized resource access | read others' queues, attachments, devices | per-route authz; device-bound tokens | queues TESTED; attachments TESTED (`attachments are served only to the uploader and listed recipients`) | — | — |

## 6. Guarantees (only those backed by tests are claimed)

See `SECURITY_CLAIMS.md` C1–C14 for the protocol guarantees and C15–C19 for the HELO 2.0 ones
(hybrid establishment, no silent downgrade, attachments, sender binding, receiver-side authorisation),
each with the tests that back it.

## 7. Limitations (stated, not hidden)

- A compromised endpoint exposes plaintext. No ratchet recovers from an
  attacker who keeps code execution.
- Metadata remains visible: who talks to whom, when, how often; IP addresses
  are visible to the relay and the TLS terminator.
- Message timing leaks information; padding hides exact length only.
- Trust-on-first-use cannot detect a first-contact MITM unless safety numbers
  are compared.
- Encrypted backups do not exist; losing a device loses its history by design.
- Disappearing messages cannot prevent screenshots, copies or exports.
- The hybrid handshake protects session establishment against a future quantum
  adversary; the Double Ratchet steps after it remain classical.
- Client-side security depends on the integrity of the installed client.
- The web client's key storage is not hardware-backed.
- The relay sees which account owns which device and can therefore always
  identify the sender of a message (no sealed sender — see research).

## 8. Residual risks

| Risk | Rationale for accepting |
|---|---|
| Username enumeration by exact lookup | needed for discovery; rate limited, no prefix search |
| Relay-asserted username→device binding | same model as phone-number-based messengers; safety numbers detect substitution |
| No independent audit | stated in README; not mitigable by the authors |
