# Security Claims and Evidence

Every security property Helo claims is listed here and mapped to:

**Claim → Mechanism → Test → Evidence → Limitation**

The rule for this document: *if a property is not backed by a named, passing
test, it is not claimed.* Properties that are architecturally intended but not
yet demonstrated appear in [§3 Not Yet Claimed](#3-not-yet-claimed), not in the
claims table.

Current status (run of 2026-10-16, `python scripts/verify.py`): **405/405 tests passing across 10 suites**.
- Python reference: 144 unit, 49 adversarial, 18 property-based and 23 integration tests, plus the vector check.
- 45 relay tests.
- 29 end-to-end checks against the real relay and its database.
- 94 Dart tests, including Messenger and chat-screen tests against the real relay.

The per-test results are in `reports/verification.json`. That file is the evidence for every "Test" row below.

```
Reproduce:  python scripts/verify.py
Python:     python -m pytest -q
Vectors:    python scripts/generate_test_vectors.py --check
```

---

## 1. Cryptographic Claims

### C1 — Confidentiality against the relay

| | |
|---|---|
| **Claim** | The relay never receives message plaintext or any key capable of producing it. |
| **Mechanism** | Message keys are derived on-device from a Double Ratchet chain seeded by X3DH. Every private half (identity DH, signed prekey, one-time prekey, ratchet key) stays on the device. The relay stores only the envelope defined in `crypto/reference/helo_ref/message.py`. |
| **Test** | `test_relay_database_contains_no_plaintext`, `test_relay_cannot_derive_the_session_key_from_stored_material` |
| **Evidence** | A simulated full database dump is searched for the plaintext, for its base64 encoding, and for every private key. All absent. |
| **Limitation** | This is confidentiality of **content only**. The relay learns substantial metadata — see [C11](#c11--metadata-exposure-is-bounded-and-documented). It is not "zero knowledge". |

### C2 — Integrity and authentication of message content

| | |
|---|---|
| **Claim** | Any modification to ciphertext causes decryption to fail. Plaintext is never released on authentication failure. |
| **Mechanism** | AES-256-GCM. The tag is verified before any plaintext is returned. |
| **Test** | `test_bitflip_in_ciphertext_fails_authentication`, `test_bitflip_in_authentication_tag_fails`, `test_truncated_ciphertext_is_rejected`, `test_any_ciphertext_mutation_fails_authentication` (property-based) |
| **Evidence** | The property-based test flips **every bit position** in the ciphertext including the tag, via modulo indexing, across 60 generated plaintexts. All raise `AuthenticationError`. |
| **Limitation** | Integrity is per-message. Message *deletion* and *reordering* by the relay are detectable by the recipient (gaps in counters) but not prevented. |

### C3 — Authentication of protocol metadata

| | |
|---|---|
| **Claim** | The ratchet header is not encrypted but *is* authenticated; modifying it causes decryption to fail. |
| **Mechanism** | AEAD associated data is `session_AD ‖ header_bytes`. `session_AD` binds both identity public keys; `header_bytes` binds the ratchet public key and both counters. |
| **Test** | `test_modified_message_number_in_header_fails`, `test_modified_ratchet_public_key_in_header_fails`, `test_any_header_counter_mutation_fails` (property-based), `test_aead_binds_associated_data` |
| **Evidence** | Counter mutations across a generated range of 1–500 all fail closed. |
| **Limitation** | The header is **readable** by the relay by necessity — the recipient needs it to select a chain. It reveals per-session message counts and ratchet cadence. |

### C4 — Forward secrecy

| | |
|---|---|
| **Claim** | Compromise of complete session state at time *T* does not reveal messages already **consumed** before *T*. |
| **Mechanism** | Chain keys advance by one-way HMAC-SHA256. Message keys are derived, used once, and never stored after successful decryption. |
| **Test** | `test_forward_secrecy_historical_messages_survive_state_compromise`, `test_forward_secrecy_holds_across_multiple_ratchet_generations` |
| **Evidence** | The test clones the victim's **entire** ratchet state (root key, both chain keys, ratchet private key, skipped-key store) — a strictly stronger attacker than real memory scraping — and then fails to decrypt any archived ciphertext across four ratchet generations. |
| **Limitation** | **Two documented exceptions, both asserted by tests rather than hidden:** (a) messages sent but **not yet processed** by the recipient remain decryptable from compromised state — `test_forward_secrecy_does_not_protect_messages_still_in_flight`; (b) **skipped message keys** retained for out-of-order delivery are decryptable until consumed — `test_skipped_message_keys_are_a_documented_forward_secrecy_exception`. Exception (b) is the direct cost of out-of-order support and is why `MAX_SKIPPED_KEYS` is bounded. |

### C5 — Post-compromise security (break-in recovery)

| | |
|---|---|
| **Claim** | After a temporary compromise, security recovers once both parties complete a DH ratchet with entropy the attacker does not hold. |
| **Mechanism** | The DH ratchet mixes fresh X25519 output into the root key via HKDF, with the current root key as salt. |
| **Test** | `test_break_in_recovery_after_bidirectional_ratchet`, `test_attacker_cannot_impersonate_after_recovery` |
| **Evidence** | The test first **confirms the attacker can read traffic** immediately post-compromise (so the later failure is meaningful, not vacuous), then performs a healing round trip, then shows three subsequent messages are unreadable to the stolen state — while the legitimate recipient reads all three. The attacker also cannot forge messages after healing. |
| **Limitation** | **Recovery is not automatic.** It requires the compromised party to actually send, generating a new ratchet key pair. If they only receive, exposure continues indefinitely — asserted by `test_no_recovery_without_fresh_entropy_from_the_compromised_side`. This also assumes the attacker is **passive after the snapshot**; an attacker retaining code execution on the device is not recoverable from by any ratchet. |

### C6 — Replay resistance

| | |
|---|---|
| **Claim** | A ciphertext accepted once is rejected on every subsequent delivery. |
| **Mechanism** | Three independent layers: (1) message keys are destroyed on use; (2) skipped keys are removed from the store on consumption; (3) superseded ratchet keys and consumed counters are tracked and classified as `ReplayError`. For session-initiating messages, the one-time prekey is destroyed on use. |
| **Test** | `test_replayed_message_is_rejected`, `test_replay_of_out_of_order_message_is_rejected`, `test_replay_across_a_ratchet_step_is_rejected`, `test_initial_prekey_message_cannot_be_replayed_into_a_new_session`, `test_replaying_any_delivered_message_is_rejected` (property-based), `test_no_message_is_ever_delivered_twice` (property-based) |
| **Evidence** | The property test offers every message in a conversation **exactly twice** and asserts the delivered count equals the sent count. |
| **Limitation** | If Bob's one-time prekeys are exhausted, an initial message could in principle be replayed into a **new** session established on the signed prekey alone. Mitigation is server-side (bundle rate limiting) plus prompt signed-prekey rotation. |

### C7 — Out-of-order and offline delivery

| | |
|---|---|
| **Claim** | Messages arriving in any order decrypt correctly; sessions establish while the recipient is offline. |
| **Mechanism** | Skipped message keys are derived forward and stored keyed by `(ratchet_pubkey, counter)`. X3DH requires no recipient participation. |
| **Test** | `test_out_of_order_within_one_chain`, `test_out_of_order_across_a_dh_ratchet`, `test_any_delivery_permutation_eventually_decrypts` (property-based), `test_complete_alice_bob_conversation` |
| **Evidence** | The property test generates **arbitrary permutations** of up to 15 messages — not just the usual 1,3,2,4 case — and asserts every message decrypts. Out-of-order delivery is also verified *across a DH ratchet boundary*, where stragglers from a superseded chain must still decrypt. |
| **Limitation** | Bounded by `MAX_SKIP` (1000 per chain) and `MAX_SKIPPED_KEYS` (2000 per session). Beyond these, messages are unrecoverable by design — see [C8](#c8--bounded-resource-consumption). |

### C8 — Bounded resource consumption

| | |
|---|---|
| **Claim** | An attacker cannot force unbounded key derivation or unbounded memory growth. |
| **Mechanism** | `MAX_SKIP` caps derivations per chain; `MAX_SKIPPED_KEYS` caps total retained keys. Both are checked *before* derivation. Ciphertext size is capped at parse time, before any crypto runs. |
| **Test** | `test_absurd_message_number_is_rejected_not_computed`, `test_skip_limit_is_enforced_exactly`, `test_oversized_ciphertext_is_rejected_before_crypto` |
| **Evidence** | A header claiming `n = 4,000,000,000` raises `TooManySkippedMessagesError` without performing the derivations. |
| **Limitation** | A sustained attacker can still force *bounded* work per message. Rate limiting at the relay is a required complementary control. |

### C9 — Availability under active attack

| | |
|---|---|
| **Claim** | A hostile message cannot desynchronise or permanently break a live session. |
| **Mechanism** | `ratchet.decrypt()` operates on a deep copy and commits only on success. |
| **Test** | `test_tampered_message_does_not_desynchronise_the_session` |
| **Evidence** | After a rejected tampered ciphertext, the genuine message still decrypts and the conversation continues normally. |
| **Limitation** | Does not prevent the relay from **dropping** messages entirely; that is unpreventable by an untrusted relay and is a denial-of-service, not a confidentiality failure. |

### C10 — Peer identity verification

| | |
|---|---|
| **Claim** | Key substitution by the relay is cryptographically detectable, and identity changes on an established session are flagged. |
| **Mechanism** | Signed prekeys carry an Ed25519 signature over `(key_id ‖ public)`. The identity binding signature ties `IK_sig` to `IK_dh`. Safety numbers are order-independent 60-digit values derived from both fingerprints. |
| **Test** | `test_forged_signed_prekey_signature_is_rejected`, `test_substituted_identity_key_is_rejected`, `test_full_mitm_produces_a_different_safety_number`, `test_identity_change_on_established_session_is_flagged`, `test_verified_session_that_changes_identity_loses_verified_status` |
| **Evidence** | Identity substitution on a live session raises `IdentityChangedError`, sets status to `IDENTITY_CHANGED`, and **cannot be cleared** by marking the peer verified. |
| **Limitation** | **This is the most important limitation in this document.** Cryptography authenticates *keys*, not *people*. A first-contact MITM is only detected if users **actually compare safety numbers out of band**. Helo's UI surfaces the state; it cannot force the comparison. Trust On First Use is the default and is a real exposure. |

### C11 — Metadata exposure is bounded and documented

| | |
|---|---|
| **Claim** | The set of metadata visible to the relay is explicitly enumerated, not minimised by assertion. |
| **Mechanism** | Field-by-field data classification in `message.py`. |
| **Evidence (measured)** | Ciphertext expansion is a constant 57 bytes, so ciphertext length reveals the encrypted length exactly. Helo/2 pads before encryption (block-256 by default), so that length is a bucket rather than the message length. **E1** (`research/RESULTS.md`): on the synthetic short-message distribution, block-256 cuts length leakage from 7.6 to 0.33 bits per message. **E3**: reading the relay database recovers the full who-talks-to-whom graph, with times, while messages are queued. Delivered messages are deleted on acknowledgement. |
| **The relay CAN observe** | Sender and recipient account/device identifiers; session identifiers linking traffic; message timing and frequency; **padded** length; ratchet cadence and per-chain message counts; the first message of each session (it is larger because of the PQXDH header); presence (subject to the users' privacy settings); blocks and reports; IP address and connection timing. |
| **The relay CANNOT observe** | Message content; the *kind* of an encrypted payload (message, receipt, typing, reaction, edit, delete, profile, group change); attachment content, names or types; any session, chain, root or message key; any private key; safety numbers or verification state. |
| **Test** | `test_short_messages_are_indistinguishable_by_size`; Dart `padding hides message length from the relay`; end-to-end `no conversation plaintext in database`, `no ML-KEM private seed in database`, `acknowledged ciphertext is deleted, not retained` |
| **Limitation** | No cover traffic, sealed sender or mixing is implemented. A traffic-analysis adversary is **not** defended against. Padding only buckets sizes, and the E1 leakage figures hold for a synthetic distribution, not measured user data. |

### C12 — Fail-closed behaviour

| | |
|---|---|
| **Claim** | There is no path that degrades to plaintext or partial plaintext on failure. |
| **Mechanism** | Every failure raises a `HeloError` subclass. No error type permits degraded operation. No plaintext fallback exists in the codebase. |
| **Test** | `test_malformed_envelopes_are_rejected` (parameterised), `test_arbitrary_bytes_never_parse_into_a_valid_envelope` (property-based), `test_revoked_session_refuses_all_crypto`, `test_responder_cannot_send_before_receiving` |
| **Evidence** | Arbitrary random byte strings fed to the envelope parser always raise a typed protocol error — never a crash, never a partial parse. |
| **Limitation** | None known at the protocol layer. UI-layer error handling is not yet implemented. |

### C13 — Protected key storage and state persistence

| | |
|---|---|
| **Claim** | Persisted session state is encrypted, integrity-protected, and bound to its session. |
| **Mechanism** | AES-256-GCM under a key derived via HKDF from a storage key, with the session id as associated data. |
| **Test** | `test_session_survives_save_and_load`, `test_corrupted_persisted_state_fails_closed`, `test_persisted_state_cannot_be_swapped_between_sessions`, `test_persisted_state_requires_the_correct_storage_key`, `test_persisted_blob_contains_no_recognisable_key_material` |
| **Evidence** | A single flipped bit in the stored blob raises `SessionStateCorruptError`. Blobs cannot be swapped between sessions. |
| **Limitation** | **The storage key's protection is a platform concern not yet implemented** — see [§3](#3-not-yet-claimed). The reference implementation takes the storage key as a parameter; it does not yet obtain it from Android Keystore or iOS Keychain. |

### C14 — Secrets do not leak through logs or diagnostics

| | |
|---|---|
| **Claim** | Diagnostic output and logging cannot emit key material. |
| **Mechanism** | `secure_log.py` uses an **allowlist**: fields not explicitly declared safe are redacted. There is deliberately no `raw` escape hatch. `IdentityKeyPair.__repr__` is overridden. |
| **Test** | `test_diagnostics_expose_no_secret_material`, `test_identity_repr_never_leaks_private_material` |
| **Evidence** | The diagnostics payload is searched for the root key, ratchet private key, and receiving chain key in both raw and hex form. All absent. |
| **Limitation** | Cannot prevent a developer from calling `print()` directly. Enforcement requires the CI lint rules described in [§3](#3-not-yet-claimed). |

### C15 — Hybrid post-quantum session establishment

| | |
|---|---|
| **Claim** | Each new session's initial secret stays secret unless **both** X25519 and ML-KEM-768 are broken. This protects against an adversary who records traffic now and has a quantum computer later. |
| **Mechanism** | PQXDH (PROTOCOL.md § 9): the ML-KEM-768 shared secret is put into the same HKDF as the X3DH DH outputs, under the distinct info string `Helo_PQXDH_X25519_SHA-256_ML-KEM-768_v1`. PQ prekeys are signed by the identity key. |
| **Test** | `test_kem_secret_contributes_to_the_session_key`, `test_hybrid_and_classical_derivations_are_domain_separated`, `test_both_sides_derive_the_same_secret`, `test_forged_pq_prekey_signature_is_rejected`, `test_substituted_pq_prekey_is_rejected_before_any_kem_operation`, `test_tampered_kem_ciphertext_fails_authentication_without_plaintext`; the `pqxdh` vectors and encapsulation fixture (Dart against Python); Dart `two users exchange messages over a hybrid PQXDH session`; end-to-end `session uses the hybrid PQXDH handshake` |
| **Evidence** | The Dart implementation (the `pqcrypto` package) reproduces OpenSSL's ML-KEM-768 encapsulation from the pinned fixture byte for byte. |
| **Limitation** | **Establishment only.** The Double Ratchet is classical, so ratchet steps after the first are not post-quantum. This instantiation has not been formally analysed, and the Dart ML-KEM package has not been audited. |

### C16 — No silent downgrade to classical

| | |
|---|---|
| **Claim** | A relay or network attacker cannot make two Helo/2 clients set up a classical session without either side noticing. |
| **Mechanism** | Initiators refuse bundles without a valid PQ prekey (`PostQuantumUnavailableError`). Responders refuse classical initial messages (`DowngradeRejectedError`). The header version and the presence of the KEM ciphertext must agree. Classical sessions need an explicit, confirmed setting and are labelled "Classical" in the UI. |
| **Test** | `test_relay_stripping_the_pq_prekey_causes_refusal_not_downgrade`, `test_downgraded_initial_message_is_refused_by_hybrid_policy`, `test_downgraded_initial_message_never_decrypts_even_if_classical_allowed`, `test_header_version_and_pq_presence_must_agree`, `test_incompatible_client_without_pq_keys_fails_closed`; Dart `a contact without PQ prekeys is refused until classical is explicitly allowed` |
| **Limitation** | A user who enables classical sessions accepts classical security for contacts that have no PQ keys. This is shown, not hidden. |

### C17 — Attachment confidentiality and integrity

| | |
|---|---|
| **Claim** | The relay stores attachment ciphertext it cannot read. Any change to the ciphertext (bits, order, truncation, extension or substitution) is detected before content is shown. |
| **Mechanism** | A fresh key per file and STREAM over AES-256-GCM (PROTOCOL.md § 11). The key and the SHA-256 digest travel only inside an E2EE message. The relay serves a blob only to the devices listed as its recipients. |
| **Test** | `test_any_flipped_bit_is_detected`, `test_reordered_chunks_are_detected`, `test_dropped_final_chunk_is_detected`, `test_truncated_bytes_are_detected`, `test_appended_bytes_are_detected`, `test_digest_detects_substitution`, `test_chunk_nonces_never_repeat_under_a_key`, plus property tests; Dart `attachments are encrypted on the device and only recipients can fetch them` |
| **Limitation** | The relay sees ciphertext size, which is close to the file size, and the upload and download times. |

### C18 — The relay cannot be used to impersonate a sender device

| | |
|---|---|
| **Claim** | A client can only queue messages as its own device. The sender username a recipient sees is asserted by the relay from the authenticated token, not taken from the envelope. |
| **Mechanism** | Sending requires a device token, and the relay checks `envelope.sender_device_id` against it. This fixes audit finding A1. |
| **Test** | relay `a forged sender device id is refused`, `fetched messages carry the relay-asserted sender username`; end-to-end `relay refuses an envelope naming another device as sender` |
| **Limitation** | This stops other *clients* from impersonating a device. It does not stop a *malicious relay*, which is why the recipient's session authentication (C2, C10) remains the real control. |

### C19 — Receivers enforce who may edit, delete and administer

| | |
|---|---|
| **Claim** | Only a message's author can edit it or delete it for everyone, and only group admins can change a group. A forged payload is ignored even if it decrypts. |
| **Mechanism** | The author of a payload is the session's authenticated peer, never a payload field. Edit and delete windows are 15 min and 48 h. Group snapshots are versioned and applied only from an admin. |
| **Test** | Dart `edits and deletions apply, and only the author can make them`, `a non-admin cannot change the group, even by forging the message`, `a removed member receives nothing sent after removal`, `a new member gets no history from before they joined` |
| **Limitation** | A "delete for everyone" removes the message from compliant clients. It cannot remove a copy that the recipient has already saved. |

---

## 2. Cross-Implementation Conformance

| | |
|---|---|
| **Claim** | The protocol is specified precisely enough that an independent implementation can be verified against it. |
| **Mechanism** | `scripts/generate_test_vectors.py` emits deterministic vectors pinning every intermediate value: HKDF output, each chain-ratchet step, root-ratchet output, AEAD vectors, full X3DH handshakes (both four-DH and three-DH) with all private inputs, a complete Double Ratchet transcript, and an out-of-order scenario. |
| **Test** | `test_vector_hkdf`, `test_vector_chain_ratchet`, `test_vector_root_ratchet`, `test_vector_aes_gcm`, `test_vector_identity_reconstruction`, `test_vector_x3dh_initiator_derives_expected_secret`, `test_vector_x3dh_responder_matches`, `test_vector_three_dh_differs_from_four_dh` |
| **Evidence** | `python3 scripts/generate_test_vectors.py --check` confirms byte-exact reproducibility. The vector suite **already caught one real defect during development**: the three-DH variant used a distinct signed prekey that was not pinned, which would have made the Dart port unverifiable for that path. |
| **Limitation** | Vectors are self-generated. They prove *internal consistency and reproducibility*, not conformance to Signal's published specification. Interoperability with libsignal is **not** claimed and has not been tested. |

---

## 3. Not Yet Claimed

These are architecturally provided for but **not implemented or not demonstrated**, and are therefore claimed nowhere above.

| Property | Status |
|---|---|
| **Post-quantum security of the ratchet** | **Not claimed.** Only session establishment is hybrid (C15). There is no post-quantum ratchet. |
| Hardware-backed key storage | The client uses `flutter_secure_storage`, which is Android Keystore / iOS Keychain on those platforms. **Android and iOS builds have not been compiled or tested.** The web build keeps keys under a WebCrypto key in the same browser, which is not hardware-backed. |
| Mobile platforms | The Dart client is verified by `flutter test` (94 tests) and in the browser. It has not been run on a phone. |
| Mobile performance | Benchmarks and E2 are reference-implementation figures on a desktop-class machine. **No mobile number is claimed.** |
| Device revocation propagation | The relay refuses a revoked device's token. Peers learn about revocation through directory lookups, not through a signed device list. |
| Sealed sender / metadata minimisation | Not implemented. See C11. |
| Push notifications | Not implemented. Notifications appear only while the app is open. |
| Formal verification | Semi-formal only: an enforced state machine with rejected invalid transitions. No ProVerif/Tamarin model. |
| Interoperability with Signal | Not attempted, not claimed. |

---

## 4. Endpoint Security Limitations

These apply to **every** claim above and cannot be mitigated by protocol design:

- **A compromised endpoint defeats everything.** Malware with process memory access reads plaintext before encryption and after decryption.
- **Memory zeroisation is best-effort.** `primitives.wipe()` cannot guarantee erasure in a managed runtime; copies may persist in garbage-collected memory, swap, or hibernation images.
- **Screen capture, keyloggers, and shoulder-surfing** are out of scope.
- **Backups** may capture protected material depending on platform configuration.
- **The recipient is a trusted party.** Nothing prevents them from storing, screenshotting, or forwarding plaintext.
