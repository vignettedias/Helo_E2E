# Research Methodology

## Objective

Build an independently engineered implementation of modern asynchronous
end-to-end encrypted messaging over an untrusted relay, and — the actual
research contribution — establish a methodology in which **every claimed
security property is mapped to executable evidence**, and every property that
cannot be so mapped is explicitly withdrawn.

The interesting question is not "can a Signal-style protocol be implemented?"
It can; the specification is public. The question is: *what does it take to
make the resulting security claims independently checkable rather than
asserted?*

## Security objectives

O1 Content confidentiality against the relay and network
O2 Message integrity and authentication
O3 Forward secrecy for consumed messages
O4 Post-compromise security after fresh ratchet entropy
O5 Replay resistance
O6 Out-of-order and offline delivery
O7 Detectable peer identity substitution
O8 Bounded, attacker-triggerable resource consumption
O9 Fail-closed behaviour with no plaintext fallback
O10 Honest, enumerated metadata exposure

## Assumptions

1. X25519, Ed25519, SHA-256, HMAC, HKDF, and AES-256-GCM are secure as
   specified. No primitive is implemented by hand.
2. The endpoint device is uncompromised. This assumption does the most work of
   any in the model; §T7 of THREAT_MODEL.md states its consequences.
3. The relay is fully hostile — operator, database, and TLS terminator.
4. Users may or may not compare safety numbers out of band. Results are
   reported separately for both cases (see O7 / T4).
5. The platform CSPRNG is sound.

## Experimental method

### Verification strategy: differential conformance

The central methodological choice. Two independent implementations exist:

| Implementation | Role |
|---|---|
| Python (`crypto/reference/`) | **Normative.** Executable specification. |
| Dart (`mobile/lib/crypto/`) | Port, verified against the reference. |

A second implementation of a cryptographic protocol is rarely wrong in a way
that crashes. It is wrong in a way that derives a *different key* while looking
healthy in isolation. Two implementations that only ever talk to themselves both
pass their own tests and fail to interoperate.

`scripts/generate_test_vectors.py` therefore pins every intermediate value —
HKDF output, each chain-ratchet step, root-ratchet output, AEAD vectors, both
X3DH variants with all private inputs, a full ratchet transcript, and an
out-of-order scenario — from a fixed seed, reproducibly. Byte-exact
reproducibility is asserted in CI.

**Validation of the method:** it found a real defect during development. The
three-DH variant used a distinct signed prekey that was never pinned, which
would have left that code path unverifiable in the port.

### Compromise simulation

Forward secrecy and post-compromise security are tested by **cloning the
victim's complete protocol state** — root key, both chain keys, ratchet private
key, skipped-key store, all counters — at a chosen instant. This is a strictly
stronger attacker than real memory scraping.

Two methodological safeguards against vacuous results:
1. The break-in recovery test **first confirms the attacker CAN read traffic**
   immediately post-compromise. Without this, a later decryption failure could
   be caused by any bug rather than by recovery.
2. The known exceptions are asserted as *positive* tests — in-flight messages
   and stored skipped keys **must** decrypt from stolen state. Encoding the
   limitation as a passing test prevents it being quietly overstated later.

### Property-based testing

Hand-written cases encode failures the author already thought of. Properties
are quantified over generated inputs: arbitrary delivery permutations (not just
1,3,2,4), every bit position in the ciphertext including the tag (via modulo
indexing rather than filtering, so no generated input is wasted), and arbitrary
byte strings against the parser.

### Cross-stack integration

`scripts/integration_e2e.py` starts the **real Node relay process**, drives it
with the **real reference client over HTTP**, then opens the relay's SQLite file
and scans the **raw bytes** — including WAL remnants — for a plaintext canary,
both identity private keys, the ratchet root key, the ratchet private key,
chain keys, the account password, and the auth token.

Alice and Bob never share a Python object. Every byte crosses a real socket and
lands in a real database first.

## Results

Current per-test results are produced by `python scripts/verify.py`, written to `reports/verification.json`
(also rendered as `reports/dashboard.html` and in the app's Verification dashboard). The final run of 2026-10-16 (405/405):

| Suite | Count | Status |
|---|---|---|
| Python unit (protocol, PQXDH, padding, attachments, QR verdict) | 144 | pass |
| Adversarial (incl. PQ downgrade / KEM tampering) | 49 | pass |
| Property-based (Hypothesis) | 18 | pass |
| Integration / vector conformance / demo proxy | 23 | pass |
| Vectors reproduce byte-exactly | 1 | pass |
| Relay backend (v1 + v2 API, proxy trust) | 45 | pass |
| Cross-stack end-to-end (PQXDH, DB inspection) | 29 checks | pass |
| Dart (vectors, protocol v2, Messenger vs real relay, chat widgets, QR decode, invites) | 94 | pass |

Measured experiments (padding overhead and leakage, hybrid vs classical handshake cost, relay metadata
inventory) are in `research/RESULTS.md`, with methods in `research/EXPERIMENTS.md`. Earlier timing figures in
`docs/benchmarks/reference-implementation.json` remain disclaimed as reference-implementation-on-desktop and
**not** mobile performance.

### Defects found by the methodology

Recorded because a methodology's value is measured by what it catches:

1. **Unpinned three-DH signed prekey** — found by vector conformance. Would
   have made that path unverifiable across implementations.
2. **Relay FIFO ordering** — messages queued within the same second were
   ordered by random UUID. Found by cross-stack integration. The protocol
   tolerates out-of-order delivery, so this decrypted correctly and was
   invisible to every component-level test.
3. **Socket destroyed on oversized body** — clients saw a connection reset
   instead of HTTP 413, indistinguishable from server failure.
4. **Infinite recursion in the Dart PQXDH seam** — a method shadowing the
   top-level function it was meant to delegate to.
5. **Dart safety number ordered by base64 text, not bytes** — found when the
   Dart suite was first executed and the vectors re-examined. The base64
   alphabet is not in ASCII order, so the port disagreed with the reference for
   roughly a third of identity pairs while agreeing with itself — exactly the
   "healthy in isolation" failure the vectors exist for. The original pinned
   pair happened to sort the same both ways, so a vector was added that cannot.
6. **Ratchet state persisted after sending** — the client saved session state
   only after the envelope left the device. A crash in between would roll the
   ratchet back and reuse a message key, and with it the derived AES-GCM nonce,
   for different plaintext. Now persisted before sending, with a regression
   test that fails a send mid-flight and restarts.
7. **Unanswered session lost its X3DH header on restart** — the pending
   initial-message header was not part of persisted session state (in the
   reference *and* the port), so a session opened but not yet used before a
   restart could never be established by the peer.
8. **Client restart was broken outright** — the device token was stored under
   the device-id key, and prekeys, tokens and sessions were never reloaded.
   Found only by actually running the app across a restart.

9. **Sender impersonation at the relay (audit finding A1)** — any authenticated account could queue an
   envelope claiming another device as sender. Sending now requires a device token and the relay checks
   `envelope.sender_device_id` against it; `scripts/integration_e2e.py` section 11 attempts the impersonation.
10. **UI and poll loop raced on the ratchet** — a send from the UI and a decrypt from the receive loop could
    read and write the same session concurrently, rolling one state change back. All ratchet operations now
    run under one `AsyncLock`; with the lock disabled the "concurrent sends" test fails 3/3.
11. **First message to a new device hung forever** — a de-duplication fix for prekey-bundle fetches used
    `.whenComplete(() => map.remove(id))`, which returns the very future being completed, so it awaited
    itself. Found by the first widget test that sent a message under the Flutter test binding; the
    Messenger suite had last run before the change.
12. **UI defects found by driving the web build** — the actions sheet overflowed on short windows; the
    message banner never dismissed (a SnackBar with an action persists by default); delete-for-everyone had
    no confirmation; the chat title was squeezed to nothing at phone width; after "Reset this device" the
    Settings page stayed on top of onboarding. Each is fixed; the sheet overflow and the delete
    confirmation have widget tests, and the rest were re-checked in the browser.

13. **Attachments without a caption were silently dropped** — the sender encoded an empty body as `""`
    and the receiver's strict decoder rejected empty strings, discarding the whole message. Every earlier
    attachment test used a caption, so nothing caught it until a voice-message test sent none. Fixed in
    the decoder (older senders already put `""` on the wire), with a regression test that fails when
    the fix is reverted.

14. **Every media upload failed behind the HTTPS demo proxy** (`run_demo.py --lan`, also used on Android
    via Termux): the proxy forwarded an allowlist of request headers that omitted `X-Helo-Recipients`, so the
    relay received uploads with no recipient list and correctly answered `400 validation_failed`. Text
    messages need no such header, so only photos, videos and voice notes broke. Every existing test talked to
    the relay directly, bypassing the proxy. Fixed by forwarding that header (named explicitly); the proxy also
    gained its own body-size cap. `tests/integration/test_demo_proxy.py` drives the real relay through the
    real proxy and failed 7 ways before the fix. The client also dropped the relay's `field`/`message`, so
    users saw only "Relay error (validation_failed)"; it now keeps and shows them.

15. **Every photo, video, file and voice message failed in the locally built web app** — `flutter build web`
    reused a stale `.dart_tool/flutter_build/*/web_plugin_registrant.dart` (from before the media plugins
    were added) that registered only secure storage, so the file picker and recorder fell back to native
    method channels that do not exist in a browser (`MissingPluginException`) and nothing was ever
    uploaded. Found by driving the real web build in a browser; `flutter test` cannot see it because tests
    run on the VM, not the web build. Fixed by a clean rebuild; `run_demo.py` now warns about such builds
    and CI fails if a web build lacks the file-picker or recorder code.

Defect 2 is the most instructive: a correctness bug *masked by a security
feature*. Only a test that drove the whole stack and checked ordering directly
could surface it.

## Limitations

- **Post-quantum only at key establishment.** PQXDH (X25519 + ML-KEM-768) protects the initial shared
  secret against harvest-now-decrypt-later; the double ratchet that follows is classical, so a quantum
  adversary who records traffic can attack ratchet steps after the first. ML-KEM is OpenSSL's in the Python
  reference and the `pqcrypto` Dart package in the client (checked against OpenSSL in tests, not audited).
- **Metadata is visible to the relay.** It sees who sends to whom, when, and padded sizes (see
  `research/RESULTS.md`, E3); there is no sealed sender or mixing.
- **Vectors are self-generated.** They prove internal consistency and
  reproducibility, not conformance to Signal's published specification.
  Interoperability with libsignal is not claimed or tested.
- **The Dart port is verified against the vectors and in the browser, not on
  phones.** `flutter test` passes and the web build has been driven end to end
  against the real relay; the Android and iOS builds have not been compiled,
  and platform keystores have not been exercised.
- **Semi-formal verification only.** An enforced state machine with rejected
  invalid transitions; no ProVerif or Tamarin model.
- **Mobile performance unmeasured.** No mobile figure is claimed.
- **No independent audit.**
- **TOFU.** First-contact MITM detection depends on users comparing safety
  numbers, which the software cannot compel.

## Future work

1. ~~PQXDH via the `KeyEstablishment` seam~~ — done in HELO 2.0. Next: a post-quantum ratchet component.
2. Symbolic verification of the handshake and ratchet in Tamarin.
3. Mobile benchmarking on physical handsets.
4. Sealed sender and padding to address the metadata exposure in T8.
5. Hardware-resident identity keys, contingent on platform support for X25519
   and Ed25519 inside the TEE / Secure Enclave.
6. Multi-device fan-out and cross-device session synchronisation.
