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

| Suite | Count | Status |
|---|---|---|
| Unit (protocol) | 37 | pass |
| Unit (security properties) | 9 | pass |
| Adversarial | 29 | pass |
| Property-based (Hypothesis) | 13 | pass |
| Integration / vector conformance | 10 | pass |
| Relay backend | 22 | pass |
| Cross-stack end-to-end | 25 checks | pass |

Measured: ciphertext expansion is a **constant 57 bytes** (16-byte tag +
41-byte header) from 0 B to 16 KB. Timing figures are in
`docs/benchmarks/reference-implementation.json`, disclaimed as
reference-implementation-on-desktop and **not** mobile performance.

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

Defect 2 is the most instructive: a correctness bug *masked by a security
feature*. Only a test that drove the whole stack and checked ordering directly
could surface it.

## Limitations

- **Not post-quantum.** No PQ primitive exists in the codebase.
- **Vectors are self-generated.** They prove internal consistency and
  reproducibility, not conformance to Signal's published specification.
  Interoperability with libsignal is not claimed or tested.
- **The Dart port is unverified at the time of writing.** It has not been
  executed; `flutter test` must be run to establish conformance. Presenting it
  as verified would be exactly the kind of unbacked claim this methodology
  exists to prevent.
- **Semi-formal verification only.** An enforced state machine with rejected
  invalid transitions; no ProVerif or Tamarin model.
- **Mobile performance unmeasured.** No mobile figure is claimed.
- **No independent audit.**
- **TOFU.** First-contact MITM detection depends on users comparing safety
  numbers, which the software cannot compel.

## Future work

1. PQXDH via the existing `KeyEstablishment` seam (hybrid ML-KEM-768 + X25519).
2. Symbolic verification of the handshake and ratchet in Tamarin.
3. Mobile benchmarking on physical handsets.
4. Sealed sender and padding to address the metadata exposure in T8.
5. Hardware-resident identity keys, contingent on platform support for X25519
   and Ed25519 inside the TEE / Secure Enclave.
6. Multi-device fan-out and cross-device session synchronisation.
