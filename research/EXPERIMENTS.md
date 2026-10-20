# Experiments

Each experiment is a script you can re-run. It writes its raw output to `research/results/*.json`.
[RESULTS.md](RESULTS.md) holds the numbers from the recorded run, and [METRICS.md](METRICS.md) defines each metric.
No number in these documents comes from anywhere other than these scripts.

| ID | Question | Script | Output |
|---|---|---|---|
| E1 | What does each padding policy cost in bytes, and how much does it hide about message length? | `scripts/experiments/padding_overhead.py` | `results/padding_overhead.json` |
| E2 | What does the hybrid (ML-KEM-768) handshake cost compared with classical X3DH? | `scripts/experiments/handshake_cost.py` | `results/handshake_cost.json` |
| E3 | What can someone holding the relay's database learn? | `scripts/experiments/metadata_inventory.py` | `results/metadata_inventory.json` |
| V | Do the security and functional tests pass? | `scripts/verify.py` | `reports/verification.json`, `reports/dashboard.html` |

```bash
python scripts/experiments/padding_overhead.py
```

```bash
python scripts/experiments/handshake_cost.py --runs 300
```

```bash
python scripts/experiments/metadata_inventory.py
```

```bash
python scripts/verify.py --flutter C:/flutter/bin/flutter.bat
```

## E1 — Padding overhead vs length leakage

- **Implementation under test:** `crypto/reference/helo_ref/padding.py`. The policies are none, block-160, block-256 (the default), pow2-256 and Padmé.
  The Dart client (`mobile/lib/crypto/padding.dart`) matches it byte for byte; this is checked by the `padding` vector section.
- **Inputs:** two synthetic length distributions. No real message corpus was available.
  - `uniform_1_1024`: every length from 1 to 1024 bytes, once each. This is a structural view.
  - `short_chat_lognormal`: 100 000 seeded samples (median 48 B, σ = 1.0, clipped to 1–4096 B).
    These parameters are an **assumption** standing in for short chat messages. They are not measured from users.
- **Wire check:** the experiment encrypts padded payloads with a real PQXDH session and confirms that the ciphertext length is always the padded length plus 16 bytes (the GCM tag).
  So the analysis describes what is actually sent.
- **Caveat:** the app pads the encoded `AppPayload`, which is JSON containing the body, so the padded unit is a little larger than the text a user typed.

## E2 — Hybrid vs classical handshake

- **Implementation under test:** the Python reference `start_as_initiator` / `start_as_responder` with `ClassicalX3DH` and `PQXDH`, using pyca/cryptography on OpenSSL ML-KEM-768.
- **Method:** 300 timed runs per protocol after 3 warm-up runs, each against a fresh responder.
  - The initiator time covers bundle verification, DH, encapsulation and the first encryption.
  - The responder time covers decapsulation, DH and the first decryption.
  - Sizes are the compact JSON forms that actually go to and from the relay.
- **Scope:** these are reference-implementation timings on one Windows laptop. They show the *relative* cost of adding ML-KEM.
  They are not mobile, Dart or production figures.

## E3 — Relay metadata inventory

- **Method:** start the real relay with an empty database. Three reference clients (alice, bob, carol) register and publish prekeys, including PQ prekeys.
  They exchange six messages in conversational order. The relay's SQLite file is then opened directly, as someone with a stolen backup or a compromised server would.
- **Recorded:**
  - every column, with the classification written beside it in `backend/src/db.js`; columns without one are reported as UNCLASSIFIED;
  - the communication graph and sizes, sampled right after each send (what a live observer of the database sees);
  - every table's row count after delivery.
- **Repeated:** once with unpadded payloads and once with block-256.
- **Limitation:** the reference client keeps one session per peer, so each sender reads before replying.
  Simultaneous initiation is handled by the app's Messenger (session archive) and tested in `mobile/test/messenger_test.dart`, not here.

## V — Verification run

`scripts/verify.py` runs these suites:
- pytest (unit, adversarial, property, integration);
- the vector check;
- the relay tests;
- the end-to-end database inspection;
- ruff;
- `flutter analyze`;
- `flutter test`.

It parses per-test results from each runner's own machine-readable output. A missing tool is recorded as NOT RUN, never as PASS.
The app's Verification dashboard displays the resulting `verification.json`.
