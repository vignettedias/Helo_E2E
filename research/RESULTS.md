# Results

Recorded on 2026-10-16. Environment: Windows 11 (AMD64), Python 3.14.6, OpenSSL 4.0.1, Node v24.16.0, Flutter 3.47.
Raw data is in `research/results/*.json`. Re-running a script overwrites its file, and timings will vary from machine to machine.
[EXPERIMENTS.md](EXPERIMENTS.md) describes the methods and [METRICS.md](METRICS.md) defines the metrics.

## E1 — Padding

### Uniform lengths 1–1024 B (structural view)

| policy | mean overhead (B) | overhead % | distinct sizes | leakage (bits) | mean anonymity set |
|---|---:|---:|---:|---:|---:|
| none | 1.0 | 0.2 | 1024 | 10.0 | 1.0 |
| block-160 | 83.44 | 16.28 | 7 | 2.762 | 146.29 |
| **block-256 (default)** | 128.5 | 25.07 | 5 | 2.009 | 204.8 |
| pow2-256 | 193.25 | 37.71 | 4 | 1.509 | 256.0 |
| padme | 11.9 | 2.32 | 76 | 5.727 | 13.47 |

### Synthetic short-chat distribution (log-normal, median 48 B; an assumption, not user data)

| policy | mean overhead (B) | overhead % | distinct sizes | leakage (bits) | mean anonymity set |
|---|---:|---:|---:|---:|---:|
| none | 1.0 | 1.25 | 960 | 7.636 | 1.0 |
| block-160 | 107.33 | 134.4 | 17 | 0.67 | 56.47 |
| **block-256 (default)** | 192.09 | 240.52 | 11 | 0.326 | 87.27 |
| pow2-256 | 194.54 | 243.6 | 5 | 0.318 | 192.0 |
| padme | 3.76 | 4.71 | 93 | 5.443 | 10.32 |

**Wire check:** for every sampled length and policy, ciphertext length = padded length + 16. The relay sees the padded size and nothing finer.

**Reading:**
- For short messages, block-256 reduces what one message reveals about its length from about 7.6 bits to about 0.33 bits.
  The cost is roughly 2.4× the bytes, but because these messages are small that is about 190 B per message.
- Padmé is cheap (under 5% overhead) but still leaks over 5 bits on short messages. It is designed for large objects, which is consistent with this result.
- These conclusions hold for the distributions above. Real message-length data would be needed to state them for real users.

## E2 — Hybrid PQXDH vs classical X3DH (Python reference, 300 runs)

| measure | classical X3DH | hybrid PQXDH | ratio |
|---|---:|---:|---:|
| initiator median (ms) | 0.49 | 0.67 | 1.37× |
| initiator p95 (ms) | 0.604 | 0.977 | 1.62× |
| responder median (ms) | 0.475 | 0.661 | 1.39× |
| responder p95 (ms) | 0.608 | 0.893 | 1.47× |
| prekey bundle (B) | 549 | 2285 | 4.16× |
| first envelope (B) | 579 | 2057 | 3.55× |
| key-agreement header (B) | 361 | 1839 | 5.09× |
| prekey upload (B) | 7226 | 43484 | 6.02× |

**Reading:**
- On this machine, ML-KEM-768 adds about 0.2 ms to each side of a session setup.
- The real cost is in bytes:
  - each bundle fetch grows by about 1.7 KB;
  - the first message of each session grows by about 1.5 KB (the 1088-byte KEM ciphertext, base64-encoded);
  - each full prekey upload grows by about 36 KB (21 encapsulation keys of 1184 B each).
- Later messages in a session are unaffected, because the double ratchet is unchanged.
- These are Python reference figures, not mobile figures.

## E3 — What the relay database reveals (3 users, 6 messages)

- **Delivery:** all six messages were delivered and decrypted, in both runs.
- **Column classes in `db.js` (71 columns):**
  - **first run:** 24 METADATA, 9 CRYPTO (public), 4 SECRET (hashed or salted), 2 CIPHERTEXT, 2 PUBLIC, and
    **30 untagged**. The untagged ones were foreign keys, timestamps and preferences, such as
    `messages.recipient_device`, the `tokens.*` timing columns and `blocks.*`.
  - Those 30 were then tagged METADATA in `db.js` (comments only, no schema change; relay tests 44/44).
    The re-run gives **54 METADATA, 9 CRYPTO, 4 SECRET, 2 CIPHERTEXT, 2 PUBLIC, 0 untagged**.
    Message delivery, the observed graph and the stored sizes were identical in both runs.
  - Only 2 of 71 columns hold ciphertext. Most of what the relay stores is metadata about it.
- **While messages are queued:** joining `messages` → `devices` → `accounts` recovers the full social graph, with times and sizes:
  `alice→bob ×2, bob→alice ×2, alice→carol ×1, carol→alice ×1`.
  The relay routes by device, so it necessarily knows this. Hiding it would need sealed sender or mixing, and HELO does not implement either.
- **After delivery:**
  - `messages` has 0 rows; delivered messages are deleted on acknowledgement.
  - What remains: 3 accounts, 3 devices, 9 token rows (hashed), 3 signed prekeys, 60 one-time prekeys, 18 PQ prekeys and 6 security events.
- **Stored envelope sizes:**

| payload policy | sizes stored (B) | distinct |
|---|---|---:|
| none | 2064, 2116, 215, 367, 2064, 249 | 5 |
| block-256 | 2400, 2400, 551, 551, 2400, 553 | 3 |

**Reading:**
- Padding collapses the message sizes into buckets.
- The **first message of each session stays distinguishable**, at about 2.4 KB, because it carries the PQXDH header.
  So an observer of the database can tell when a new session starts.
- The 551 B vs 553 B difference comes from the envelope header's JSON (ratchet counters), not from content. The header is visible to the relay by design, as in Signal.

## V — Verification run

These are the results of `scripts/verify.py` on 2026-10-16. Two runs were made.

| Suite | First run | Second run (after lint fixes) |
|---|---|---|
| unit | 130/130 | 130/130 |
| adversarial | 49/49 | 49/49 |
| property | 18/18 | 18/18 |
| integration | 10/10 | 10/10 |
| vectors | 1/1 | 1/1 |
| relay | 44/44 | 44/44 |
| integration_e2e | 29/29 | 29/29 |
| lint_python (ruff) | **FAIL**: 15 findings (unused `noqa`, import order) in the new experiment scripts | 1/1 |
| flutter_analyze | 1/1 | 1/1 |
| flutter_test | 76/76 | 76/76 |
| **total** | 358/359, 9 suites PASS, 1 FAIL | **359/359, all 10 suites PASS** |

A third run followed after four more changes:
- two new Dart tests: pin, archive and mute; payload dedupe. Both were mutation-checked.
- a fix that returns the app to onboarding after a device reset.
- clearer wording for the key-conflict notice.

That run passed **361/361, all 10 suites PASS**, with flutter_test at 78/78.

A fourth run followed after QR scanning, voice messages and media playback were added. It also included
the fix for caption-less attachments being dropped. That run passed **388/388**: unit 144, Dart 91, the
rest unchanged.

A fifth run followed after HTTPS LAN mode (relay proxy trust, +1 relay test) and group invite links
(+2 Dart tests). That run passed **391/391**: relay 45, Dart 93.

A sixth run followed after the fix for media uploads failing behind the HTTPS demo proxy (methodology
defect 14). That run passed **405/405**: integration 23 (13 new proxy tests), Dart 94.

A seventh run followed the attack simulator, the privacy features and the presentation extras:
**436/436**, with relay 51 (demo-attack switch) and Dart 116.

The per-test detail for the latest run is in `reports/verification.json` and `reports/dashboard.html`.
