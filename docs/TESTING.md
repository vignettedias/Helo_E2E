# Testing

## One command

```bash
python scripts/verify.py --flutter C:/flutter/bin/flutter.bat
```

This runs every suite below and writes `reports/verification.json` and `reports/dashboard.html`.
The app's **Settings → Verification dashboard** shows the same report when the demo is running, because `run_demo.py` serves it at `/verification.json`.
- A suite whose tool is missing is recorded as **NOT RUN**, never as PASS.
- `--skip <key>` leaves a suite out.
- `HELO_FLUTTER` and `HELO_RUFF` can point at tools that are not on PATH.

## Suites

| Key | What it checks | Run it alone |
|---|---|---|
| `unit` | Python reference: X3DH/PQXDH, double ratchet, envelopes, padding, STREAM attachments, session persistence | `python -m pytest tests/unit -q` |
| `adversarial` | tampering, replay, reordering, key substitution, classical downgrade, malformed KEM data | `python -m pytest tests/adversarial -q` |
| `property` | Hypothesis round-trip and invariant properties (ratchet, padding, attachments) | `python -m pytest tests/property -q` |
| `integration` | multi-party flows and conformance to the committed vectors | `python -m pytest tests/integration -q` |
| `vectors` | every vector in `tests/vectors/` regenerates byte for byte | `python scripts/generate_test_vectors.py --check` |
| `relay` | real HTTP server per test: auth, device-bound sending, prekeys incl. PQ, long-poll, batch, attachments, blocks, presence privacy, rate limits, migrations | `cd backend && npm test` |
| `integration_e2e` | the real relay plus the reference client over PQXDH, then reading the relay database for plaintext, keys, PQ seeds and sender impersonation | `python scripts/integration_e2e.py` |
| `lint_python` | ruff | `ruff check crypto/ tests/ scripts/` |
| `flutter_analyze` | Dart static analysis | `cd mobile && flutter analyze` |
| `flutter_test` | Dart crypto vs. the Python vectors, protocol v2 conformance, Messenger end to end and chat-screen widget tests, **against the real relay process** | `cd mobile && flutter test` |

`flutter_test` needs `node` on PATH, because each Messenger and widget test starts `backend/src/server.js` with a fresh database (`mobile/test/support/relay_harness.dart`).

## How the client tests work

- **`messenger_test.dart`** drives two or three real `Messenger` instances through a real relay. It covers:
  - PQXDH sessions;
  - simultaneous initiation;
  - groups and admin authorisation;
  - edits and deletes by non-authors (rejected);
  - receipts and typing;
  - disappearing messages;
  - attachments;
  - blocking;
  - relay outages (envelopes re-sent, never re-encrypted);
  - restart from storage;
  - a tampered first message (it must not create a conversation);
  - safety numbers and per-device verification;
  - padding (the relay must not see message length).
- **`chat_view_test.dart`** pumps the real `ChatView` against the same relay. It checks:
  - tap, long-press and right-click open the actions sheet;
  - own and incoming messages offer the right actions;
  - a reaction and a quoted reply reach the other side;
  - delete-for-everyone asks first.

  Three details are needed to run real I/O under the widget-test binding:
  - `HttpOverrides.global = null`, because the binding otherwise answers every HTTP request with 400;
  - relay and account setup in `setUp`;
  - pumping past HttpClient's 15-second idle-connection timer at the end.

## Evidence that the tests are not vacuous (mutation checks)

| Mutation | Test that caught it |
|---|---|
| `AsyncLock` disabled (ratchet operations no longer serialised) | "concurrent sends…" fails 3/3 |
| persist-before-send removed | "relay outage…" fails (the receiver rejects key reuse) |
| `.whenComplete(() => map.remove(id))` deadlock (a real bug, not a planted one) | every `chat_view_test.dart` setUp hung until it was fixed |
| muted chats notify anyway | "pinning, archiving and muting…" fails (`['d:bob', 'd:carol']` instead of `['d:carol']`) |
| application-level payload dedupe removed | "a payload delivered twice … is shown once" fails (message shown twice) |

## Why some tests changed in HELO 2.0

- **Relay message tests** now use device tokens. Sending with an account token, or with a mismatched `sender_device_id`, must now fail; this is audit finding A1.
  The old tests encoded the vulnerable behaviour.
- **`session_manager_test.dart`** was deleted together with `SessionManager`. Its properties are re-tested against the `Messenger` that replaced it, in `messenger_test.dart`:
  - restart on both sides;
  - transparent token renewal;
  - crash or outage before send (the same envelope is re-sent);
  - a forged or tampered first message;
  - the stored device id is not a bearer token.

## Manual browser check

```bash
python scripts/run_demo.py --fresh
```

Open http://localhost:5000 (Alice) and http://localhost:5001 (Bob). What was exercised on 2026-10-16 is listed in `docs/IMPLEMENTATION_STATUS.md`.
Attachments were not exercised there, because the browser automation cannot drive the OS file picker; `messenger_test.dart` covers them.

## Latest results

See `reports/verification.json` (the current run) and `research/RESULTS.md` (the recorded run with experiments).
