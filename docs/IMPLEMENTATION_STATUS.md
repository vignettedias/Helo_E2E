# Implementation Status (session hand-off file)

Kept current so work can resume from here after any interruption.
**Last updated 2026-10-16.** Nothing has been committed or pushed: the user pushes manually.

## Current phase

**All planned phases are done: 0–10.** Verified by `python scripts/verify.py`: 391/391 tests, 10/10 suites PASS.
What remains is listed under "Not done / honest gaps".

## Completed

| Phase | What | Where |
|---|---|---|
| 0 | Audit and design docs | `docs/PROJECT_AUDIT.md`, `ARCHITECTURE.md`, `SECURITY_MODEL.md`, `IMPLEMENTATION_ROADMAP.md` |
| 1 | Stabilisation: A1 sender binding, `--lan` refusal, relay migrations | `backend/src/`, `scripts/run_demo.py` |
| 2 | Protocol v2: PQXDH, padding, STREAM attachments (Python + Dart + vectors) | `crypto/reference/helo_ref/`, `mobile/lib/crypto/`, `tests/vectors/` |
| 3 | Relay v2 API | `backend/src/routes/*.js`, `docs/API.md` |
| 4 | Client domain: Messenger, Directory, LocalStore, groups, AsyncLock | `mobile/lib/domain/`, `mobile/lib/protocol/` |
| 5 | UI, browser-checked | `mobile/lib/ui/` |
| 8/10 | Experiments E1–E3 and research docs (real outputs only) | `scripts/experiments/`, `research/` |
| 9 | Verification runner, report, HTML dashboard, in-app dashboard served by `run_demo.py` | `scripts/verify.py`, `reports/` |
| docs | TESTING, API, `.env.example`, PROTOCOL §9–12, SECURITY_CLAIMS C15–C19, README, RUNNING, PRIVACY, THREAT_MODEL, SECURITY, roadmap statuses, methodology defects 9–12 | |
| CI | `setup-node` added to the flutter job | `.github/workflows/ci.yml` |
| E3 follow-up | all 71 relay DB columns classified (30 untagged → METADATA); E3 re-run | `backend/src/db.js`, `research/RESULTS.md` |

## Bugs found and fixed in the final pass

| Bug | Found by | Fix |
|---|---|---|
| **First message to any new device hung forever.** `.whenComplete(() => _bundleFetches.remove(id))` returned the very future being completed, so it awaited itself | new `test/chat_view_test.dart` | block-bodied callback in `Messenger._send` |
| Actions sheet overflowed by 113 px on short windows | widget test | `isScrollControlled` + scroll view |
| Message banner never disappeared (a SnackBar with an action persists) | browser | `persist: false` |
| Delete-for-everyone had no confirmation | browser review | confirm dialog + widget test |
| Chat title squeezed to nothing at phone width | browser, 375 px | badges move under the title below 600 px |
| Settings page stayed on top of onboarding after "Reset this device" | browser | navigator key; pop to root on reset |
| Key-conflict notice promised a "verify again" path that does not exist | code review | honest wording; a conflicting device stays blocked by design |
| `verify.py` showed mojibake in the environment line on Windows | in-app dashboard | decode tool output as UTF-8 |
| Earlier in the browser pass: right-click/tap opened no actions menu; "Connecting…" stuck for 25 s; duplicate bundle fetches | browser | fixed (see methodology defect 12) |

## Browser check (2026-10-16, `run_demo.py`, Alice on :5000, Bob on :5001)

Exercised:
- **Accounts and chats:** register two users; new chat by username; PQ hybrid badge; presence.
- **Messaging:** live delivery both ways; read ticks; unread badge; in-app banner.
- **Message actions:** tap and right-click open the actions sheet; reaction (seen by the other side); quoted reply; edit (shown as "edited"; Edit hidden after 15 min); delete for everyone.
- **Groups:** group create, with the message delivered to the member.
- **Settings and appearance:** settings; dark theme; phone width (375 px) list and chat; wide 3-pane layout.
- **Verification dashboard:** shows the real report.
- **Recovery:** the relay was wiped, the app showed a clear message, the device was reset and the account re-registered.

Not exercised in the browser: attachments (the browser tool cannot drive the OS file picker). They are covered by `messenger_test.dart` against the real relay.

## Latest results (2026-10-16, final `python scripts/verify.py`)

| Suite | Result |
|---|---|
| unit / adversarial / property / integration (pytest) | 144 / 49 / 18 / 10 passed |
| vectors `--check` | PASS |
| relay | 45 passed |
| integration_e2e | 29/29 |
| ruff | clean |
| flutter analyze | clean |
| flutter test | 93 passed |
| **total** | **391/391, 10/10 suites PASS** |

Mutation checks (evidence the tests are not vacuous):
- AsyncLock disabled → the "concurrent sends" test fails;
- persist-before-send removed → the "relay outage" test fails;
- mute ignored → the "pinning, archiving and muting" test fails;
- payload dedupe removed → the "delivered twice" test fails.

Code was restored after each check.

## Voice, video, QR (added after the main pass)

| Piece | Where | Tested by |
|---|---|---|
| QR verdict (normative) | `helo_ref/identity.py` `check_qr_payload` | `tests/unit/test_qr_verification.py` (14); `qr_check` vectors |
| QR verdict (Dart) | `lib/crypto/identity.dart` `checkQrPayload` | vector conformance (all 9 cases) |
| QR image decode (pure Dart: zxing2 + image) | `lib/verification/qr_image.dart` | `test/qr_scan_test.dart` (6): PNG, lossy 2000 px JPEG, the app's own qr_flutter encoder, wrong key, non-Helo, garbage |
| Scan → verify exactly one device | `Messenger.verifyByScannedCode` | messenger test against the real relay (match / peer mismatch / own-key mismatch / not Helo) |
| Scanner screen (camera stills every 0.6 s, or "Choose an image") | `lib/ui/screens/qr_scan_screen.dart` | NOT checked by hand yet |
| Voice/duration fields, strict decode | `lib/protocol/payload.dart` | codec test (6 rejections, backward compatible) |
| Voice send, receive, forward | `Messenger.sendAttachment(voice:)` | messenger test against the real relay |
| Recorder bar (AAC, else 16 kHz WAV; 5 min cap) | `lib/ui/widgets/voice_recorder.dart` | widget test: no microphone → fails safe; real recording NOT checked by hand |
| Player (audio inline, video dialog) | `lib/ui/widgets/media_player.dart`, `lib/media/` | widget test: a voice note renders as a player; playback NOT checked by hand |

**Bug found on the way:** an attachment sent without a caption was silently dropped by every receiver.
The decoder rejected the empty body. Fixed, with a regression test that fails when the fix is reverted.

New dependencies, all official or pure Dart:
- `zxing2` and `image` (QR decode);
- `camera`, `video_player`, `record`;
- `path_provider`, `cross_file`, `web`;
- `qr` (dev only).

`mobile_scanner` was rejected because on web it loads a decoder script from a CDN.
Platform permissions were added: Android `CAMERA` and `RECORD_AUDIO`; iOS camera and microphone usage strings.

**Manual check still to do** (`python scripts/run_demo.py --fresh`, two tabs):
1. Bob taps the mic, records a few seconds and sends. Alice taps play, and the length shows.
2. Send a short `.mp4` with the attach button. The other side taps ▶ and it plays in the dialog.
3. Alice opens chat Details → Compare and screenshots the QR code. Bob opens Compare → "Scan their code" →
   "Choose an image", picks the screenshot, and gets "Verified". With a webcam, try the live scan too.

## Phone access and invite links (added 2026-10-20)

- **`run_demo.py --lan`** serves the app over HTTPS on the Wi-Fi, with a self-signed certificate for every
  IPv4 address of the PC (`backend/data/demo-tls/`).
  - It forwards the relay API on the same origin. The relay stays on 127.0.0.1.
  - `TRUST_PROXY_LOOPBACK=1` keeps rate limits per client: tested in `relay_v2.test.js`.
  - The client now uses its own origin as the relay URL on HTTPS pages (`lib/app.dart`). On port 443 that
    is the same as before.
  - Verified by `scripts/lan_smoke.py` against the real Wi-Fi address: 8/8 checks.
  - **Not verified:** a real phone. The built-in browser cannot click through a self-signed certificate
    warning, so it could not stand in for one.
- **Group invite links:**
  - Built in `Messenger.createInviteLink` / `requestJoinByInvite` / `_handleJoinRequest`, plus the
    group details "Invite link" dialog (QR, copy, revoke) and New chat accepting a link.
  - Tests: join works, a guessed secret is refused (mutation-checked), revoked links are refused, the
    secret never enters the group snapshot, strict parsing.
- **Still not done:**
  - history sync between one user's own devices (needs protocol "sync messages");
  - real message-length data for E1, which does not exist here and will not be invented.

## Not done / honest gaps

- Android and iOS builds have never been compiled; there is no Android SDK or macOS here.
- There is no post-quantum ratchet. PQ covers establishment only, and the instantiation has not been formally analysed.
- No sealed sender, cover traffic or push notifications.
- QR scanning, voice recording and audio/video playback are implemented and tested in code, but have not
  been checked by hand with a real camera, microphone or player (see "Voice, video, QR" below).
- A user's own devices do not sync history with each other.
- E1 uses synthetic length distributions, not real user data.

## How to resume

```bash
python scripts/verify.py --flutter C:/flutter/bin/flutter.bat
```

```bash
python scripts/run_demo.py --fresh
```

## Tool notes

- Flutter: `C:/flutter/bin/flutter` (not on PATH). Python: `python`. ruff: scratchpad `ruffpkg/bin/ruff.exe` (pass with `--ruff`).
- Heredocs in the Bash tool mangle backslash escapes. Write patch scripts with the Write tool.
- Messenger and widget tests need `node` on PATH, because they start `backend/src/server.js`.
- Widget tests against the real relay (`test/chat_view_test.dart`) need three things:
  - `HttpOverrides.global = null`, because the binding mocks HttpClient with 400s;
  - relay and account setup in `setUp`;
  - pumping past HttpClient's 15 s idle timer at the end.
- Browser pane screenshots are tiny when the pane is hidden, so show it first (`show_pane preview`).
- The `.claude/launch.json` config `helo-demo` uses `--fresh`, so restarting it wipes the demo relay.
