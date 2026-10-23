# Implementation Status (session hand-off file)

Kept current so work can resume from here after any interruption.
**Last updated 2026-10-16.** Nothing has been committed or pushed: the user pushes manually.

## Current phase

**All planned phases are done: 0–10.** Verified by `python scripts/verify.py`: 436/436 tests, 10/10 suites PASS.
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

## Browser check (2026-10-16, `run_demo.py`, User 1 on :5000, User 2 on :5001)

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
| unit / adversarial / property / integration (pytest) | 147 / 49 / 18 / 23 passed |
| vectors `--check` | PASS |
| relay | 51 passed |
| integration_e2e | 29/29 |
| ruff | clean |
| flutter analyze | clean |
| flutter test | 116 passed |
| **total** | **436/436, 10/10 suites PASS** |

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
1. User 2 taps the mic, records a few seconds and sends. User 1 taps play, and the length shows.
2. Send a short `.mp4` with the attach button. The other side taps ▶ and it plays in the dialog.
3. User 1 opens chat Details → Compare and screenshots the QR code. User 2 opens Compare → "Scan their code" →
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

## Fix: media uploads failed in the phone/Termux demo (2026-10-21)

- **Root cause:** the `--lan` HTTPS proxy in `scripts/run_demo.py` forwarded only the `authorization`,
  `content-type`, `accept` and `last-event-id` request headers.
  - It dropped `X-Helo-Recipients`, so the relay answered every `POST /attachments` with
    `400 {"error":"validation_failed","field":"x-helo-recipients"}`.
  - Text needs no such header, so it kept working.
  - The plain localhost web version calls the relay directly and was never affected. This was checked in a
    real browser: CORS preflight, upload 201, byte-identical download.
- **Fix:** forward `x-helo-recipients`; the proxy also caps request bodies at 26 MiB itself (413).
- **Diagnostics:** `RelayException` keeps the relay's `field` and `message`, and the UI shows them. Tokens,
  keys and content are never included.
- **Tests:**
  - `tests/integration/test_demo_proxy.py` (13), against the real relay and the real proxy: image-, video-
    and audio-sized encrypted uploads, recipient download, digest check, decryption, database holds only
    ciphertext, unlisted device refused, missing/invalid/empty recipients, empty body, wrong content type,
    oversize at both relay and proxy, text still flows, exact header allowlist.
  - Relay CORS preflight test for `X-Helo-Recipients`.
  - Dart test: a structured validation error reaches the user.
- **Result:** `verify.py` 436/436 (integration 23, Dart 94).

## Fix: media did nothing in the locally built web app (2026-10-21)

- **Root cause:** a stale web plugin registrant from Oct 15 registered only secure storage. The file picker,
  recorder, camera and video player web code was absent from `main.dart.js`, so the browser console showed
  `MissingPluginException … filepicker` and no upload was ever attempted.
- **Fix:** `flutter clean && flutter build web`.
- **Verified in the browser** on the rebuilt app (a test file supplied to the real file input):
  - photo sent and shown (`POST /attachments 201`);
  - WAV sent and played to the end;
  - WebM video sent and played in the player;
  - the mic button reaches the browser's permission request. The browser pane blocks the microphone, so the
    app showed "Microphone permission was not granted"; a real browser will prompt.
- **Guards:** `run_demo.py` warns at start if the build lacks this code (`tests/unit/test_demo_build_check.py`),
  and a CI step fails such a build.

## Cyberdeck UI and visible security (2026-10-23)

- **Theme (`lib/ui/theme.dart`, `lib/ui/widgets/cyberdeck.dart`):**
  - phosphor terminal palette, dark by default, with a "green-bar paper" light theme;
  - sharp 4px corners;
  - JetBrains Mono bundled (SIL OFL, `mobile/assets/fonts/OFL.txt`; no runtime font fetch);
  - `HELO:~$` title with a blinking cursor that respects reduced motion;
  - CRT scan lines in dark mode that ignore pointer input.
- **B1 Crypto X-Ray:**
  - A chat header toggle shows, under each message, what the relay stored: envelope size, AES-GCM length
    (padded + tag), the start of the ciphertext, ratchet n/pn, the start of the DH key, and whether the
    envelope opened a PQXDH session.
  - All of it comes from the real envelope (`WireInfo` in `lib/domain/models.dart`) and holds nothing the
    relay does not already see.
  - Tests: messenger (both sides, persistence) and a chat-view widget test.
- **B5 padding meter:** Settings shows each padding policy's measured length leak and byte cost, copied from
  `research/RESULTS.md` E1.
- **B6 visual safety numbers:**
  - A 12-emoji strip derived from the safety number (`lib/verification/visual_safety.dart`), identical on
    both sides; tested.
  - The digits and the QR scan remain the authoritative check.
- **Learned on the way (true behaviour, now tested):** until the recipient replies, every message
  re-carries the PQXDH header, so any one of them can open the session.

## Crypto Lab, command palette, ratchet timeline, privacy blur (2026-10-23)

- **Crypto Lab** (`lib/lab/crypto_lab.dart`, `lib/ui/screens/crypto_lab_screen.dart`):
  - Runs the real Dart protocol on throwaway in-memory identities: a full PQXDH handshake, then five attacks.
  - The attacks: a 1-bit tamper, a replay, a downgrade (PQ part stripped), a relay hiding the PQ prekey,
    and a substituted KEM key.
  - Each prints the real rejection (`AuthenticationError`, `ReplayError`, `DowngradeRejectedError`,
    `PostQuantumUnavailableError`, `SignatureVerificationError`).
  - A defence that did not hold would be printed as `[FAIL]`.
  - Reachable from the menu, Ctrl+K, and the sign-up screen (no account needed).
  - Tests: `test/crypto_lab_test.dart` (all 6), `test/crypto_lab_screen_test.dart` ("6/6 defences held").
- **Ctrl+K command palette** (`lib/ui/widgets/command_palette.dart`):
  - New chat or group, crypto lab, X-Ray, privacy blur, theme, settings, the verification dashboard,
    jump to any chat, and a panic wipe (with confirmation).
  - Filtering tested.
- **Global X-Ray and privacy blur** (`lib/ui/deck_state.dart`). Blur hides message bubbles until hovered;
  it guards against shoulder-surfing and does not stop screenshots.
- **Ratchet timeline** (chat details):
  - Messages are grouped by the sender's ratchet key, taken from the X-Ray data.
  - A new key after each turn shows the DH ratchet stepping.
  - Tested against a real exchange (`the ratchet timeline shows a fresh sender key after every turn`).
- **Results:** Dart 107/107 passed; analyze clean.

## Attack simulator, privacy features, presentation extras (2026-10-23)

- **C7 attack simulator** (`backend/src/routes/demo.js`): the relay can be told to corrupt, duplicate,
  strip or swap what it serves.
  - The routes exist ONLY with `DEMO_ATTACKS=1`; arming needs an authenticated account; the mode is
    in-memory, so a restart disarms it. It never weakens a check — it only misbehaves where a hostile
    relay could.
  - Modes: `tamper`, `replay`, `strip_pq`, `substitute_identity`.
  - Tests: 6 relay tests (including that the switch is absent by default and that honest traffic is
    untouched) and 5 end-to-end tests where real clients refuse each attack
    (`mobile/test/demo_attack_e2e_test.dart`).
  - UI: `lib/ui/screens/attack_screen.dart` — arm an attack, then watch refusals appear.
- **Refusals are now visible.** Rejected messages used to be dropped silently. They are recorded as
  `SecurityIncident`s and posted into the chat as a notice naming the error and what it means
  (`describeRejection`). This was a real gap, not just demo dressing.
- **`refreshDevices(user)`:** re-fetch a contact's keys, ignoring the directory cache. Needed because a
  substituted key is only observable on a real lookup — a finding from writing the attack test.
- **C8 network inspector** (`lib/ui/screens/network_screen.dart`): every relay request with status,
  byte counts and duration. Records no headers (tokens) and no bodies.
- **D11 view-once messages:** a composer toggle; the reader sees it once, then the copy on that device is
  erased and the erasure persisted. The app states plainly that this cannot stop a screenshot and that
  the sender keeps their own copy.
- **D16 "harvest now, decrypt later" card** in *What HELO protects*: which layer resists it (session
  setup) and which do not (the ratchet, and all metadata).
- **E17 demo run sheet** (`lib/ui/screens/demo_script_screen.dart`): ten steps with one line to say for
  each and a button that opens the right screen.
- **E18 measured numbers in the app** (`lib/research_numbers.dart`): figures quoted in the UI are copied
  from `research/results/*.json`, and `test/research_numbers_test.dart` fails if they drift from the
  experiment output.
- **Demo users renamed:** the demo prints `User 1`, `User 2`, … and the Crypto Lab says "user 1"/"user 2"
  instead of personal names. Alice/Bob remain only as standard protocol notation in PROTOCOL.md.
- **Results:** `verify.py` 436/436, 10/10 suites.

## Android APK (2026-10-24)

- **Built in CI, not here:** this machine has no Android SDK or adb, so `.github/workflows/android-build.yml`
  (manual trigger) builds `app-release.apk` on a GitHub runner and uploads it as `helo-android-apk`.
  Signed with Flutter's debug key: sideloadable, not distributable.
- **Relay address is now settable** (`lib/data/relay_address.dart`, stored under `StorageKeys.relayUrl`):
  a packaged app cannot guess the address of a relay on someone's laptop. Only offered before the
  device registers, since sessions and prekeys live on one relay. Validation accepts a bare origin
  only — no path, query, fragment or credentials (tested).
- **Cleartext, and the warning that goes with it:** the APK permits cleartext HTTP because the demo
  relay serves plain HTTP by design. When the configured relay is `http://` and not loopback, the
  first screen warns that metadata and the device bearer token are exposed on that network
  (`relayTransportIsExposed`, tested). Message content is unaffected.
- **`run_demo.py --relay-lan`** binds the relay to 0.0.0.0 so a packaged app can reach it, and prints
  the address plus that warning. Browsers should still use `--lan` (HTTPS proxy, relay stays loopback).
- **Not verified:** no APK has been built or installed from here — no SDK. The workflow is unrun.

## Relay in Docker Desktop (2026-10-24)

- **`docker/docker-compose.local.yml`** runs the relay alone on `127.0.0.1:8443` with the deployment's
  hardening, for laptops. The existing `docker-compose.yml` still needs a domain for Caddy/TLS.
- **`run_demo.py --external-relay`** serves the web client against a relay someone else started, instead
  of spawning one. Flags that belong to the relay (`--fresh`, `--attacks`, `--relay-lan`) are ignored
  with a notice rather than silently doing nothing.
- **Verified on this machine:** image built (its 51 relay tests ran in the build), container reports
  healthy, read-only rootfs, `cap_drop: ALL`, `no-new-privileges`, uid 10001, 512 MB cap; web client
  served on both ports against it; CORS allows the demo origins and refuses others; the upload
  preflight permits `X-Helo-Recipients`; `DEMO_ATTACKS=1` passes through (the demo route answers 401,
  not 404).

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
