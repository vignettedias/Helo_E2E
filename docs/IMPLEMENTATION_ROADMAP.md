# HELO 2.0 Implementation Roadmap

Live tracker. Statuses use exactly these labels:
**IMPLEMENTED AND TESTED · IMPLEMENTED BUT NOT FULLY TESTED · PARTIALLY
IMPLEMENTED · EXPERIMENTAL · PLANNED · BLOCKED · NOT VERIFIED**

---

## Phase order (and why it differs from the brief)

The brief orders phases app-first (auth → messaging UX → E2EE → attachments →
privacy → PQ → groups). Here the **wire-format pieces come first**: PQXDH,
padding and attachment STREAM encryption change what every app feature puts on
the wire. Building them first — in the normative Python reference, with
vectors, then in the Dart port — means the messaging layer is written once, on
the final formats, instead of being reworked. E2EE is not a later phase here: it
already exists, and no feature is ever allowed to bypass it.

| Phase | Content | Depends on |
|---|---|---|
| 0 | Audit, baseline, docs | — |
| 1 | Stabilization: sender-binding fix (A1), demo `--lan` fix (A3), relay migrations framework | 0 |
| 2 | Protocol v2 in reference + Dart: PQXDH hybrid, padding, STREAM attachments, vectors | 1 |
| 3 | Relay v2 API: directory, device-bound send, batch, long-poll, PQ prekeys, attachments, blocks, reports, presence, settings, password change, security events | 1 |
| 4 | Client domain: Messenger, Directory, LocalStore, payload kinds (msg/react/edit/del/rcpt/typing/profile/timer), fan-out, outbox/retry | 2, 3 |
| 5 | UI: responsive shell, chat UX, settings, security panels, light/dark | 4 |
| 6 | Attachments end-to-end (pick, encrypt, upload, download, preview) | 2, 3, 4 |
| 7 | Groups (pairwise fan-out, admin-authorized state) | 4 |
| 8 | Privacy: presence/receipt/typing controls, metadata inventory + experiments | 3, 4 |
| 9 | Verification runner (JSON) + dashboard | all tests |
| 10 | Benchmarks, research results, documentation pass | all |

## Files by phase

| Phase | Primary files |
|---|---|
| 1 | `backend/src/server.js`, `backend/src/db.js` (migrations), `scripts/integration_e2e.py`, `scripts/run_demo.py` |
| 2 | `crypto/reference/helo_ref/{pqxdh,padding,attachment}.py`, `x3dh.py`, `prekeys.py`, `session.py`; `mobile/lib/crypto/{pqxdh,padding,attachment}.dart`; `scripts/generate_test_vectors.py`; tests |
| 3 | `backend/src/*`, `backend/test/*` |
| 4 | `mobile/lib/domain/*`, `mobile/lib/protocol/*`, `mobile/lib/data/relay_client.dart`, tests |
| 5 | `mobile/lib/ui/**` |
| 6–7 | `mobile/lib/domain/{attachments,groups}.dart`, UI |
| 8 | `scripts/experiments/*`, `research/*` |
| 9 | `scripts/verify.py`, `reports/`, dashboard |

## Tests required per phase

| Phase | Tests |
|---|---|
| 1 | relay: forged sender rejected; migration from a v1 database preserves data |
| 2 | Python: PQXDH valid/invalid/tamper/downgrade/version mismatch; padding boundaries; STREAM tamper/truncate/reorder; vectors. Dart: conformance against those vectors incl. OpenSSL-generated ML-KEM data |
| 3 | relay: every new route incl. authorization failures, long-poll wake-up, attachment cross-user access, block enforcement, password change revocation |
| 4 | Dart: payload codec, author-only edit/delete, receipts, dedupe, outbox retry without re-encryption, restart persistence |
| 5 | widget smoke tests |
| 6 | Dart + relay: upload/download/authorization/tamper |
| 7 | Dart: unauthorized membership change rejected, removed member excluded, new member gets no history |
| 8 | experiment scripts produce reports from real runs |
| 9 | runner emits JSON for every suite; dashboard renders only from that JSON |

## Feature status

| # | Feature | Status | Evidence |
|---|---|---|---|
| 1 | Registration | IMPLEMENTED AND TESTED | relay auth tests; `relay.user()` in every Dart test |
| 2 | Login | IMPLEMENTED AND TESTED | relay auth tests |
| 3 | Logout (incl. logout everywhere) | IMPLEMENTED AND TESTED | `logout-all revokes every session of the account` |
| 4 | Profiles (display name) | IMPLEMENTED AND TESTED | `profiles travel end to end and appear at the contact` |
| 5 | Avatars | IMPLEMENTED BUT NOT FULLY TESTED | sent inside the E2EE profile payload; no test covers the image path |
| 6 | Username discovery (exact match, no search) | IMPLEMENTED AND TESTED | `the directory resolves usernames to active devices, exact match only` |
| 7 | Contacts | PARTIALLY IMPLEMENTED | contacts are the people you have chats with; there is no address book |
| 8 | One-to-one conversations | IMPLEMENTED AND TESTED | `two users exchange messages over a hybrid PQXDH session` |
| 9 | Real-time messaging | IMPLEMENTED AND TESTED | long-poll (`a long-poll returns as soon as a message is queued`); browser check |
| 10 | Offline delivery | IMPLEMENTED AND TESTED | `a relay outage queues ciphertext…`, queued delivery e2e |
| 11 | Encrypted history | IMPLEMENTED AND TESTED | restart test (sealed local store) |
| 12 | Sent / delivered / read | IMPLEMENTED AND TESTED | `status goes sent → delivered → read…` |
| 13 | Typing indicators | IMPLEMENTED AND TESTED | `typing indicators propagate…` |
| 14 | Presence (online / last seen) | IMPLEMENTED AND TESTED | `presence honours the target settings and is reciprocal` |
| 15 | Replies | IMPLEMENTED AND TESTED | Dart round-trip + `reply from the sheet sends a quoted message` |
| 16 | Reactions | IMPLEMENTED AND TESTED | Dart round-trip + `reacting from the sheet reaches the other side` |
| 17 | Editing | IMPLEMENTED AND TESTED | `edits and deletions apply, and only the author can make them` |
| 18 | Deleting (for me / for everyone) | IMPLEMENTED AND TESTED | same + `delete for everyone asks first…` |
| 19 | Forwarding | IMPLEMENTED AND TESTED | `replies, reactions and forwarding round-trip` |
| 20 | Message search | IMPLEMENTED AND TESTED | `search finds messages across conversations` |
| 21 | Conversation search | IMPLEMENTED BUT NOT FULLY TESTED | chat-list filter; browser only |
| 22 | Pinned conversations | IMPLEMENTED AND TESTED | `pinning, archiving and muting…` |
| 23 | Archived conversations | IMPLEMENTED AND TESTED | same |
| 24 | Muting | IMPLEMENTED AND TESTED | same (mutation-checked) |
| 25 | Blocking | IMPLEMENTED AND TESTED | relay + Dart blocking tests |
| 26 | Reporting | IMPLEMENTED AND TESTED | `reports accept a fixed reason vocabulary and carry no message content` |
| 27 | Disappearing messages | IMPLEMENTED AND TESTED | `disappearing messages are removed on both sides after the timer` |
| 28–29 | Image / document attachments | IMPLEMENTED AND TESTED | STREAM tests + `attachments are encrypted on the device…`; the UI file picker was not driven in the browser |
| 30–31 | Audio / video attachments | IMPLEMENTED BUT NOT FULLY TESTED | in-app player (`video_player`); delivery tested; playback not yet checked in a real browser |
| 32 | Voice messages | IMPLEMENTED BUT NOT FULLY TESTED | `record` (AAC, or 16 kHz WAV on Chrome/Firefox), 5 min cap; voice payload, forwarding and UI tested; real microphone not yet checked |
| 33–35 | Groups, admins, membership | IMPLEMENTED AND TESTED | group fan-out, non-admin forgery, removal and new-member tests |
| 36 | Invitations | IMPLEMENTED AND TESTED | invite links (`an invite link lets someone join; guessed and revoked links do not`, mutation-checked), strict parsing test; UI not checked by hand |
| 37 | Group pictures | IMPLEMENTED BUT NOT FULLY TESTED | carried in the admin-authorised group snapshot; no test covers the image |
| 38 | Device & session management | PARTIALLY IMPLEMENTED | device list, revoke, logout-all tested; a user's own devices do not sync history with each other |
| 39 | Identity verification | IMPLEMENTED AND TESTED (per device) | `safety numbers match on both sides and verification is per device`; QR scan: `scanning a contact's code verifies exactly that device…`, `qr_check` vectors, image decode tests; live camera not yet checked |
| 40 | Security notifications | IMPLEMENTED BUT NOT FULLY TESTED | relay security events; in-chat notices for new or conflicting devices |
| 41 | Privacy settings | IMPLEMENTED AND TESTED | presence, receipts and typing opt-outs tested |
| 42 | Notification settings | PARTIALLY IMPLEMENTED | in-app banners and previews only; no push service |
| 43 | Secure configuration | IMPLEMENTED BUT NOT FULLY TESTED | `.env.example`, CORS allowlist, HTTPS `--lan` demo with loopback-only proxy trust (relay test + `scripts/lan_smoke.py`) |
| 44 | Responsive UI | IMPLEMENTED BUT NOT FULLY TESTED | checked in the browser at 375 px, 800 px and 1400 px, light and dark |
| 45 | Error handling & recovery | IMPLEMENTED BUT NOT FULLY TESTED | outage, token renewal and relay-reset messages tested or checked by hand |
| R-A | Hybrid PQ key establishment | IMPLEMENTED AND TESTED — EXPERIMENTAL | C15/C16 in SECURITY_CLAIMS.md; not formally analysed; ratchet stays classical |
| R-B | Measurable metadata protection | IMPLEMENTED AND TESTED | padding policies + E1/E3 in `research/RESULTS.md` |
| R-C | Automated verification dashboard | IMPLEMENTED AND TESTED | `scripts/verify.py` → `reports/`, shown in the app (checked in the browser) |
