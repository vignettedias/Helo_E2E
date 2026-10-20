# Running Helo

Each part can be run independently. **Start with §1** — it verifies the
cryptography without needing Docker, Flutter, or a network. **§4 is the
quickest way to see the app itself.**

---

## Quick start (60 seconds)

```bash
pip install cryptography pytest hypothesis
python3 -m pytest -q                      # 221 tests
python3 scripts/integration_e2e.py        # real relay + database inspection
```

Everything at once, with a report: `python scripts/verify.py` writes `reports/verification.json` and
`reports/dashboard.html`. See [docs/TESTING.md](docs/TESTING.md).

The second command is the one worth watching. It starts the real relay,
drives it with the real client over HTTP, then opens the relay's SQLite file and
scans the raw bytes for your plaintext and every private key. Requires Node 22+.

---

## 1. Protocol tests (Python)

**Requires:** Python 3.11+

```bash
pip install cryptography pytest hypothesis

python3 -m pytest -q                       # all 99
python3 -m pytest tests/unit -q            # 47
python3 -m pytest tests/adversarial -q     # 29 — active attacker
python3 -m pytest tests/property -q        # 13 — Hypothesis
python3 -m pytest tests/integration -q     # 10 — vector conformance
```

Test vectors and benchmarks:

```bash
python3 scripts/generate_test_vectors.py           # regenerate
python3 scripts/generate_test_vectors.py --check    # byte-exact reproducibility
python3 scripts/benchmark.py                        # measured performance
```

`--check` failing means the protocol's derived keys changed. That may be
intentional, but it must never happen silently.

---

## 2. Relay backend (Node)

**Requires:** Node 22.5+ (uses `node:sqlite`). **Zero npm dependencies** — there
is nothing to install.

```bash
cd backend
node --test test/relay.test.js      # 25 tests
```

Run it:

```bash
cd backend
mkdir -p data
PORT=8443 DB_PATH=./data/helo.db node src/server.js
```

```bash
curl -s localhost:8443/health
```

The relay speaks **plain HTTP by design** — terminate TLS in front of it.

**Browser clients and CORS.** CORS is off by default; native apps do not need
it. To let a browser build of the client call the relay, allowlist its exact
origins (no wildcard — a literal `*` is ignored):

```bash
CORS_ORIGINS=http://localhost:5000,http://localhost:5001 node src/server.js
```

CORS is not a security boundary here — authentication is a bearer token, never
a cookie — but the allowlist still keeps arbitrary sites from scripting the
relay with a token they somehow obtained.

### Try it by hand

```bash
BASE=http://localhost:8443

curl -s -X POST $BASE/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"correct-horse-battery-staple"}'

TOKEN=$(curl -s -X POST $BASE/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"correct-horse-battery-staple"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

curl -s $BASE/devices -H "Authorization: Bearer $TOKEN"
```

Try sending an envelope with an extra field — the relay rejects unknown fields
rather than storing them:

```bash
curl -s -X POST $BASE/messages -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"recipient_device_id":"x","envelope":{"v":1,"type":"normal",
       "session_id":"abc","sender_device_id":"y","header":"AA==",
       "ciphertext":"AAAA","preview":"hi bob"}}'
# -> {"error":"validation_failed","field":"preview", ...}
```

---

## 3. Cross-stack end-to-end

**Requires:** Python 3.11+ **and** Node 22.5+. Starts and stops the relay itself.

```bash
python3 scripts/integration_e2e.py
```

Ten sections: registration, async session establishment with the recipient
offline, bidirectional messaging, offline queue, safety numbers, **server
compromise simulation** (opens the SQLite file and scans raw bytes including WAL
remnants), an honest enumeration of what the relay *did* learn, ciphertext
tampering, and replay.

Exit code 0 means all 24 checks passed.

---

## 4. Web demo

**Requires:** Flutter 3.22+, Python 3.11+, Node 22.5+. No Android SDK, Xcode or
Visual Studio needed — the client runs in the browser.

```bash
cd mobile && flutter build web && cd ..
python3 scripts/run_demo.py --fresh
```

`run_demo.py` starts the real relay (with a CORS allowlist for exactly the demo
origins) and serves the web build on two ports:

| Tab | URL |
|---|---|
| Alice | http://localhost:5000 |
| Bob | http://localhost:5001 |

Each port is a separate browser origin, so each tab has its own key storage —
two genuinely different devices in one browser. Then:

1. Create an account in each tab (password 12+ characters).
2. In Alice's tab, tap **New chat** and enter `bob`. Bob does not need to be online. The chat header
   shows **PQ hybrid**: the session was set up with X25519 + ML-KEM-768.
3. Message back and forth. Tap, long-press or right-click a message for reply, react, copy, forward,
   edit (your own, within 15 min), message info and delete. Reload either tab: identity, sessions and
   history are restored from encrypted storage.
4. Try a group (the people icon at the top), the **Details & security** panel (ⓘ), dark mode and
   privacy settings (avatar menu → **Settings & privacy**), and disappearing messages (chat details).
5. Compare safety numbers in both tabs' details panels, then mark the device verified.
6. **Settings → Verification dashboard** shows the last `scripts/verify.py` run, served at
   `/verification.json`.

Options:
- `--build` runs `flutter build web` first.
- `--ports` changes or adds ports.
- `--fresh` empties the relay database. Clear the tabs' site data as well, or they will hold identities
  the new relay has never seen; the app then says so and offers **Settings → Account → Reset this device**.
- `--lan` makes the demo reachable from a phone on the same Wi-Fi (next section).

### On your phone (`--lan`)

```bash
python scripts/run_demo.py --fresh --lan
```

- **What it does:**
  - serves the app over **HTTPS**, with a self-signed certificate made for this PC's addresses and stored
    in `backend/data/demo-tls/`;
  - forwards the relay API on that same HTTPS origin, while the relay itself still listens on 127.0.0.1
    only.
- **Why HTTPS:** phones' browsers allow the key store, camera and microphone only on HTTPS pages.
- **Steps:**
  1. Connect the phone to the **same Wi-Fi** as the PC.
  2. Open the `https://<address>:5000` URL printed by the script in Chrome (Android) or Safari (iPhone).
     Use the address of the PC's "Wireless LAN adapter Wi-Fi" in `ipconfig`.
  3. Get past the one-time certificate warning:
     - **Chrome:** *Advanced → Proceed to … (unsafe)*.
     - **Safari:** *Show Details → visit this website*.

     This is expected for a self-signed demo certificate. It is never acceptable for a real deployment.
  4. Register on the phone, register a second user on the PC (`https://localhost:5001`), and chat.
- **If the phone cannot connect:**
  - When Windows asks, allow **Python** through the firewall on **Private** networks. To check later:
    Windows Security → Firewall → Allow an app.
  - Make sure the Wi-Fi is set to *Private*, not *Public*.
  - Some campus or guest networks block device-to-device traffic. A phone hotspot shared with the PC
    works instead.
- **Self-test from the PC** (uses this PC's registration quota, so restart the demo with `--fresh`
  afterwards):

```bash
python scripts/lan_smoke.py 192.168.1.20
```

  Use the address the demo printed. It checks the page, the proxied API, a PQXDH conversation,
  long-polling and per-client rate limiting.

The web build stores keys via `flutter_secure_storage`'s browser backend —
encrypted under a WebCrypto key kept in the same browser. That is fine for a
demo and much weaker than a phone keystore; see README → Known limitations.

---

## 5. Flutter client

**Requires:** Flutter 3.22+

```bash
cd mobile
flutter pub get
flutter test          # 93 tests (needs node on PATH: they start the real relay)
flutter analyze
```

The test files:
- `test/vector_conformance_test.dart` and `test/protocol_v2_conformance_test.dart` replay the vectors
  the Python reference generates, including PQXDH, padding and attachments. If a single derived byte
  differs, they fail. That is the mechanism that makes the port verifiable rather than merely plausible.
- `test/messenger_test.dart` drives real `Messenger` instances through the **real relay process**:
  - PQXDH;
  - groups;
  - receipts;
  - edits;
  - outages;
  - restarts;
  - downgrade refusal.
- `test/chat_view_test.dart` drives the chat screen the same way.

Platform projects for Android, iOS, web and Windows are generated. Building for
Android needs the Android SDK; Windows desktop needs Visual Studio with the
"Desktop development with C++" workload and Windows Developer Mode (plugins
are linked by symlink).

Run the app against a local relay:

```bash
# Android emulator (10.0.2.2 reaches the host machine)
flutter run --dart-define=HELO_RELAY_URL=http://10.0.2.2:8443

# iOS simulator / desktop
flutter run --dart-define=HELO_RELAY_URL=http://localhost:8443

# Real device on your LAN
flutter run --dart-define=HELO_RELAY_URL=http://192.168.1.50:8443
```

Without `--dart-define`, the app picks a default: `10.0.2.2` on Android, the
page's own host on the web, `localhost` elsewhere.

**Two devices, one relay:** run the relay on your machine, launch the app on two
emulators or devices, create two accounts. Each shows its device id on the
conversation list — copy one into the other's **New chat** dialog.

Note the app never asks for a contact's key. It fetches the prekey bundle from
the relay and verifies the signatures itself; a relay that substitutes keys is
rejected before any private key is touched.

---

## 6. Deployment (Docker)

**Requires:** Docker with Compose v2, and a domain pointing at the host.

```bash
cd docker
RELAY_DOMAIN=relay.example.com docker compose up -d --build
docker compose logs -f relay
```

Caddy obtains TLS certificates automatically. The relay runs read-only,
non-root, with all Linux capabilities dropped, on an internal network not
reachable from outside.

TLS here protects **metadata** in transit and authenticates the server. It
contributes nothing to message confidentiality — a fully compromised TLS
terminator still sees only ciphertext.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `ModuleNotFoundError: helo_ref` | Run pytest from the repo root; `tests/conftest.py` sets the path |
| `node:sqlite` not found | Node < 22.5. Check `node --version` |
| Relay tests fail on ports | Another process on the ephemeral port; rerun |
| `--check` reports a vector diff | Derived keys changed — review the diff before committing |
| Flutter: vector file missing | Run `python3 scripts/generate_test_vectors.py` first |
| App can't reach relay | Emulator needs `10.0.2.2`, not `localhost` |
| Relay returns 429 | Rate limiting working as intended; wait |
| Web demo: "too many attempts" on sign-up | Registration allows 3 per hour per IP; restart `run_demo.py` (limits are in memory) |
| Web demo: "Could not reach the relay" | Relay not running, or the page origin is not in `CORS_ORIGINS` |
| Web demo: "relay no longer recognises this device" | Relay database was reset; use **Settings → Account → Reset this device** in that tab |
| Web demo: both tabs are the same user | Same origin — use different ports (5000 / 5001), not two tabs of one URL |

---

## What to read

| Question | File |
|---|---|
| What is actually proven? | `SECURITY_CLAIMS.md` |
| What attacks were considered? | `THREAT_MODEL.md` |
| How does the protocol work? | `PROTOCOL.md` |
| How is it structured, and why? | `ARCHITECTURE.md` |
| What does the server learn? | `PRIVACY.md` |
| How was it evaluated? | `RESEARCH_METHODOLOGY.md`, `research/` |
| What does the relay API look like? | `docs/API.md` |
| How do I run every test? | `docs/TESTING.md` |
