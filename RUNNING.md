# Running Helo

Three things can be run independently. **Start with §1** — it verifies the
cryptography without needing Docker, Flutter, or a network.

---

## Quick start (60 seconds)

```bash
pip install cryptography pytest hypothesis
python3 -m pytest -q                      # 98 tests
python3 scripts/integration_e2e.py        # real relay + database inspection
```

The second command is the one worth watching. It starts the real relay,
drives it with the real client over HTTP, then opens the relay's SQLite file and
scans the raw bytes for your plaintext and every private key. Requires Node 22+.

---

## 1. Protocol tests (Python)

**Requires:** Python 3.11+

```bash
pip install cryptography pytest hypothesis

python3 -m pytest -q                       # all 98
python3 -m pytest tests/unit -q            # 46
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
node --test test/relay.test.js      # 22 tests
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

## 4. Flutter client

> **Not verified.** This code has never been executed — the environment it was
> written in had no Dart toolchain. `flutter test` is what establishes
> conformance. Treat it as unverified until you run it.

**Requires:** Flutter 3.22+

```bash
cd mobile
flutter pub get
flutter test          # includes vector conformance against the Python reference
flutter analyze
```

`test/vector_conformance_test.dart` replays the same vectors the Python
reference generates. If a single derived byte differs, it fails. That is the
mechanism that makes the port verifiable rather than merely plausible.

Run the app against a local relay:

```bash
# Android emulator (10.0.2.2 reaches the host machine)
flutter run --dart-define=HELO_RELAY_URL=http://10.0.2.2:8443

# iOS simulator / desktop
flutter run --dart-define=HELO_RELAY_URL=http://localhost:8443

# Real device on your LAN
flutter run --dart-define=HELO_RELAY_URL=http://192.168.1.50:8443
```

**Two devices, one relay:** run the relay on your machine, launch the app on two
emulators or devices, create two accounts. Each shows its device id in
**Diagnostics** — paste one into the other's "New conversation" dialog.

Note the app never asks for a contact's key. It fetches the prekey bundle from
the relay and verifies the signatures itself; a relay that substitutes keys is
rejected before any private key is touched.

---

## 5. Deployment (Docker)

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

---

## What to read

| Question | File |
|---|---|
| What is actually proven? | `SECURITY_CLAIMS.md` |
| What attacks were considered? | `THREAT_MODEL.md` |
| How does the protocol work? | `PROTOCOL.md` |
| How is it structured, and why? | `ARCHITECTURE.md` |
| What does the server learn? | `PRIVACY.md` |
| How was it evaluated? | `RESEARCH_METHODOLOGY.md` |
