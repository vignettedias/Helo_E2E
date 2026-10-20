#!/usr/bin/env python3
"""Smoke-test a running `run_demo.py --lan` from this or another machine.

    python scripts/run_demo.py --fresh --lan      # in one terminal
    python scripts/lan_smoke.py 192.168.1.20      # the address it printed

Checks, through the HTTPS proxy exactly as a phone would see it: the web app
is served, the relay API is reachable on the same origin, two clients
establish a PQXDH session and exchange messages, long-polling works, and the
registration rate limit still applies per client behind the proxy.

Certificate verification is OFF here on purpose: the demo certificate is
self-signed. Never copy that into anything that talks to a real server.
Uses up to 5 registrations of the relay's per-client limit (3/hour): run it
against a fresh demo, and register your phone/browser users from other devices.
"""
import json
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "crypto" / "reference"))
sys.path.insert(0, str(REPO / "scripts"))

import integration_e2e as e2e

HOST = sys.argv[1] if len(sys.argv) > 1 else "localhost"
CTX = ssl._create_unverified_context()  # self-signed demo certificate (test only)


class LanRelay(e2e.Relay):
    def __init__(self, port):
        self.port = port

    @property
    def base(self):
        return f"https://{HOST}:{self.port}"

    def request(self, method, path, body=None, token=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=60, context=CTX) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")


def page(port, path="/"):
    with urllib.request.urlopen(f"https://{HOST}:{port}{path}", timeout=10, context=CTX) as r:
        return r.status, r.headers.get("Content-Type"), r.read()


ok = True


def check(label, cond):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + label)


st, ct, body = page(5000)
check(f"web app served over HTTPS at {HOST}:5000 ({ct})", st == 200 and b"flutter" in body.lower())
st, ct, _ = page(5001, "/main.dart.js")
check("second origin (:5001) serves the app script as JavaScript", st == 200 and "javascript" in ct)
st, _, body = page(5000, "/health")
check("relay /health reachable through the same origin", st == 200 and json.loads(body)["status"] == "ok")

alice = e2e.Client(LanRelay(5000), "alice", "alice-phone")
bob = e2e.Client(LanRelay(5001), "bob", "bob-laptop")
for c in (alice, bob):
    c.register()
    c.publish_prekeys()
check("both users registered and published PQ prekeys via the proxy", alice.pq_available == 5)

alice.start_session_with("bob-laptop")
alice.send("bob-laptop", b"hello from the phone")
got = bob.receive()
check("PQXDH message phone -> laptop delivered and decrypted", got == [("alice-phone", b"hello from the phone")])
bob.send("alice-phone", b"hi phone")
check("reply laptop -> phone", alice.receive() == [("bob-laptop", b"hi phone")])

t = time.time()
st, body = alice.relay.request("GET", "/messages?wait=2", token=alice.device_token)
check(f"long-poll held through the proxy (~{time.time() - t:.1f}s, empty)", st == 200 and time.time() - t >= 1.5)

# Rate limits stay per client: this script is ONE client (one IP), so its 4th
# registration within the hour must be refused even though all requests reach
# the relay from 127.0.0.1 via the proxy.
codes = [LanRelay(5000).request("POST", "/auth/register",
                                {"username": f"extra{i}", "password": "correct-horse-battery"})[0]
         for i in range(3)]
check(f"registration rate limit still applies per client (codes {codes})", 429 in codes)
print("ALL PASS" if ok else "SOME FAILED")
sys.exit(0 if ok else 1)
