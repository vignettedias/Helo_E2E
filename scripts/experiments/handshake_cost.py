#!/usr/bin/env python3
"""Experiment E2 — cost of hybrid PQXDH vs classical X3DH.

Measures, with the Python reference implementation (pyca/cryptography,
OpenSSL ML-KEM-768):

  time   initiator (bundle verify + DH + encapsulate + first encrypt) and
         responder (decapsulate + DH + first decrypt), N runs each
  bytes  prekey bundle JSON as served, first-message envelope JSON, and the
         prekey upload a device makes (default batch sizes)

SCOPE: reference-implementation timings on this machine. They show the
RELATIVE cost of adding ML-KEM; they are not mobile or Dart figures (see the
warning in scripts/benchmark.py).

    python scripts/experiments/handshake_cost.py [--runs 300]
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "crypto" / "reference"))

from helo_ref.identity import IdentityKeyPair
from helo_ref.message import Envelope
from helo_ref.pqxdh import PQXDH
from helo_ref.prekeys import (
    ONE_TIME_PREKEY_BATCH,
    PQ_ONE_TIME_PREKEY_BATCH,
    PreKeyBundle,
    PreKeyStore,
)
from helo_ref.session import start_as_initiator, start_as_responder
from helo_ref.x3dh import ClassicalX3DH

OUT = REPO / "research" / "results" / "handshake_cost.json"


def compact(obj) -> int:
    return len(json.dumps(obj, separators=(",", ":")).encode())


def fresh_bob(pq: bool):
    bob = IdentityKeyPair.generate()
    store = PreKeyStore(bob)
    store.rotate_signed_prekey()
    store.generate_one_time_prekeys(1)
    if pq:
        store.rotate_pq_last_resort()
        store.generate_pq_one_time_prekeys(1)
    return bob, store


def summary(samples: list[float]) -> dict:
    s = sorted(samples)
    return {"n": len(s), "median_ms": round(statistics.median(s), 3),
            "mean_ms": round(statistics.mean(s), 3),
            "p95_ms": round(s[max(0, int(len(s) * 0.95) - 1)], 3),
            "min_ms": round(s[0], 3)}


def measure(pq: bool, runs: int) -> dict:
    kex = PQXDH() if pq else ClassicalX3DH()
    alice = IdentityKeyPair.generate()
    init_t, resp_t = [], []
    bundle_bytes = first_bytes = header_bytes = 0
    for i in range(runs + 3):  # 3 warm-up runs, discarded
        bob, store = fresh_bob(pq)
        bundle_json = store.publish_bundle("bob").to_json()
        bundle = PreKeyBundle.from_json(bundle_json)

        t0 = time.perf_counter()
        a = start_as_initiator(alice, "alice", bundle, kex=kex)
        first = a.encrypt(b"hello")
        t1 = time.perf_counter()
        env_json = first.to_json()
        received = Envelope.from_json(env_json)
        t2 = time.perf_counter()
        b = start_as_responder(bob, "bob", store, received, accept_classical=not pq)
        assert b.decrypt(received) == b"hello"
        t3 = time.perf_counter()

        if i >= 3:
            init_t.append((t1 - t0) * 1000)
            resp_t.append((t3 - t2) * 1000)
        bundle_bytes = compact(bundle_json)
        first_bytes = compact(env_json)
        header_bytes = compact(env_json.get("x3dh"))
    return {"kex": "pqxdh-mlkem768" if pq else "x3dh-classical",
            "initiator": summary(init_t), "responder": summary(resp_t),
            "bundle_json_bytes": bundle_bytes, "first_envelope_json_bytes": first_bytes,
            "x3dh_header_json_bytes": header_bytes}


def upload_bytes(pq: bool) -> int:
    bob = IdentityKeyPair.generate()
    store = PreKeyStore(bob)
    body = {"signed_prekey": store.rotate_signed_prekey().to_json(),
            "one_time_prekeys": [k.to_json() for k in store.generate_one_time_prekeys(ONE_TIME_PREKEY_BATCH)]}
    if pq:
        body["pq_last_resort"] = store.rotate_pq_last_resort().to_json()
        body["pq_one_time_prekeys"] = [k.to_json() for k in
                                       store.generate_pq_one_time_prekeys(PQ_ONE_TIME_PREKEY_BATCH)]
    return compact(body)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=300)
    args = ap.parse_args()

    try:
        from cryptography.hazmat.backends.openssl.backend import backend
        openssl = backend.openssl_version_text()
    except Exception:
        openssl = "?"
    results = {"experiment": "E2 hybrid vs classical handshake cost",
               "environment": {"python": platform.python_version(), "openssl": openssl,
                               "machine": platform.machine(), "os": f"{platform.system()} {platform.release()}"},
               "runs": args.runs,
               "classical": measure(False, args.runs),
               "hybrid": measure(True, args.runs),
               "prekey_upload_json_bytes": {
                   "classical": upload_bytes(False), "hybrid": upload_bytes(True),
                   "batch": {"one_time": ONE_TIME_PREKEY_BATCH, "pq_one_time": PQ_ONE_TIME_PREKEY_BATCH}}}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8", newline="\n")

    c, h = results["classical"], results["hybrid"]
    print("| measure | classical X3DH | hybrid PQXDH | ratio |")
    print("|---|---:|---:|---:|")
    for label, key in (("initiator median (ms)", ("initiator", "median_ms")),
                       ("initiator p95 (ms)", ("initiator", "p95_ms")),
                       ("responder median (ms)", ("responder", "median_ms")),
                       ("responder p95 (ms)", ("responder", "p95_ms"))):
        cv, hv = c[key[0]][key[1]], h[key[0]][key[1]]
        print(f"| {label} | {cv} | {hv} | {hv / cv:.2f}x |")
    for label, key in (("prekey bundle (B)", "bundle_json_bytes"),
                       ("first envelope (B)", "first_envelope_json_bytes"),
                       ("x3dh header (B)", "x3dh_header_json_bytes")):
        print(f"| {label} | {c[key]} | {h[key]} | {h[key] / c[key]:.2f}x |")
    u = results["prekey_upload_json_bytes"]
    print(f"| prekey upload (B) | {u['classical']} | {u['hybrid']} | {u['hybrid'] / u['classical']:.2f}x |")
    print(f"\nwrote {OUT.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
