#!/usr/bin/env python3
"""Protocol benchmarks.

SCOPE WARNING -- read before quoting any number from this script.

These figures are measured on the REFERENCE PYTHON IMPLEMENTATION running on a
general-purpose machine. They are useful for two things:

  1. relative cost between protocol operations (is the DH ratchet 10x or 1000x
     a symmetric step?), and
  2. regression detection in CI.

They are NOT mobile performance figures and must never be presented as such.
Python's interpreter overhead dominates several of these measurements, and
mobile devices differ in CPU, thermal budget, and hardware crypto acceleration.
Mobile numbers require running the equivalent harness on a physical handset
through the Flutter client, recorded separately in docs/benchmarks/.
"""

from __future__ import annotations

import json
import platform
import statistics
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "crypto" / "reference"))

from helo_ref.identity import IdentityKeyPair
from helo_ref.message import Envelope
from helo_ref.prekeys import PreKeyStore
from helo_ref.session import start_as_initiator, start_as_responder


def bench(label: str, fn, iterations: int) -> dict:
    fn()  # warm up
    samples = []
    for _ in range(iterations):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000.0)
    samples.sort()
    return {
        "operation": label,
        "iterations": iterations,
        "mean_ms": round(statistics.mean(samples), 4),
        "median_ms": round(statistics.median(samples), 4),
        "p95_ms": round(samples[int(len(samples) * 0.95) - 1], 4),
        "min_ms": round(samples[0], 4),
        "max_ms": round(samples[-1], 4),
    }


def make_pair():
    bob_id = IdentityKeyPair.generate()
    bob_pk = PreKeyStore(bob_id)
    bob_pk.rotate_signed_prekey()
    bob_pk.generate_one_time_prekeys(50)
    bundle = bob_pk.publish_bundle("bob-device")

    alice_id = IdentityKeyPair.generate()
    alice = start_as_initiator(alice_id, "alice-device", bundle)
    first = alice.encrypt(b"bootstrap")
    bob = start_as_responder(bob_id, "bob-device", bob_pk, first)
    bob.decrypt(first)
    alice.decrypt(bob.encrypt(b"ack"))
    return alice, bob


def main() -> int:
    results = []

    results.append(bench("identity_key_generation", IdentityKeyPair.generate, 200))

    bob_id = IdentityKeyPair.generate()
    store = PreKeyStore(bob_id)
    store.rotate_signed_prekey()
    results.append(bench("signed_prekey_rotation", store.rotate_signed_prekey, 200))
    results.append(
        bench("one_time_prekey_x100",
              lambda: PreKeyStore(bob_id).generate_one_time_prekeys(100), 20)
    )

    store.generate_one_time_prekeys(5000)
    bundle = store.publish_bundle("bob-device")
    alice_id = IdentityKeyPair.generate()
    results.append(
        bench("x3dh_session_establishment_initiator",
              lambda: start_as_initiator(alice_id, "alice-device", bundle), 200)
    )
    results.append(bench("prekey_bundle_verification", bundle.verify, 500))

    alice, bob = make_pair()
    payload = b"A" * 256
    results.append(bench("message_encrypt_256B", lambda: alice.encrypt(payload), 500))

    # Decryption on a steady chain (no DH ratchet).
    def encrypt_then_decrypt():
        env = alice.encrypt(payload)
        bob.decrypt(Envelope.from_json(env.to_json()))

    results.append(bench("encrypt_decrypt_roundtrip_256B", encrypt_then_decrypt, 300))

    # DH ratchet step: forced by alternating direction.
    def dh_ratchet_step():
        a, b = make_pair()
        b.decrypt(a.encrypt(payload))
        a.decrypt(b.encrypt(payload))

    results.append(bench("dh_ratchet_step_pair", dh_ratchet_step, 60))

    # Ciphertext expansion (deterministic, not timing).
    a2, b2 = make_pair()
    expansion = []
    for size in (0, 64, 256, 1024, 4096, 16384):
        env = a2.encrypt(b"A" * size)
        b2.decrypt(Envelope.from_json(env.to_json()))
        expansion.append({
            "plaintext_bytes": size,
            "ciphertext_bytes": len(env.ciphertext),
            "header_bytes": 41,
            "total_overhead_bytes": len(env.ciphertext) - size + 41,
        })

    report = {
        "disclaimer": (
            "Reference Python implementation on a general-purpose machine. "
            "NOT mobile performance. Do not quote as such."
        ),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "processor": platform.processor() or "unknown",
        },
        "timings": results,
        "ciphertext_expansion": expansion,
    }

    out = REPO / "docs" / "benchmarks" / "reference-implementation.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n")

    print(f"{'operation':<40} {'median ms':>10} {'p95 ms':>10}")
    print("-" * 62)
    for r in results:
        print(f"{r['operation']:<40} {r['median_ms']:>10.4f} {r['p95_ms']:>10.4f}")
    print()
    print(f"{'plaintext':>10} {'ciphertext':>12} {'overhead':>10}")
    print("-" * 34)
    for e in expansion:
        print(f"{e['plaintext_bytes']:>10} {e['ciphertext_bytes']:>12} "
              f"{e['total_overhead_bytes']:>10}")
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
