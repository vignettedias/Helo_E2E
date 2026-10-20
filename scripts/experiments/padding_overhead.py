#!/usr/bin/env python3
"""Experiment E1 — padding: bandwidth overhead vs. length leakage.

For every padding policy the client supports, this measures, over two input
length distributions:

  * overhead      padded bytes added (mean, and mean as % of the input)
  * sizes         number of distinct padded sizes the relay can observe
  * leakage_bits  Shannon entropy of the observed size, H(padded_len). Padding
                  is deterministic, so this equals the mutual information
                  I(len; padded_len): how many bits about the true length
                  the relay learns from one message. Lower is better.
  * anonymity     mean number of distinct input lengths sharing the observed
                  size (the length "anonymity set"; higher is better)

It also verifies, with the real reference Session, that the ciphertext length
on the wire depends only on the padded length (ciphertext = padded + 16-byte
tag) — i.e. that the analysis above is about what is actually sent.

Distributions (both SYNTHETIC — no corpus of real messages is used):
  uniform     every payload length 1..1024 equally likely: structural view
  short-chat  log-normal, median 48 bytes, sigma 1.0, clipped to 1..4096,
              100 000 seeded samples: a stand-in for short chat messages.
              The parameters are an assumption, not a measurement of users.

Note: in the app, the padded unit is the encoded AppPayload (JSON with id,
timestamp and kind around the body), so a body of n bytes is a payload of
roughly n + 60..120 bytes. Lengths here are payload lengths.

    python scripts/experiments/padding_overhead.py
"""

from __future__ import annotations

import json
import math
import platform
import random
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "crypto" / "reference"))

from helo_ref.identity import IdentityKeyPair
from helo_ref.message import Envelope
from helo_ref.padding import POLICIES, pad, unpad
from helo_ref.pqxdh import PQXDH
from helo_ref.prekeys import PreKeyBundle, PreKeyStore
from helo_ref.session import start_as_initiator, start_as_responder

OUT = REPO / "research" / "results" / "padding_overhead.json"
SEED = 20261016


def distributions() -> dict[str, list[int]]:
    rng = random.Random(SEED)
    short = [min(4096, max(1, round(rng.lognormvariate(math.log(48), 1.0)))) for _ in range(100_000)]
    return {"uniform_1_1024": list(range(1, 1025)), "short_chat_lognormal": short}


def entropy(counts: Counter) -> float:
    n = sum(counts.values())
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def analyse(lengths: list[int], policy) -> dict:
    padded = [len(pad(b"x" * n, policy)) for n in lengths]
    overhead = [p - n for p, n in zip(padded, lengths, strict=True)]
    by_size: dict[int, set[int]] = {}
    for n, p in zip(lengths, padded, strict=True):
        by_size.setdefault(p, set()).add(n)
    return {
        "mean_input": round(sum(lengths) / len(lengths), 2),
        "mean_padded": round(sum(padded) / len(padded), 2),
        "mean_overhead_bytes": round(sum(overhead) / len(overhead), 2),
        "mean_overhead_pct": round(100 * sum(overhead) / sum(lengths), 2),
        "max_overhead_ratio": round(max(p / n for p, n in zip(padded, lengths, strict=True)), 2),
        "distinct_sizes": len(by_size),
        "leakage_bits": round(entropy(Counter(padded)), 3),
        "mean_anonymity_set": round(sum(len(v) for v in by_size.values()) / len(by_size), 2),
    }


def wire_check(sample_lengths: list[int]) -> dict:
    """Encrypt padded payloads with a real PQXDH session; record wire sizes."""
    alice = IdentityKeyPair.generate()
    bob = IdentityKeyPair.generate()
    store = PreKeyStore(bob)
    store.rotate_signed_prekey()
    store.generate_one_time_prekeys(1)
    store.rotate_pq_last_resort()
    bundle = PreKeyBundle.from_json(store.publish_bundle("bob").to_json())
    a = start_as_initiator(alice, "alice", bundle, kex=PQXDH())
    first = Envelope.from_json(a.encrypt(b"hi").to_json())
    b = start_as_responder(bob, "bob", store, first)
    b.decrypt(first)

    rows = []
    for name, policy in POLICIES.items():
        for n in sample_lengths:
            payload = bytes(random.Random(n).randrange(256) for _ in range(n))
            env = Envelope.from_json(a.encrypt(pad(payload, policy)).to_json())
            assert unpad(b.decrypt(env)) == payload
            rows.append({"policy": name, "payload_len": n,
                         "padded_len": len(pad(payload, policy)),
                         "ciphertext_len": len(env.ciphertext),
                         "envelope_json_bytes": len(json.dumps(env.to_json(), separators=(",", ":")))})
    tag_ok = all(r["ciphertext_len"] == r["padded_len"] + 16 for r in rows)
    return {"ciphertext_equals_padded_plus_16": tag_ok, "rows": rows}


def main() -> int:
    results = {"experiment": "E1 padding overhead vs length leakage", "seed": SEED,
               "python": platform.python_version(), "distributions": {}}
    for dname, lengths in distributions().items():
        results["distributions"][dname] = {name: analyse(lengths, p) for name, p in POLICIES.items()}
    results["wire_check"] = wire_check([1, 15, 100, 255, 256, 700])

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8", newline="\n")

    for dname, table in results["distributions"].items():
        print(f"\n### {dname}\n")
        print("| policy | mean overhead (B) | overhead % | distinct sizes | leakage (bits) | mean anonymity set |")
        print("|---|---:|---:|---:|---:|---:|")
        for name, r in table.items():
            print(f"| {name} | {r['mean_overhead_bytes']} | {r['mean_overhead_pct']} | "
                  f"{r['distinct_sizes']} | {r['leakage_bits']} | {r['mean_anonymity_set']} |")
    print(f"\nciphertext == padded + 16 for every sample: {results['wire_check']['ciphertext_equals_padded_plus_16']}")
    print(f"wrote {OUT.relative_to(REPO)}")
    return 0 if results["wire_check"]["ciphertext_equals_padded_plus_16"] else 1


if __name__ == "__main__":
    sys.exit(main())
