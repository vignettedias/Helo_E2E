#!/usr/bin/env python3
"""Generate deterministic cross-implementation test vectors.

WHY THIS EXISTS
---------------
A second implementation of a protocol is almost never wrong in a way that
makes it crash. It is wrong in a way that makes it derive a *different* key
while looking perfectly healthy in isolation -- a swapped DH order, a missing
0xFF prefix, a different HKDF info string, big-endian vs little-endian
counters. Alice-talks-to-Alice tests cannot catch any of that.

These vectors pin every intermediate value, so the Dart/Flutter client can be
checked against the reference at each step rather than only at the end.

DETERMINISM
-----------
All randomness comes from a seeded DRBG. The generator is reproducible: the
same seed always yields byte-identical vectors, so a diff in the output means
a real change in the protocol, and vectors can be regenerated in CI and
compared.

    !! The DRBG in this file is FOR TEST VECTOR GENERATION ONLY. !!
    !! It is not a CSPRNG and must never appear in a build.      !!
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "crypto" / "reference"))

from helo_ref import attachment, pqxdh, x3dh
from helo_ref.encoding import b64d, b64e
from helo_ref.identity import (
    IdentityKeyPair,
    check_qr_payload,
    qr_payload,
    safety_number,
)
from helo_ref.padding import POLICIES, pad
from helo_ref.pq import MLKEM768
from helo_ref.pqxdh import PQXDH
from helo_ref.prekeys import PreKeyStore
from helo_ref.primitives import (
    aes256gcm_encrypt,
    hkdf,
)
from helo_ref.ratchet import expand_message_key, kdf_chain, kdf_root
from helo_ref.session import start_as_initiator, start_as_responder

DEFAULT_SEED = b"Helo test vector seed v1 -- NOT FOR PRODUCTION USE"
PQ_FIXTURE = REPO / "tests" / "vectors" / "pqxdh_encapsulation_fixture.json"


class TestOnlyDRBG:
    """Deterministic byte source. TEST VECTOR GENERATION ONLY -- NOT A CSPRNG."""

    def __init__(self, seed: bytes) -> None:
        self._seed = hashlib.sha256(seed).digest()
        self._counter = 0

    def bytes(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            out += hashlib.sha256(
                self._seed + self._counter.to_bytes(8, "big")
            ).digest()
            self._counter += 1
        return bytes(out[:n])


def _fixed_clock():
    return 1_700_000_000


# --- Vector groups ----------------------------------------------------------

def vectors_primitives() -> dict:
    """KDF and AEAD vectors. These catch encoding and domain-separation bugs."""
    chain_key = bytes(range(32))
    chain_steps = []
    ck = chain_key
    for i in range(4):
        mk, ck = kdf_chain(ck)
        aes_key, nonce = expand_message_key(mk)
        chain_steps.append({
            "index": i,
            "message_key": b64e(mk),
            "next_chain_key": b64e(ck),
            "aes_key": b64e(aes_key),
            "nonce": b64e(nonce),
        })

    root_key = bytes([0xA5] * 32)
    dh_output = bytes([0x5A] * 32)
    new_root, new_chain = kdf_root(root_key, dh_output)

    aead_key = bytes(range(32))
    aead_nonce = bytes(range(12))
    aead_ct = aes256gcm_encrypt(aead_key, aead_nonce, b"Helo AEAD vector", b"AD")

    return {
        "hkdf_sha256": {
            "ikm": b64e(b"input keying material"),
            "salt": b64e(b"salt"),
            "info": b64e(b"Helo_TestVector_v1"),
            "length": 64,
            "okm": b64e(hkdf(b"input keying material", b"salt",
                             b"Helo_TestVector_v1", 64)),
        },
        "chain_ratchet": {
            "initial_chain_key": b64e(chain_key),
            "steps": chain_steps,
        },
        "root_ratchet": {
            "root_key": b64e(root_key),
            "dh_output": b64e(dh_output),
            "new_root_key": b64e(new_root),
            "new_chain_key": b64e(new_chain),
        },
        "aes_256_gcm": {
            "key": b64e(aead_key),
            "nonce": b64e(aead_nonce),
            "plaintext": b64e(b"Helo AEAD vector"),
            "associated_data": b64e(b"AD"),
            "ciphertext_with_tag": b64e(aead_ct),
        },
    }


def vectors_x3dh(drbg: TestOnlyDRBG) -> dict:
    """Full X3DH handshake with every private input pinned.

    A conforming implementation loading these private keys MUST arrive at the
    identical shared secret, associated data, and session id.
    """
    alice_id = IdentityKeyPair.generate(drbg)
    bob_id = IdentityKeyPair.generate(drbg)

    bob_prekeys = PreKeyStore(bob_id, rng=drbg, clock=_fixed_clock)
    bob_prekeys.rotate_signed_prekey()
    bob_prekeys.generate_one_time_prekeys(2)
    bundle = bob_prekeys.publish_bundle("bob-device-1")

    result, header = x3dh.initiate(alice_id, bundle, drbg)
    bob_result = x3dh.respond(bob_id, bob_prekeys, header)
    assert result.shared_secret == bob_result.shared_secret

    # Three-DH variant (no one-time prekey).
    bob_prekeys_3 = PreKeyStore(bob_id, rng=drbg, clock=_fixed_clock)
    bob_prekeys_3.rotate_signed_prekey()
    bundle_3 = bob_prekeys_3.publish_bundle("bob-device-1")
    result_3, header_3 = x3dh.initiate(alice_id, bundle_3, drbg)
    assert x3dh.respond(bob_id, bob_prekeys_3, header_3).shared_secret == result_3.shared_secret

    return {
        "description": "Classical X3DH over Curve25519 with HKDF-SHA256.",
        "alice_identity_private": {
            "sig_seed": b64e(alice_id.sig_seed),
            "dh_priv": b64e(alice_id.dh_priv),
        },
        "bob_identity_private": {
            "sig_seed": b64e(bob_id.sig_seed),
            "dh_priv": b64e(bob_id.dh_priv),
        },
        "alice_identity_public": alice_id.public().to_json(),
        "bob_identity_public": bob_id.public().to_json(),
        "bob_prekey_bundle": bundle.to_json(),
        "bob_signed_prekey_private": b64e(
            bob_prekeys.signed_prekey_private(bundle.signed_prekey.key_id)
        ),
        "four_dh": {
            "initial_header": header.to_json(),
            "shared_secret": b64e(result.shared_secret),
            "associated_data": b64e(result.associated_data),
            "session_id": result.session_id,
            "used_one_time_prekey": result.used_one_time_prekey,
        },
        "three_dh": {
            "comment": (
                "Separate prekey store, so this variant has its OWN signed "
                "prekey. Pinning it explicitly is required for replay."
            ),
            "prekey_bundle": bundle_3.to_json(),
            "signed_prekey_private": b64e(
                bob_prekeys_3.signed_prekey_private(bundle_3.signed_prekey.key_id)
            ),
            "initial_header": header_3.to_json(),
            "shared_secret": b64e(result_3.shared_secret),
            "associated_data": b64e(result_3.associated_data),
            "session_id": result_3.session_id,
            "used_one_time_prekey": result_3.used_one_time_prekey,
        },
        "safety_number": safety_number(alice_id.public(), bob_id.public()),
        "alice_fingerprint": b64e(alice_id.public().fingerprint()),
        "bob_fingerprint": b64e(bob_id.public().fingerprint()),
    }


def vectors_double_ratchet(drbg: TestOnlyDRBG) -> dict:
    """A full conversation with every envelope pinned.

    Includes a unidirectional burst, a reply (forcing a DH ratchet), and a
    second burst -- so a conforming implementation exercises both ratchets.
    """
    alice_id = IdentityKeyPair.generate(drbg)
    bob_id = IdentityKeyPair.generate(drbg)

    bob_prekeys = PreKeyStore(bob_id, rng=drbg, clock=_fixed_clock)
    bob_prekeys.rotate_signed_prekey()
    bob_prekeys.generate_one_time_prekeys(2)
    bundle = bob_prekeys.publish_bundle("bob-device-1")
    spk_priv = bob_prekeys.signed_prekey_private(bundle.signed_prekey.key_id)

    alice = start_as_initiator(alice_id, "alice-device-1", bundle, drbg)

    transcript = []

    first_plain = b"A0: initial prekey message"
    first = alice.encrypt(first_plain)
    bob = start_as_responder(bob_id, "bob-device-1", bob_prekeys, first)
    assert bob.decrypt(first, drbg) == first_plain
    transcript.append({
        "direction": "alice->bob",
        "plaintext": b64e(first_plain),
        "envelope": first.to_json(),
    })

    for i in range(1, 3):
        p = f"A{i}: same sending chain".encode()
        env = alice.encrypt(p)
        assert bob.decrypt(env, drbg) == p
        transcript.append({
            "direction": "alice->bob",
            "plaintext": b64e(p),
            "envelope": env.to_json(),
        })

    for i in range(2):
        p = f"B{i}: reply, forces a DH ratchet".encode()
        env = bob.encrypt(p)
        assert alice.decrypt(env, drbg) == p
        transcript.append({
            "direction": "bob->alice",
            "plaintext": b64e(p),
            "envelope": env.to_json(),
        })

    for i in range(2):
        p = f"A{i}: new sending chain after ratchet".encode()
        env = alice.encrypt(p)
        assert bob.decrypt(env, drbg) == p
        transcript.append({
            "direction": "alice->bob",
            "plaintext": b64e(p),
            "envelope": env.to_json(),
        })

    return {
        "description": (
            "Full Double Ratchet transcript. A conforming implementation seeded "
            "with the listed private keys must produce byte-identical envelopes."
        ),
        "alice_identity_private": {
            "sig_seed": b64e(alice_id.sig_seed),
            "dh_priv": b64e(alice_id.dh_priv),
        },
        "bob_identity_private": {
            "sig_seed": b64e(bob_id.sig_seed),
            "dh_priv": b64e(bob_id.dh_priv),
        },
        "bob_prekey_bundle": bundle.to_json(),
        "bob_signed_prekey_private": b64e(spk_priv),
        "bob_one_time_prekey_private": b64e(
            bob_prekeys._one_time[bundle.one_time_prekey.key_id].private
        ) if bundle.one_time_prekey and bundle.one_time_prekey.key_id in bob_prekeys._one_time else None,
        "transcript": transcript,
    }


def vectors_out_of_order(drbg: TestOnlyDRBG) -> dict:
    """Delivery order 1,3,2,4 with skipped-key handling pinned."""
    alice_id = IdentityKeyPair.generate(drbg)
    bob_id = IdentityKeyPair.generate(drbg)
    bob_prekeys = PreKeyStore(bob_id, rng=drbg, clock=_fixed_clock)
    bob_prekeys.rotate_signed_prekey()
    bob_prekeys.generate_one_time_prekeys(2)
    bundle = bob_prekeys.publish_bundle("bob-device-1")

    alice = start_as_initiator(alice_id, "alice-device-1", bundle, drbg)
    first = alice.encrypt(b"M0")
    bob = start_as_responder(bob_id, "bob-device-1", bob_prekeys, first)
    bob.decrypt(first, drbg)

    envelopes = [alice.encrypt(f"M{i}".encode()) for i in range(1, 5)]
    delivery_order = [0, 2, 1, 3]
    observed = []
    for idx in delivery_order:
        pt = bob.decrypt(envelopes[idx], drbg)
        observed.append({
            "delivered_index": idx,
            "plaintext": b64e(pt),
            "skipped_keys_stored_after": len(bob.ratchet.skipped),
        })

    return {
        "description": "Out-of-order delivery: sent 1,2,3,4 delivered 1,3,2,4.",
        "bootstrap_envelope": first.to_json(),
        "bob_prekey_bundle": bundle.to_json(),
        "envelopes": [e.to_json() for e in envelopes],
        "delivery_order": delivery_order,
        "expected": observed,
    }


def vectors_safety_number_ordering(drbg: TestOnlyDRBG) -> dict:
    """A pair whose fingerprints sort DIFFERENTLY as bytes than as base64.

    The safety number orders the two fingerprints before hashing, and the
    reference orders raw bytes. The base64 alphabet is not in ASCII order, so
    an implementation that compares base64 strings agrees with the reference
    on some pairs and silently disagrees on others (about a third). The
    pinned pair in the x3dh group happens to sort the same both ways, so it
    could never catch that; this pair is chosen so it must.
    """
    for _ in range(64):
        a = IdentityKeyPair.generate(drbg).public()
        b = IdentityKeyPair.generate(drbg).public()
        fa, fb = a.fingerprint(), b.fingerprint()
        if (fa < fb) != (b64e(fa) < b64e(fb)):
            break
    else:  # pragma: no cover - probability ~ (2/3)^64
        raise RuntimeError("no order-inverting identity pair found")
    return {
        "description": (
            "Identity pair whose fingerprints order differently as raw bytes "
            "than as base64 text. The safety number must follow byte order."
        ),
        "identity_a": a.to_json(),
        "identity_b": b.to_json(),
        "fingerprint_a": b64e(fa),
        "fingerprint_b": b64e(fb),
        "a_sorts_first_by_bytes": fa < fb,
        "safety_number": safety_number(a, b),
        "qr_payload_a_to_b": qr_payload(a, b),
    }


def vectors_qr_check(drbg: TestOnlyDRBG) -> dict:
    """Scanned-QR verification outcomes (identity.check_qr_payload).

    Alice scans what Bob displays. Only the first case may mark Bob verified.
    """
    alice = IdentityKeyPair.generate(drbg).public()
    bob = IdentityKeyPair.generate(drbg).public()
    mallory = IdentityKeyPair.generate(drbg).public()
    good = qr_payload(bob, alice)
    cases = [
        ("bob shows his code, both keys as held", good),
        ("code of someone else (or a key the relay substituted)", qr_payload(mallory, alice)),
        ("bob holds a different key for alice", qr_payload(bob, mallory)),
        ("halves swapped", qr_payload(alice, bob)),
        ("not a helo code", "https://example.com/" + good),
        ("wrong version", good.replace("helo:v1:", "helo:v2:", 1)),
        ("three parts", good + ":AAAA"),
        ("bad base64", "helo:v1:!!!!:" + good.split(":")[3]),
        ("oversized", good + "A" * 600),
    ]
    return {
        "description": "Alice (me) scans Bob's code; expected outcome per case.",
        "me": alice.to_json(),
        "peer": bob.to_json(),
        "cases": [
            {"name": name, "scanned": text,
             "expected": check_qr_payload(text, alice, bob).value}
            for name, text in cases
        ],
    }


class _PinnedKEM:
    """TEST VECTOR GENERATION ONLY. Returns a pinned ML-KEM ciphertext.

    OpenSSL (through pyca) offers no derandomized encapsulation, so encapsulating
    afresh on every run would make this file irreproducible. The ciphertext was
    produced ONCE by real OpenSSL encapsulation against the pinned public key
    and committed as a fixture; the shared secret is recomputed here by real
    decapsulation every run, so nothing about the KEM is faked.
    """

    def __init__(self, seed: bytes, ct: bytes) -> None:
        self._seed, self._ct = seed, ct

    def encapsulate(self, ek: bytes) -> tuple[bytes, bytes]:
        assert ek == MLKEM768.public_from_seed(self._seed), "pinned KEM used for another key"
        return self._ct, MLKEM768.decapsulate(self._seed, self._ct)


def _pinned_kem_ciphertext(ek: bytes, check: bool) -> bytes:
    tag = hashlib.sha256(ek).hexdigest()
    if PQ_FIXTURE.exists():
        fixture = json.loads(PQ_FIXTURE.read_text())
        if fixture.get("ek_sha256") == tag:
            return b64d(fixture["ciphertext"])
    if check:
        raise SystemExit("FAIL: PQ encapsulation fixture is missing or does not match the "
                         "pinned key. Regenerate the vectors deliberately and review the diff.")
    ct, _ = MLKEM768.encapsulate(ek)
    PQ_FIXTURE.write_text(json.dumps({
        "note": ("One real OpenSSL ML-KEM-768 encapsulation against the PQ prekey "
                 "pinned in helo_vectors.json (pqxdh). Committed so the vectors "
                 "reproduce; regenerate only together with the vectors."),
        "ek_sha256": tag,
        "ciphertext": b64e(ct),
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    return ct


def vectors_pqxdh(drbg: TestOnlyDRBG, check: bool) -> dict:
    """Hybrid PQXDH establishment and a first ratcheted reply, every input pinned.

    The ML-KEM key pair is generated from a pinned seed, so a conforming
    implementation must reproduce OpenSSL's encapsulation key from the seed and
    OpenSSL's shared secret from the ciphertext -- a direct interoperability
    check of the ML-KEM implementation, not just of our protocol code.
    """
    alice_id = IdentityKeyPair.generate(drbg)
    bob_id = IdentityKeyPair.generate(drbg)
    store = PreKeyStore(bob_id, rng=drbg, clock=_fixed_clock)
    store.rotate_signed_prekey()
    store.generate_one_time_prekeys(1)
    store.rotate_pq_last_resort()
    store.generate_pq_one_time_prekeys(1)
    bundle = store.publish_bundle("bob-device-1")
    assert bundle.pq_prekey is not None and bundle.pq_prekey.one_time
    pq_seed = store._pq[bundle.pq_prekey.key_id].seed
    spk_priv = store.signed_prekey_private(bundle.signed_prekey.key_id)
    otp_priv = store._one_time[bundle.one_time_prekey.key_id].private

    ct = _pinned_kem_ciphertext(bundle.pq_prekey.encapsulation_key(), check)
    kem_secret = MLKEM768.decapsulate(pq_seed, ct)

    alice = start_as_initiator(alice_id, "alice-device-1", bundle, drbg,
                               kex=PQXDH(kem=_PinnedKEM(pq_seed, ct)))
    first_plain = b"PQ0: hybrid initial message"
    first = alice.encrypt(first_plain)
    result = pqxdh.respond(bob_id, copy.deepcopy(store), first.x3dh)
    bob = start_as_responder(bob_id, "bob-device-1", store, first, accept_classical=False)
    assert bob.decrypt(first, drbg) == first_plain
    reply_plain = b"PQ1: reply over the ratchet"
    reply = bob.encrypt(reply_plain)
    assert alice.decrypt(reply, drbg) == reply_plain

    return {
        "description": (
            "Hybrid PQXDH (X25519 x4 + ML-KEM-768). The ML-KEM key is derived from "
            "a pinned FIPS 203 seed; the ciphertext is a pinned OpenSSL encapsulation."
        ),
        "info": pqxdh.INFO_PQXDH.decode(),
        "alice_identity_private": {
            "sig_seed": b64e(alice_id.sig_seed), "dh_priv": b64e(alice_id.dh_priv),
        },
        "bob_identity_private": {
            "sig_seed": b64e(bob_id.sig_seed), "dh_priv": b64e(bob_id.dh_priv),
        },
        "bob_prekey_bundle": bundle.to_json(),
        "bob_signed_prekey_private": b64e(spk_priv),
        "bob_one_time_prekey_private": b64e(otp_priv),
        "bob_pq_prekey_seed": b64e(pq_seed),
        "kem_ciphertext": b64e(ct),
        "kem_shared_secret": b64e(kem_secret),
        "shared_secret": b64e(result.shared_secret),
        "associated_data": b64e(result.associated_data),
        "session_id": result.session_id,
        "transcript": [
            {"direction": "alice->bob", "plaintext": b64e(first_plain),
             "envelope": first.to_json()},
            {"direction": "bob->alice", "plaintext": b64e(reply_plain),
             "envelope": reply.to_json()},
        ],
    }


def vectors_padding() -> dict:
    lengths = [0, 1, 158, 159, 160, 254, 255, 256, 300, 1000, 5000]
    return {
        "description": "payload || 0x80 || 0x00* to a bucket; padded length per policy.",
        "cases": [
            {"policy": name, "payload_length": n, "padded_length": len(pad(bytes(n), policy))}
            for name, policy in sorted(POLICIES.items())
            for n in lengths
        ],
        "example": {
            "policy": "block-256",
            "payload": b64e(b'{"v":1,"k":"typing"}'),
            "padded": b64e(pad(b'{"v":1,"k":"typing"}', POLICIES["block-256"])),
        },
    }


def vectors_attachment(drbg: TestOnlyDRBG) -> dict:
    key = attachment.generate_key(drbg)
    plaintext = bytes((i * 31 + 7) % 256 for i in range(200))
    small_chunks = attachment.encrypt(key, plaintext, 64)
    default_chunks = attachment.encrypt(key, plaintext[:100])
    return {
        "description": "STREAM AES-256-GCM: nonce = 0^7 || u32(i) || u8(final), AD fixed.",
        "ad": attachment.ATTACHMENT_AD.decode(),
        "key": b64e(key),
        "plaintext": b64e(plaintext),
        "chunk_size": 64,
        "ciphertext": b64e(small_chunks),
        "digest": b64e(attachment.digest(small_chunks)),
        "default_chunk_plaintext": b64e(plaintext[:100]),
        "default_chunk_ciphertext": b64e(default_chunks),
    }


def build(seed: bytes, check: bool = False) -> dict:
    return {
        "format_version": 1,
        "protocol": "Helo/1 X3DH-Curve25519-SHA256 + DoubleRatchet + AES-256-GCM",
        "post_quantum": False,
        "seed": seed.decode("utf-8", "replace"),
        "warning": (
            "Private keys in this file are DERIVED FROM A FIXED TEST SEED and are "
            "PUBLIC BY DESIGN. They must never be used for anything real."
        ),
        "primitives": vectors_primitives(),
        "x3dh": vectors_x3dh(TestOnlyDRBG(seed + b"|x3dh")),
        "double_ratchet": vectors_double_ratchet(TestOnlyDRBG(seed + b"|dr")),
        "out_of_order": vectors_out_of_order(TestOnlyDRBG(seed + b"|ooo")),
        "pqxdh": vectors_pqxdh(TestOnlyDRBG(seed + b"|pqxdh"), check),
        "padding": vectors_padding(),
        "attachment": vectors_attachment(TestOnlyDRBG(seed + b"|attachment")),
        "safety_number_ordering": vectors_safety_number_ordering(
            TestOnlyDRBG(seed + b"|sn-order")
        ),
        "qr_check": vectors_qr_check(TestOnlyDRBG(seed + b"|qr-check")),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out", default=str(REPO / "tests" / "vectors" / "helo_vectors.json")
    )
    parser.add_argument("--check", action="store_true",
                        help="regenerate and fail if the committed vectors differ")
    args = parser.parse_args()

    payload = json.dumps(build(DEFAULT_SEED, check=args.check), indent=2, sort_keys=True) + "\n"
    out_path = Path(args.out)

    if args.check:
        if not out_path.exists():
            print(f"FAIL: {out_path} does not exist", file=sys.stderr)
            return 1
        if out_path.read_text() != payload:
            print("FAIL: committed test vectors differ from regenerated output.",
                  file=sys.stderr)
            print("The protocol changed. Review the diff before committing.",
                  file=sys.stderr)
            return 1
        print(f"OK: test vectors reproduce exactly ({len(payload)} bytes)")
        return 0

    out_path.parent.mkdir(parents=True, exist_ok=True)
    # LF on every platform, so the committed file is byte-stable across OSes.
    out_path.write_text(payload, encoding="utf-8", newline="\n")
    digest = hashlib.sha256(payload.encode()).hexdigest()
    print(f"wrote {out_path} ({len(payload)} bytes)")
    print(f"sha256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
