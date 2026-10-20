"""Scanning a verification QR code: only an exact two-way match verifies.

The code a peer displays says "this is me, and this is who I think you are".
Scanning it must never import a key: a code naming an unknown identity is a
mismatch, not a new contact.
"""

import json
from pathlib import Path

import pytest
from helo_ref.identity import IdentityKeyPair, QrCheck, check_qr_payload, qr_payload

VECTORS = Path(__file__).resolve().parents[1] / "vectors" / "helo_vectors.json"


@pytest.fixture
def ids():
    return tuple(IdentityKeyPair.generate().public() for _ in range(3))


def test_matching_code_verifies(ids):
    alice, bob, _ = ids
    assert check_qr_payload(qr_payload(bob, alice), me=alice, peer=bob) is QrCheck.MATCH


def test_both_parties_can_verify_each_other(ids):
    alice, bob, _ = ids
    assert check_qr_payload(qr_payload(alice, bob), me=bob, peer=alice) is QrCheck.MATCH


def test_substituted_peer_key_is_a_mismatch_not_an_import(ids):
    alice, bob, mallory = ids
    # The relay gave Alice Mallory's key "for Bob"; the real Bob's code shows
    # the real Bob. Alice holds Mallory, so the scan must not verify.
    assert check_qr_payload(qr_payload(bob, alice), me=alice, peer=mallory) is QrCheck.PEER_KEY_MISMATCH


def test_peer_holding_a_different_key_for_me_is_detected(ids):
    alice, bob, mallory = ids
    # Bob was given Mallory's key "for Alice": his code says so.
    assert check_qr_payload(qr_payload(bob, mallory), me=alice, peer=bob) is QrCheck.OWN_KEY_MISMATCH


def test_scanning_my_own_code_does_not_verify(ids):
    alice, bob, _ = ids
    assert check_qr_payload(qr_payload(alice, bob), me=alice, peer=bob) is not QrCheck.MATCH


@pytest.mark.parametrize("text", [
    "", "hello", "helo:v1:", "helo:v1:AAAA", "helo:v1:AAAA:BBBB:CCCC",
    "helo:v2:AAAA:BBBB", "helo:v1:!!!!:AAAA", "helo:v1:" + "A" * 1000 + ":AAAA",
])
def test_malformed_codes_are_not_helo(ids, text):
    alice, bob, _ = ids
    assert check_qr_payload(text, me=alice, peer=bob) is QrCheck.NOT_HELO


def test_committed_vectors_match_the_reference():
    v = json.loads(VECTORS.read_text(encoding="utf-8"))["qr_check"]
    from helo_ref.identity import IdentityPublic

    me, peer = IdentityPublic.from_json(v["me"]), IdentityPublic.from_json(v["peer"])
    outcomes = [check_qr_payload(c["scanned"], me, peer).value for c in v["cases"]]
    assert outcomes == [c["expected"] for c in v["cases"]]
    assert outcomes.count("match") == 1
