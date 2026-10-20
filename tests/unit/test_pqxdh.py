"""Hybrid PQXDH establishment: valid runs, derivation properties, policy.

Adversarial variants (tampering, downgrade, malformed KEM data) live in
tests/adversarial/test_pq_adversarial.py.
"""

import pytest
from conftest import wire
from helo_ref import pqxdh, x3dh
from helo_ref.errors import PostQuantumUnavailableError, PreKeyUnavailableError
from helo_ref.identity import IdentityKeyPair
from helo_ref.pq import MLKEM768, MLKEM768_CT_LEN
from helo_ref.pqxdh import PQXDH
from helo_ref.prekeys import PreKeyBundle, PreKeyStore
from helo_ref.session import Session, start_as_initiator, start_as_responder
from helo_ref.x3dh import ClassicalX3DH


def make_bob(one_time=2, pq_one_time=2, last_resort=True):
    bob = IdentityKeyPair.generate()
    store = PreKeyStore(bob)
    store.rotate_signed_prekey()
    store.generate_one_time_prekeys(one_time)
    if last_resort:
        store.rotate_pq_last_resort()
    store.generate_pq_one_time_prekeys(pq_one_time)
    return bob, store


def bundle_of(store, device="bob-device"):
    # Every bundle crosses a JSON round trip, as it would from the relay.
    return PreKeyBundle.from_json(store.publish_bundle(device).to_json())


def establish(alice, bob, store, **responder_kw):
    a = start_as_initiator(alice, "alice-device", bundle_of(store), kex=PQXDH())
    first = wire(a.encrypt(b"hello, post-quantum world"))
    b = start_as_responder(bob, "bob-device", store, first, **responder_kw)
    assert b.decrypt(first) == b"hello, post-quantum world"
    return a, b, first


def test_hybrid_establishment_with_all_prekeys():
    alice = IdentityKeyPair.generate()
    bob, store = make_bob()
    a, b, first = establish(alice, bob, store, accept_classical=False)
    assert first.x3dh.is_hybrid
    assert len(first.x3dh.pq_ciphertext) == MLKEM768_CT_LEN
    assert a.kex == b.kex == "pqxdh-mlkem768"
    assert a.used_one_time_prekey and b.used_one_time_prekey


def test_hybrid_establishment_without_ec_one_time_prekey():
    alice = IdentityKeyPair.generate()
    bob, store = make_bob(one_time=0)
    a, b, _ = establish(alice, bob, store)
    assert not a.used_one_time_prekey
    assert a.kex == "pqxdh-mlkem768"


def test_conversation_ratchets_normally_after_hybrid_establishment():
    alice = IdentityKeyPair.generate()
    bob, store = make_bob()
    a, b, _ = establish(alice, bob, store)
    for i in range(5):
        assert a.decrypt(wire(b.encrypt(f"b{i}".encode()))) == f"b{i}".encode()
        assert b.decrypt(wire(a.encrypt(f"a{i}".encode()))) == f"a{i}".encode()


def test_one_time_pq_prekey_is_consumed_and_last_resort_is_reused():
    alice = IdentityKeyPair.generate()
    bob, store = make_bob(pq_one_time=1)
    first_bundle = bundle_of(store)
    assert first_bundle.pq_prekey.one_time
    start_as_responder(bob, "bob", store,
                       wire(start_as_initiator(alice, "a", first_bundle, kex=PQXDH()).encrypt(b"x")))
    assert store.pq_one_time_prekey_count() == 0

    # With no one-time PQ keys left, the last-resort key answers -- repeatedly.
    for _ in range(2):
        bundle = bundle_of(store)
        assert not bundle.pq_prekey.one_time
        a = start_as_initiator(IdentityKeyPair.generate(), "x", bundle, kex=PQXDH())
        msg = wire(a.encrypt(b"via last resort"))
        assert start_as_responder(bob, "bob", store, msg).decrypt(msg) == b"via last resort"


def test_kem_secret_contributes_to_the_session_key():
    """An attacker who somehow knew every DH output but not the KEM secret
    must not be able to compute SK. Model it directly: same DH outputs, a
    different KEM secret, a different key."""
    dhs = [bytes([i]) * 32 for i in range(1, 5)]
    real = pqxdh._derive(dhs, b"\x11" * 32)
    assert pqxdh._derive(dhs, b"\x22" * 32) != real
    assert pqxdh._derive(dhs, b"\x00" * 32) != real


def test_hybrid_and_classical_derivations_are_domain_separated():
    dhs = [bytes([i]) * 32 for i in range(1, 5)]
    assert pqxdh._derive(dhs, b"") != x3dh._derive(dhs), \
        "even with an empty KEM secret the info strings must differ"
    assert pqxdh.INFO_PQXDH != b"Helo_X3DH_v1"


def test_both_sides_derive_the_same_secret():
    alice = IdentityKeyPair.generate()
    bob, store = make_bob()
    result, header = pqxdh.initiate(alice, bundle_of(store))
    assert pqxdh.respond(bob, store, header).shared_secret == result.shared_secret


def test_refuses_bundle_without_pq_prekey_instead_of_falling_back():
    alice = IdentityKeyPair.generate()
    bob = IdentityKeyPair.generate()
    store = PreKeyStore(bob)
    store.rotate_signed_prekey()
    with pytest.raises(PostQuantumUnavailableError):
        start_as_initiator(alice, "a", bundle_of(store), kex=PQXDH())


def test_classical_mode_is_retained_and_labelled():
    alice = IdentityKeyPair.generate()
    bob, store = make_bob()
    a = start_as_initiator(alice, "a", bundle_of(store), kex=ClassicalX3DH())
    msg = wire(a.encrypt(b"classical"))
    assert not msg.x3dh.is_hybrid
    b = start_as_responder(bob, "b", store, msg, accept_classical=True)
    assert b.decrypt(msg) == b"classical"
    assert a.kex == b.kex == "x3dh"


def test_kex_survives_persistence():
    alice = IdentityKeyPair.generate()
    bob, store = make_bob()
    a, _, _ = establish(alice, bob, store)
    key = b"\x42" * 32
    assert Session.load(a.save(key), key, a.session_id).kex == "pqxdh-mlkem768"


def test_pending_hybrid_header_survives_persistence():
    alice = IdentityKeyPair.generate()
    bob, store = make_bob()
    a = start_as_initiator(alice, "a", bundle_of(store), kex=PQXDH())
    key = b"\x43" * 32
    a = Session.load(a.save(key), key, a.session_id)
    msg = wire(a.encrypt(b"after restart"))
    assert msg.x3dh.is_hybrid
    assert start_as_responder(bob, "b", store, msg).decrypt(msg) == b"after restart"


def test_pq_prekey_store_rejects_unknown_ids():
    _, store = make_bob()
    with pytest.raises(PreKeyUnavailableError):
        store.consume_pq_prekey(9999)


def test_kem_round_trip_and_seed_determinism():
    seed, ek = MLKEM768.generate()
    assert MLKEM768.public_from_seed(seed) == ek
    ct, ss = MLKEM768.encapsulate(ek)
    assert MLKEM768.decapsulate(seed, ct) == ss
