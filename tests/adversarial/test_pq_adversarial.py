"""Active attacks on the hybrid handshake: substitution, malformed KEM data,
negotiation tampering and downgrade."""

import copy

import pytest
from conftest import wire
from helo_ref.encoding import b64d, b64e
from helo_ref.errors import (
    AuthenticationError,
    DowngradeRejectedError,
    InvalidEncodingError,
    InvalidKeyError,
    PostQuantumUnavailableError,
    PreKeyUnavailableError,
    SignatureVerificationError,
)
from helo_ref.identity import IdentityKeyPair
from helo_ref.message import Envelope
from helo_ref.pq import KEM_ID_MLKEM768, MLKEM768, encode_pq_public
from helo_ref.pqxdh import PQXDH
from helo_ref.prekeys import PreKeyBundle, PreKeyStore, pq_prekey_signing_input
from helo_ref.session import start_as_initiator, start_as_responder
from helo_ref.x3dh import ClassicalX3DH

pytestmark = pytest.mark.adversarial


class CountingKEM:
    """Records whether encapsulation ever ran -- it must not, for a bad bundle."""

    calls = 0

    @classmethod
    def encapsulate(cls, ek):
        cls.calls += 1
        return MLKEM768.encapsulate(ek)


def bob_with_store():
    bob = IdentityKeyPair.generate()
    store = PreKeyStore(bob)
    store.rotate_signed_prekey()
    store.generate_one_time_prekeys(3)
    store.rotate_pq_last_resort()
    store.generate_pq_one_time_prekeys(3)
    return bob, store


def bundle_json(store):
    return store.publish_bundle("bob-device").to_json()


def initiate_with(bundle_obj):
    CountingKEM.calls = 0
    alice = IdentityKeyPair.generate()
    return start_as_initiator(alice, "alice", PreKeyBundle.from_json(bundle_obj),
                              kex=PQXDH(kem=CountingKEM))


# ------------------------------------------------- bundle-side attacks

def test_substituted_pq_prekey_is_rejected_before_any_kem_operation():
    _, store = bob_with_store()
    obj = bundle_json(store)
    _, attacker_ek = MLKEM768.generate()
    obj["pq_prekey"]["public"] = b64e(encode_pq_public(attacker_ek))
    with pytest.raises(SignatureVerificationError):
        initiate_with(obj)
    assert CountingKEM.calls == 0, "a bad bundle must never reach encapsulation"


def test_forged_pq_prekey_signature_is_rejected():
    _, store = bob_with_store()
    obj = bundle_json(store)
    sig = bytearray(b64d(obj["pq_prekey"]["signature"]))
    sig[0] ^= 1
    obj["pq_prekey"]["signature"] = b64e(bytes(sig))
    with pytest.raises(SignatureVerificationError):
        initiate_with(obj)
    assert CountingKEM.calls == 0


def test_pq_prekey_id_swap_breaks_the_signature():
    _, store = bob_with_store()
    obj = bundle_json(store)
    obj["pq_prekey"]["key_id"] += 1
    with pytest.raises(SignatureVerificationError):
        initiate_with(obj)


def test_pq_key_signed_by_someone_else_is_rejected():
    _, store = bob_with_store()
    mallory = IdentityKeyPair.generate()
    seed, ek = MLKEM768.generate()
    encoded = encode_pq_public(ek)
    obj = bundle_json(store)
    obj["pq_prekey"].update({
        "key_id": 77, "public": b64e(encoded),
        "signature": b64e(mallory.sign(pq_prekey_signing_input(77, encoded))),
    })
    with pytest.raises(SignatureVerificationError):
        initiate_with(obj)


@pytest.mark.parametrize("mutate", [
    lambda raw: raw[:-1],                                   # truncated
    lambda raw: raw + b"\x00",                               # extended
    lambda raw: bytes([KEM_ID_MLKEM768 + 1]) + raw[1:],      # wrong KEM id
])
def test_malformed_pq_public_key_is_rejected(mutate):
    _, store = bob_with_store()
    obj = bundle_json(store)
    obj["pq_prekey"]["public"] = b64e(mutate(b64d(obj["pq_prekey"]["public"])))
    with pytest.raises((InvalidEncodingError, InvalidKeyError, SignatureVerificationError)):
        initiate_with(obj)
    assert CountingKEM.calls == 0


def test_relay_stripping_the_pq_prekey_causes_refusal_not_downgrade():
    _, store = bob_with_store()
    obj = bundle_json(store)
    del obj["pq_prekey"]
    with pytest.raises(PostQuantumUnavailableError):
        initiate_with(obj)


# ------------------------------------------------- message-side attacks

def hybrid_first_message():
    bob, store = bob_with_store()
    alice = IdentityKeyPair.generate()
    a = start_as_initiator(alice, "alice", PreKeyBundle.from_json(bundle_json(store)), kex=PQXDH())
    env = a.encrypt(b"secret first message")
    return bob, store, env.to_json()


def test_tampered_kem_ciphertext_fails_authentication_without_plaintext():
    bob, store, obj = hybrid_first_message()
    ct = bytearray(b64d(obj["x3dh"]["pq"]["ct"]))
    ct[100] ^= 0x01
    obj["x3dh"]["pq"]["ct"] = b64e(bytes(ct))
    env = Envelope.from_json(obj)
    session = start_as_responder(bob, "bob", store, env)
    # ML-KEM implicit rejection: decapsulation yields an unrelated secret, so
    # the keys disagree and the first message fails authentication.
    with pytest.raises(AuthenticationError):
        session.decrypt(env)


@pytest.mark.parametrize("length", [0, 1087, 1089, 2000])
def test_malformed_kem_ciphertext_length_is_rejected_at_parse(length):
    _, _, obj = hybrid_first_message()
    obj["x3dh"]["pq"]["ct"] = b64e(bytes(length))
    with pytest.raises(InvalidEncodingError):
        Envelope.from_json(obj)


def test_header_version_and_pq_presence_must_agree():
    _, _, obj = hybrid_first_message()
    v2_without_pq = copy.deepcopy(obj)
    del v2_without_pq["x3dh"]["pq"]
    with pytest.raises(InvalidEncodingError):
        Envelope.from_json(v2_without_pq)

    v1_with_pq = copy.deepcopy(obj)
    v1_with_pq["x3dh"]["version"] = 1
    with pytest.raises(InvalidEncodingError):
        Envelope.from_json(v1_with_pq)

    unknown = copy.deepcopy(obj)
    unknown["x3dh"]["version"] = 3
    with pytest.raises(InvalidEncodingError):
        Envelope.from_json(unknown)


def test_downgraded_initial_message_is_refused_by_hybrid_policy():
    """The attacker strips the KEM ciphertext and relabels the header v1."""
    bob, store, obj = hybrid_first_message()
    del obj["x3dh"]["pq"]
    obj["x3dh"]["version"] = 1
    env = Envelope.from_json(obj)
    with pytest.raises(DowngradeRejectedError):
        start_as_responder(bob, "bob", store, env, accept_classical=False)


def test_downgraded_initial_message_never_decrypts_even_if_classical_allowed():
    """With a permissive responder the downgrade is still not SILENT: Alice
    used the hybrid key, Bob derives the classical one, and the first message
    fails authentication rather than opening under a weaker key."""
    bob, store, obj = hybrid_first_message()
    del obj["x3dh"]["pq"]
    obj["x3dh"]["version"] = 1
    env = Envelope.from_json(obj)
    session = start_as_responder(bob, "bob", store, env, accept_classical=True)
    with pytest.raises(AuthenticationError):
        session.decrypt(env)


def test_classical_responder_refuses_hybrid_header():
    bob, store, obj = hybrid_first_message()
    env = Envelope.from_json(obj)
    with pytest.raises(InvalidEncodingError):
        start_as_responder(bob, "bob", store, env, kex=ClassicalX3DH())


def test_incompatible_client_without_pq_keys_fails_closed():
    """A responder whose store has no such PQ key (e.g. an old client, or a
    reinstalled device) cannot complete the handshake and says so."""
    bob, store, obj = hybrid_first_message()
    fresh = PreKeyStore(bob)
    fresh.rotate_signed_prekey()
    env = Envelope.from_json(obj)
    with pytest.raises(PreKeyUnavailableError):
        start_as_responder(bob, "bob", fresh, env)


def test_replayed_hybrid_initial_message_cannot_build_a_second_session():
    bob, store, obj = hybrid_first_message()
    env = Envelope.from_json(obj)
    start_as_responder(bob, "bob", store, env).decrypt(env)
    with pytest.raises(PreKeyUnavailableError):
        start_as_responder(bob, "bob", store, Envelope.from_json(obj))


def test_classical_message_with_hybrid_required_is_refused_end_to_end():
    bob, store = bob_with_store()
    alice = IdentityKeyPair.generate()
    a = start_as_initiator(alice, "a", PreKeyBundle.from_json(bundle_json(store)),
                           kex=ClassicalX3DH())
    with pytest.raises(DowngradeRejectedError):
        start_as_responder(bob, "b", store, wire(a.encrypt(b"x")), accept_classical=False)
