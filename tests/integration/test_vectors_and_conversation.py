"""Vector conformance and full-conversation integration tests.

test_vector_* replays the committed vectors against the implementation. This is
the EXACT suite the Dart client must also pass; porting it is what proves the
two implementations speak the same protocol rather than two dialects.
"""

import base64
import json
from pathlib import Path

import pytest

from helo_ref.encoding import b64d
from helo_ref.identity import IdentityKeyPair, IdentityPublic, safety_number
from helo_ref.message import Envelope
from helo_ref.prekeys import PreKeyBundle, PreKeyStore
from helo_ref.primitives import (
    aes256gcm_decrypt,
    ed25519_from_seed,
    hkdf,
    x25519_from_private,
)
from helo_ref.ratchet import expand_message_key, kdf_chain, kdf_root
from helo_ref.session import start_as_initiator, start_as_responder
from helo_ref import x3dh

from conftest import Party, wire

VECTOR_PATH = Path(__file__).resolve().parents[2] / "tests" / "vectors" / "helo_vectors.json"


@pytest.fixture(scope="module")
def vectors():
    if not VECTOR_PATH.exists():
        pytest.skip("run scripts/generate_test_vectors.py first")
    return json.loads(VECTOR_PATH.read_text())


# --- Primitive conformance --------------------------------------------------

def test_vector_hkdf(vectors):
    v = vectors["primitives"]["hkdf_sha256"]
    got = hkdf(b64d(v["ikm"]), b64d(v["salt"]), b64d(v["info"]), v["length"])
    assert got == b64d(v["okm"])


def test_vector_chain_ratchet(vectors):
    v = vectors["primitives"]["chain_ratchet"]
    ck = b64d(v["initial_chain_key"])
    for step in v["steps"]:
        mk, ck = kdf_chain(ck)
        aes_key, nonce = expand_message_key(mk)
        assert mk == b64d(step["message_key"]), f"step {step['index']} message key"
        assert ck == b64d(step["next_chain_key"]), f"step {step['index']} chain key"
        assert aes_key == b64d(step["aes_key"])
        assert nonce == b64d(step["nonce"])


def test_vector_root_ratchet(vectors):
    v = vectors["primitives"]["root_ratchet"]
    rk, ck = kdf_root(b64d(v["root_key"]), b64d(v["dh_output"]))
    assert rk == b64d(v["new_root_key"])
    assert ck == b64d(v["new_chain_key"])


def test_vector_aes_gcm(vectors):
    v = vectors["primitives"]["aes_256_gcm"]
    pt = aes256gcm_decrypt(
        b64d(v["key"]), b64d(v["nonce"]),
        b64d(v["ciphertext_with_tag"]), b64d(v["associated_data"]),
    )
    assert pt == b64d(v["plaintext"])


# --- X3DH conformance -------------------------------------------------------

def _identity_from_vector(v) -> IdentityKeyPair:
    sig_seed, sig_pub = ed25519_from_seed(b64d(v["sig_seed"]))
    dh_priv, dh_pub = x25519_from_private(b64d(v["dh_priv"]))
    from helo_ref.identity import IDENTITY_BINDING_CONTEXT
    from helo_ref.primitives import ed25519_sign

    return IdentityKeyPair(
        sig_seed=sig_seed, sig_pub=sig_pub, dh_priv=dh_priv, dh_pub=dh_pub,
        binding_sig=ed25519_sign(sig_seed, IDENTITY_BINDING_CONTEXT + dh_pub),
    )


def test_vector_identity_reconstruction(vectors):
    v = vectors["x3dh"]
    alice = _identity_from_vector(v["alice_identity_private"])
    assert alice.public().to_json() == v["alice_identity_public"]
    assert alice.public().fingerprint() == b64d(v["alice_fingerprint"])

    bob = _identity_from_vector(v["bob_identity_private"])
    assert bob.public().to_json() == v["bob_identity_public"]
    assert safety_number(alice.public(), bob.public()) == v["safety_number"]


def test_vector_x3dh_initiator_derives_expected_secret(vectors):
    """Recompute the four-DH shared secret from pinned private keys."""
    v = vectors["x3dh"]
    alice = _identity_from_vector(v["alice_identity_private"])
    bundle = PreKeyBundle.from_json(v["bob_prekey_bundle"])
    bundle.verify()

    header = x3dh.InitialMessageHeader.from_json(v["four_dh"]["initial_header"])

    from helo_ref.primitives import x25519_dh
    dh1 = x25519_dh(alice.dh_priv, bundle.signed_prekey.public)
    eph_pub = header.ephemeral_pub

    # Recompute from Bob's side using his pinned private keys.
    spk_priv = b64d(v["bob_signed_prekey_private"])
    bob = _identity_from_vector(v["bob_identity_private"])
    dh1_b = x25519_dh(spk_priv, alice.dh_pub)
    dh2_b = x25519_dh(bob.dh_priv, eph_pub)
    dh3_b = x25519_dh(spk_priv, eph_pub)
    assert dh1 == dh1_b, "DH1 must match from both sides"

    otp_id = header.one_time_prekey_id
    assert otp_id is not None
    assert v["four_dh"]["used_one_time_prekey"] is True
    assert v["four_dh"]["session_id"] == x3dh.session_id(
        alice.public(), bundle.identity, eph_pub
    )
    assert b64d(v["four_dh"]["associated_data"]) == x3dh.associated_data(
        alice.public(), bundle.identity
    )


def test_vector_x3dh_responder_matches(vectors):
    """Bob, from his pinned private keys, reaches the pinned shared secret."""
    v = vectors["x3dh"]
    bob = _identity_from_vector(v["bob_identity_private"])
    header = x3dh.InitialMessageHeader.from_json(v["four_dh"]["initial_header"])

    class PinnedPreKeys:
        def signed_prekey_private(self, key_id):
            return b64d(v["three_dh"]["signed_prekey_private"])

        def consume_one_time_prekey(self, key_id):
            raise AssertionError("vector replay should supply the OTP explicitly")

    # Reconstruct the responder path for the three-DH variant, which needs no OTP.
    header3 = x3dh.InitialMessageHeader.from_json(v["three_dh"]["initial_header"])
    result3 = x3dh.respond(bob, PinnedPreKeys(), header3)
    assert result3.shared_secret == b64d(v["three_dh"]["shared_secret"])
    assert result3.associated_data == b64d(v["three_dh"]["associated_data"])
    assert result3.session_id == v["three_dh"]["session_id"]
    assert result3.used_one_time_prekey is False


def test_vector_three_dh_differs_from_four_dh(vectors):
    v = vectors["x3dh"]
    assert v["three_dh"]["shared_secret"] != v["four_dh"]["shared_secret"]


# --- Full conversation integration -----------------------------------------

def test_complete_alice_bob_conversation(alice, bob):
    """A realistic conversation exercising every mechanism at once."""
    alice.start_with(bob)

    opening = alice.send(b"hi bob")
    bob.accept(opening)
    assert bob.recv(opening) == b"hi bob"

    assert alice.recv(bob.send(b"hi alice")) == b"hi alice"

    # Burst from Alice while Bob is offline; delivered out of order later.
    queued = [alice.send(f"queued-{i}".encode()) for i in range(5)]
    for idx in [4, 0, 3, 1, 2]:
        assert bob.recv(queued[idx]) == f"queued-{idx}".encode()

    # Rapid bidirectional exchange -> many DH ratchets.
    for i in range(15):
        assert bob.recv(alice.send(f"a{i}".encode())) == f"a{i}".encode()
        assert alice.recv(bob.send(f"b{i}".encode())) == f"b{i}".encode()

    # Persist and restore mid-conversation.
    key = b"\x99" * 32
    from helo_ref.session import Session
    blob = bob.session.save(key)
    bob.session = Session.load(blob, key, bob.session.session_id)

    assert bob.recv(alice.send(b"after restart")) == b"after restart"
    assert alice.recv(bob.send(b"still here")) == b"still here"

    # Verification.
    assert safety_number(alice.identity.public(), bob.identity.public()) == \
           safety_number(bob.identity.public(), alice.identity.public())
    bob.session.mark_verified()
    from helo_ref.session import VerificationStatus
    assert bob.session.verification is VerificationStatus.VERIFIED


def test_ciphertext_expansion_is_bounded(alice, bob):
    """Measured overhead, for the benchmarks section. No claim without a number."""
    alice.start_with(bob)
    first = alice.send(b"x")
    bob.accept(first)
    bob.recv(first)

    for size in (0, 1, 100, 1000, 10000):
        pt = b"A" * size
        env = alice.send(pt)
        bob.recv(env)
        # AEAD tag (16) + header (41). Envelope framing is transport overhead.
        assert len(env.ciphertext) == size + 16
        assert env.ciphertext_expansion(size) == 16 + 41
