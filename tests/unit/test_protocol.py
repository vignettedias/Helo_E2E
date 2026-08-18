"""Unit tests for primitives, X3DH, ratchet mechanics, and key lifecycle."""

import pytest
from conftest import Party, wire
from helo_ref import x3dh
from helo_ref.encoding import HEADER_LEN, RatchetHeader
from helo_ref.errors import (
    AuthenticationError,
    InvalidEncodingError,
    InvalidKeyError,
    InvalidStateTransitionError,
    PreKeyUnavailableError,
    SignatureVerificationError,
)
from helo_ref.identity import IdentityKeyPair, safety_number
from helo_ref.primitives import (
    aes256gcm_decrypt,
    aes256gcm_encrypt,
    ed25519_sign,
    ed25519_verify,
    hkdf,
    validate_x25519_public,
    x25519_dh,
    x25519_generate,
)
from helo_ref.session import (
    Session,
    SessionState,
)

# --- Primitives -------------------------------------------------------------

def test_aes_gcm_round_trip():
    key, nonce, ad = b"\x01" * 32, b"\x02" * 12, b"header"
    ct = aes256gcm_encrypt(key, nonce, b"secret", ad)
    assert aes256gcm_decrypt(key, nonce, ct, ad) == b"secret"


def test_aes_gcm_rejects_wrong_associated_data():
    key, nonce = b"\x01" * 32, b"\x02" * 12
    ct = aes256gcm_encrypt(key, nonce, b"secret", b"header-a")
    with pytest.raises(AuthenticationError):
        aes256gcm_decrypt(key, nonce, ct, b"header-b")


def test_aes_gcm_rejects_wrong_key():
    ct = aes256gcm_encrypt(b"\x01" * 32, b"\x02" * 12, b"secret", b"")
    with pytest.raises(AuthenticationError):
        aes256gcm_decrypt(b"\x09" * 32, b"\x02" * 12, ct, b"")


@pytest.mark.parametrize("bad_len", [0, 16, 31, 33, 64])
def test_aes_gcm_rejects_wrong_key_size(bad_len):
    with pytest.raises(InvalidKeyError):
        aes256gcm_encrypt(b"\x01" * bad_len, b"\x02" * 12, b"x", b"")


def test_x25519_agreement_is_symmetric():
    a_priv, a_pub = x25519_generate()
    b_priv, b_pub = x25519_generate()
    assert x25519_dh(a_priv, b_pub) == x25519_dh(b_priv, a_pub)


@pytest.mark.parametrize("bad", [bytes(32), b"\x01" + bytes(31)])
def test_low_order_points_are_rejected(bad):
    with pytest.raises(InvalidKeyError):
        validate_x25519_public(bad)


def test_ed25519_signature_round_trip():
    kp = IdentityKeyPair.generate()
    sig = ed25519_sign(kp.sig_seed, b"message")
    ed25519_verify(kp.sig_pub, sig, b"message")
    with pytest.raises(SignatureVerificationError):
        ed25519_verify(kp.sig_pub, sig, b"message!")


def test_hkdf_is_deterministic_and_domain_separated():
    a = hkdf(b"ikm", b"salt", b"info-a", 32)
    b = hkdf(b"ikm", b"salt", b"info-b", 32)
    assert a == hkdf(b"ikm", b"salt", b"info-a", 32)
    assert a != b


def test_identity_repr_never_leaks_private_material():
    kp = IdentityKeyPair.generate()
    text = repr(kp)
    assert "REDACTED" in text
    assert kp.sig_seed.hex() not in text
    assert kp.dh_priv.hex() not in text


# --- X3DH -------------------------------------------------------------------

def test_alice_and_bob_derive_the_same_shared_secret(alice, bob):
    result_a, header = x3dh.initiate(alice.identity, bob.bundle())
    result_b = x3dh.respond(bob.identity, bob.prekeys, header)

    assert result_a.shared_secret == result_b.shared_secret
    assert result_a.associated_data == result_b.associated_data
    assert result_a.session_id == result_b.session_id


def test_x3dh_works_without_a_one_time_prekey(alice):
    """Three-DH fallback when Bob's one-time prekeys are exhausted."""
    bob = Party("bob", one_time_prekeys=0)
    bundle = bob.bundle()
    assert bundle.one_time_prekey is None

    result_a, header = x3dh.initiate(alice.identity, bundle)
    result_b = x3dh.respond(bob.identity, bob.prekeys, header)

    assert result_a.shared_secret == result_b.shared_secret
    assert result_a.used_one_time_prekey is False


def test_three_dh_and_four_dh_produce_different_secrets(alice, bob):
    """Omitting the OPK must change the derived secret, not be silently ignored."""
    with_otp, _ = x3dh.initiate(alice.identity, bob.bundle())

    stripped = bob.bundle()
    stripped.one_time_prekey = None
    without_otp, _ = x3dh.initiate(alice.identity, stripped)

    assert with_otp.shared_secret != without_otp.shared_secret


def test_unknown_signed_prekey_id_is_rejected(alice, bob):
    _, header = x3dh.initiate(alice.identity, bob.bundle())
    bogus = type(header)(
        version=header.version,
        initiator_identity=header.initiator_identity,
        ephemeral_pub=header.ephemeral_pub,
        signed_prekey_id=9999,
        one_time_prekey_id=header.one_time_prekey_id,
    )
    with pytest.raises(PreKeyUnavailableError):
        x3dh.respond(bob.identity, bob.prekeys, bogus)


def test_associated_data_is_role_ordered(alice, bob):
    """AD must not be symmetric, or a message could be reflected at its sender."""
    ad_ab = x3dh.associated_data(alice.identity.public(), bob.identity.public())
    ad_ba = x3dh.associated_data(bob.identity.public(), alice.identity.public())
    assert ad_ab != ad_ba


def test_safety_number_is_order_independent_and_identity_dependent(alice, bob):
    a, b = alice.identity.public(), bob.identity.public()
    assert safety_number(a, b) == safety_number(b, a)
    assert safety_number(a, b) != safety_number(a, IdentityKeyPair.generate().public())
    assert len(safety_number(a, b).replace(" ", "")) == 60


# --- Ratchet mechanics ------------------------------------------------------

def test_sequential_messages_in_both_directions(established):
    alice, bob = established
    for i in range(20):
        assert bob.recv(alice.send(f"a{i}".encode())) == f"a{i}".encode()
        assert alice.recv(bob.send(f"b{i}".encode())) == f"b{i}".encode()


def test_long_unidirectional_run_then_reply(established):
    alice, bob = established
    for i in range(50):
        assert bob.recv(alice.send(f"burst{i}".encode())) == f"burst{i}".encode()
    assert alice.recv(bob.send(b"finally")) == b"finally"


def test_out_of_order_within_one_chain(established):
    alice, bob = established
    msgs = [alice.send(f"m{i}".encode()) for i in range(6)]
    for i in [5, 0, 3, 1, 4, 2]:
        assert bob.recv(msgs[i]) == f"m{i}".encode()


def test_out_of_order_across_a_dh_ratchet(established):
    """Messages from an old chain still decrypt after the ratchet advances."""
    alice, bob = established

    old_chain = [alice.send(f"old{i}".encode()) for i in range(3)]
    bob.recv(old_chain[0])

    # Bob replies -> DH ratchet; Alice then sends on a brand-new chain.
    alice.recv(bob.send(b"ratchet now"))
    new_chain = [alice.send(f"new{i}".encode()) for i in range(3)]

    assert bob.recv(new_chain[0]) == b"new0"
    # The stragglers from the previous chain still work.
    assert bob.recv(old_chain[1]) == b"old1"
    assert bob.recv(old_chain[2]) == b"old2"
    assert bob.recv(new_chain[2]) == b"new2"
    assert bob.recv(new_chain[1]) == b"new1"


def test_many_dh_ratchet_generations(established):
    """30 round trips force 30 DH ratchet steps in each direction."""
    alice, bob = established
    start_ratchet = alice.session.ratchet.dh_send_pub

    for i in range(30):
        assert bob.recv(alice.send(f"ping{i}".encode())) == f"ping{i}".encode()
        assert alice.recv(bob.send(f"pong{i}".encode())) == f"pong{i}".encode()

    # Assert the ratchet actually ADVANCED, rather than asserting a tautology.
    #
    # Note n_send is NOT a valid check here: Alice's last action is a receive,
    # and a DH ratchet step resets n_send to 0. prev_chain_len is the durable
    # evidence that a sending chain was completed and then superseded.
    assert alice.session.ratchet.dh_send_pub != start_ratchet
    assert alice.session.ratchet.prev_chain_len > 0
    assert len(alice.session.ratchet.seen_remote_ratchets) > 1
    assert len(bob.session.ratchet.seen_remote_ratchets) > 1


def test_responder_cannot_send_before_receiving(alice, bob):
    """Bob has no sending chain until Alice's first message arrives."""
    alice.start_with(bob)
    first = alice.send(b"hello")
    bob.accept(first)

    with pytest.raises(InvalidStateTransitionError):
        bob.send(b"too early")

    bob.recv(first)
    assert bob.send(b"now fine") is not None


def test_empty_and_large_plaintexts(established):
    alice, bob = established
    assert bob.recv(alice.send(b"")) == b""
    big = b"A" * 40_000
    assert bob.recv(alice.send(big)) == big


def test_header_encoding_round_trip():
    _, pub = x25519_generate()
    h = RatchetHeader(dh_pub=pub, pn=41, n=42)
    encoded = h.encode()
    assert len(encoded) == HEADER_LEN
    assert RatchetHeader.decode(encoded) == h


def test_header_decoding_rejects_trailing_bytes():
    _, pub = x25519_generate()
    encoded = RatchetHeader(dh_pub=pub, pn=1, n=1).encode()
    with pytest.raises(InvalidEncodingError):
        RatchetHeader.decode(encoded + b"\x00")


# --- Persistence ------------------------------------------------------------

def test_session_survives_save_and_load(established):
    alice, bob = established
    storage_key = b"\x55" * 32

    mid = alice.send(b"before reload")
    blob = bob.session.save(storage_key)
    bob.session = Session.load(blob, storage_key, bob.session.session_id)

    assert bob.session.decrypt(wire(mid)) == b"before reload"
    assert bob.session.decrypt(wire(alice.send(b"after reload"))) == b"after reload"
    assert alice.recv(bob.send(b"reply after reload")) == b"reply after reload"


def test_skipped_keys_survive_persistence(established):
    alice, bob = established
    storage_key = b"\x66" * 32

    m0, m1, m2 = (alice.send(f"s{i}".encode()) for i in range(3))
    bob.recv(m2)  # stores skipped keys for m0, m1

    blob = bob.session.save(storage_key)
    reloaded = Session.load(blob, storage_key, bob.session.session_id)

    assert reloaded.decrypt(wire(m0)) == b"s0"
    assert reloaded.decrypt(wire(m1)) == b"s1"


def test_persisted_blob_contains_no_recognisable_key_material(established):
    alice, bob = established
    blob = bob.session.save(b"\x77" * 32)
    assert bob.session.ratchet.root_key not in blob
    assert bob.session.ratchet.dh_send_priv not in blob


# --- Lifecycle --------------------------------------------------------------

def test_one_time_prekey_is_destroyed_on_use():
    bob = Party("bob", one_time_prekeys=3)
    assert bob.prekeys.one_time_prekey_count() == 3
    bob.prekeys.consume_one_time_prekey(1)
    assert bob.prekeys.one_time_prekey_count() == 2
    with pytest.raises(PreKeyUnavailableError):
        bob.prekeys.consume_one_time_prekey(1)


def test_signed_prekey_rotation_produces_a_new_verifiable_key():
    bob = Party("bob")
    first = bob.prekeys.current_signed_prekey()
    second = bob.prekeys.rotate_signed_prekey()
    assert first.key_id != second.key_id
    second.verify(bob.identity.public())
    first.verify(bob.identity.public())


def test_replenishment_watermark():
    bob = Party("bob", one_time_prekeys=5)
    assert bob.prekeys.needs_one_time_replenishment() is True
    bob.prekeys.generate_one_time_prekeys(100)
    assert bob.prekeys.needs_one_time_replenishment() is False


def test_revoked_session_refuses_all_crypto(established):
    alice, bob = established
    env = alice.send(b"before revocation")
    bob.session.revoke()

    with pytest.raises(InvalidStateTransitionError):
        bob.session.decrypt(wire(env))
    with pytest.raises(InvalidStateTransitionError):
        bob.session.encrypt(b"anything")
    assert bob.session.state is SessionState.SESSION_REVOKED


def test_diagnostics_expose_no_secret_material(established):
    alice, bob = established
    bob.recv(alice.send(b"x"))
    diag = bob.session.diagnostics()
    blob = repr(diag).encode()

    r = bob.session.ratchet
    for secret in (r.root_key, r.dh_send_priv, r.chain_key_recv):
        if secret:
            assert secret.hex().encode() not in blob
            assert secret not in blob
    assert "root_key" not in diag
    assert "chain_key" not in str(diag)
