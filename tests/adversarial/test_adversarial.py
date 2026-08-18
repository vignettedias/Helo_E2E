"""Adversarial tests: the attacker is assumed to control the relay.

Each test corresponds to a numbered entry in THREAT_MODEL.md. These are the
tests that produce the evidence column in SECURITY_CLAIMS.md.
"""

import base64
import copy
import json

import pytest

from helo_ref.errors import (
    AuthenticationError,
    IdentityChangedError,
    InvalidEncodingError,
    InvalidKeyError,
    PreKeyUnavailableError,
    ReplayError,
    SessionStateCorruptError,
    SignatureVerificationError,
    TooManySkippedMessagesError,
)
from helo_ref.identity import IdentityKeyPair
from helo_ref.message import Envelope
from helo_ref.prekeys import PreKeyStore
from helo_ref.ratchet import MAX_SKIP
from helo_ref.session import start_as_initiator, start_as_responder

from conftest import Party, wire

pytestmark = pytest.mark.adversarial


def flip_bit(data: bytes, index: int = 0, bit: int = 0) -> bytes:
    buf = bytearray(data)
    buf[index] ^= 1 << bit
    return bytes(buf)


# --- T1: malicious relay tampers with ciphertext ---------------------------

def test_bitflip_in_ciphertext_fails_authentication(established):
    alice, bob = established
    env = alice.send(b"transfer approved")
    obj = env.to_json()
    ct = base64.b64decode(obj["ciphertext"])
    obj["ciphertext"] = base64.b64encode(flip_bit(ct, 0)).decode()

    with pytest.raises(AuthenticationError):
        bob.session.decrypt(Envelope.from_json(obj))


def test_bitflip_in_authentication_tag_fails(established):
    alice, bob = established
    env = alice.send(b"transfer approved")
    obj = env.to_json()
    ct = base64.b64decode(obj["ciphertext"])
    obj["ciphertext"] = base64.b64encode(flip_bit(ct, len(ct) - 1, 3)).decode()

    with pytest.raises(AuthenticationError):
        bob.session.decrypt(Envelope.from_json(obj))


def test_truncated_ciphertext_is_rejected(established):
    alice, bob = established
    env = alice.send(b"data")
    obj = env.to_json()
    ct = base64.b64decode(obj["ciphertext"])
    obj["ciphertext"] = base64.b64encode(ct[:-4]).decode()

    with pytest.raises(AuthenticationError):
        bob.session.decrypt(Envelope.from_json(obj))


# --- T2: relay tampers with the authenticated header -----------------------

def test_modified_message_number_in_header_fails(established):
    """The header is not encrypted, but it IS authenticated as AEAD AD."""
    alice, bob = established
    env = alice.send(b"payload")
    tampered = Envelope(
        session_id=env.session_id,
        sender_device_id=env.sender_device_id,
        header=type(env.header)(dh_pub=env.header.dh_pub, pn=env.header.pn, n=env.header.n + 7),
        ciphertext=env.ciphertext,
    )
    with pytest.raises(Exception) as exc:
        bob.session.decrypt(wire(tampered))
    assert isinstance(exc.value, (AuthenticationError, TooManySkippedMessagesError))


def test_modified_ratchet_public_key_in_header_fails(established):
    alice, bob = established
    env = alice.send(b"payload")
    fake_ratchet_key = IdentityKeyPair.generate().dh_pub
    tampered = Envelope(
        session_id=env.session_id,
        sender_device_id=env.sender_device_id,
        header=type(env.header)(dh_pub=fake_ratchet_key, pn=env.header.pn, n=env.header.n),
        ciphertext=env.ciphertext,
    )
    with pytest.raises(AuthenticationError):
        bob.session.decrypt(wire(tampered))


def test_low_order_ratchet_key_is_rejected(established):
    """A degenerate curve point must never be accepted into the ratchet."""
    alice, bob = established
    env = alice.send(b"payload")
    obj = env.to_json()
    header = bytearray(base64.b64decode(obj["header"]))
    header[1:33] = bytes(32)  # all-zero X25519 point
    obj["header"] = base64.b64encode(bytes(header)).decode()

    with pytest.raises(InvalidKeyError):
        Envelope.from_json(obj)


# --- T3: replay attacker ----------------------------------------------------

def test_replayed_message_is_rejected(established):
    alice, bob = established
    env = alice.send(b"pay me again")
    assert bob.recv(env) == b"pay me again"

    with pytest.raises(ReplayError):
        bob.recv(env)


def test_replay_of_out_of_order_message_is_rejected(established):
    """A message delivered late is accepted once, then its key is destroyed."""
    alice, bob = established
    m1, m2, m3 = (alice.send(f"m{i}".encode()) for i in range(1, 4))

    assert bob.recv(m3) == b"m3"   # arrives first; m1,m2 keys get stored
    assert bob.recv(m1) == b"m1"   # late delivery, accepted
    with pytest.raises(ReplayError):
        bob.recv(m1)               # replay of the same late message
    assert bob.recv(m2) == b"m2"   # unaffected


def test_replay_across_a_ratchet_step_is_rejected(established):
    alice, bob = established
    old = alice.send(b"old chain message")
    assert bob.recv(old) == b"old chain message"

    # Force several DH ratchet steps.
    for _ in range(3):
        bob.recv(alice.send(b"x"))
        alice.recv(bob.send(b"y"))

    with pytest.raises(ReplayError):
        bob.recv(old)


def test_initial_prekey_message_cannot_be_replayed_into_a_new_session(alice, bob):
    """The one-time prekey is destroyed on use, so a fresh session cannot form."""
    alice.start_with(bob)
    first = alice.send(b"hello")
    bob.accept(first)
    assert bob.recv(first) == b"hello"

    with pytest.raises(PreKeyUnavailableError):
        start_as_responder(bob.identity, bob.device_id, bob.prekeys, wire(first))


# --- T4: MITM / identity substitution --------------------------------------

def test_forged_signed_prekey_signature_is_rejected(alice, bob):
    """A relay that swaps in its own prekey cannot forge Bob's signature."""
    mallory = IdentityKeyPair.generate()
    mallory_prekeys = PreKeyStore(mallory)
    mallory_prekeys.rotate_signed_prekey()

    forged = bob.bundle()
    forged.signed_prekey = mallory_prekeys.current_signed_prekey()

    with pytest.raises(SignatureVerificationError):
        start_as_initiator(alice.identity, alice.device_id, forged)


def test_substituted_identity_key_is_rejected(alice, bob):
    """Swapping IK_dh breaks the identity binding signature."""
    mallory = IdentityKeyPair.generate()
    forged = bob.bundle()
    forged.identity = type(forged.identity)(
        sig_pub=bob.identity.sig_pub,
        dh_pub=mallory.dh_pub,
        binding_sig=bob.identity.binding_sig,
    )
    with pytest.raises(SignatureVerificationError):
        start_as_initiator(alice.identity, alice.device_id, forged)


def test_full_mitm_produces_a_different_safety_number(alice, bob):
    """MITM is not prevented by crypto alone -- it is DETECTED by verification."""
    from helo_ref.identity import safety_number

    mallory = IdentityKeyPair.generate()
    honest = safety_number(alice.identity.public(), bob.identity.public())
    attacked = safety_number(alice.identity.public(), mallory.public())
    assert honest != attacked


def test_identity_change_on_established_session_is_flagged(established):
    """An established session pins the peer identity and refuses substitution.

    Scenario: the relay tries to take over an existing conversation by
    re-initiating it under an attacker-controlled identity. The session must
    reject the message AND surface IDENTITY_CHANGED to the user, rather than
    silently starting a new session with the attacker.
    """
    from helo_ref.session import VerificationStatus
    from helo_ref.x3dh import InitialMessageHeader

    alice, bob = established
    mallory = IdentityKeyPair.generate()

    env = alice.send(b"legit")
    forged = Envelope(
        session_id=env.session_id,
        sender_device_id=env.sender_device_id,
        header=env.header,
        ciphertext=env.ciphertext,
        x3dh=InitialMessageHeader(
            version=1,
            initiator_identity=mallory.public(),
            ephemeral_pub=mallory.dh_pub,
            signed_prekey_id=1,
            one_time_prekey_id=None,
        ),
    )

    with pytest.raises(IdentityChangedError):
        bob.session.decrypt(wire(forged))

    assert bob.session.verification is VerificationStatus.IDENTITY_CHANGED

    # A user cannot dismiss the warning by simply marking the peer verified.
    with pytest.raises(Exception):
        bob.session.mark_verified()


def test_verified_session_that_changes_identity_loses_verified_status(established):
    from helo_ref.session import VerificationStatus
    from helo_ref.x3dh import InitialMessageHeader

    alice, bob = established
    bob.session.mark_verified()
    assert bob.session.verification is VerificationStatus.VERIFIED

    mallory = IdentityKeyPair.generate()
    env = alice.send(b"legit")
    forged = Envelope(
        session_id=env.session_id,
        sender_device_id=env.sender_device_id,
        header=env.header,
        ciphertext=env.ciphertext,
        x3dh=InitialMessageHeader(
            version=1,
            initiator_identity=mallory.public(),
            ephemeral_pub=mallory.dh_pub,
            signed_prekey_id=1,
            one_time_prekey_id=None,
        ),
    )
    with pytest.raises(IdentityChangedError):
        bob.session.decrypt(wire(forged))

    assert bob.session.verification is VerificationStatus.IDENTITY_CHANGED


# --- T5: compromised backend / stored-database inspection ------------------

def test_relay_database_contains_no_plaintext(alice, bob):
    """Simulate full database disclosure and search for plaintext."""
    secret = b"THE-LAUNCH-CODE-IS-HUNTER2"
    alice.start_with(bob)
    first = alice.send(secret)
    bob.accept(first)
    bob.recv(first)

    stored_rows = [first.to_json()]
    for i in range(10):
        stored_rows.append(alice.send(secret + str(i).encode()).to_json())

    dump = json.dumps(stored_rows).encode()
    assert b"LAUNCH-CODE" not in dump
    assert b"HUNTER2" not in dump
    assert base64.b64encode(secret) not in dump


def test_relay_cannot_derive_the_session_key_from_stored_material(alice, bob):
    """Everything the relay stores is public; it lacks every private half."""
    bundle = bob.bundle()
    relay_view = bundle.to_json()
    forbidden = {
        base64.b64encode(bob.identity.dh_priv).decode(),
        base64.b64encode(bob.identity.sig_seed).decode(),
        base64.b64encode(alice.identity.dh_priv).decode(),
    }
    serialized = json.dumps(relay_view)
    for secret in forbidden:
        assert secret not in serialized


# --- T6: resource-exhaustion via skipped keys ------------------------------

def test_absurd_message_number_is_rejected_not_computed(established):
    """An attacker must not be able to force unbounded key derivation."""
    alice, bob = established
    env = alice.send(b"payload")
    tampered = Envelope(
        session_id=env.session_id,
        sender_device_id=env.sender_device_id,
        header=type(env.header)(
            dh_pub=env.header.dh_pub, pn=env.header.pn, n=4_000_000_000
        ),
        ciphertext=env.ciphertext,
    )
    with pytest.raises(TooManySkippedMessagesError):
        bob.session.decrypt(wire(tampered))


def test_skip_limit_is_enforced_exactly(established):
    alice, bob = established
    env = alice.send(b"payload")
    tampered = Envelope(
        session_id=env.session_id,
        sender_device_id=env.sender_device_id,
        header=type(env.header)(dh_pub=env.header.dh_pub, pn=env.header.pn, n=MAX_SKIP + 5),
        ciphertext=env.ciphertext,
    )
    with pytest.raises(TooManySkippedMessagesError):
        bob.session.decrypt(wire(tampered))


# --- T7: session state must survive hostile input --------------------------

def test_tampered_message_does_not_desynchronise_the_session(established):
    """A hostile message must not be able to break a working conversation.

    Without atomic state handling, an active attacker could permanently kill
    any session by injecting one garbage ciphertext -- a trivial DoS.
    """
    alice, bob = established
    good = alice.send(b"first")
    obj = good.to_json()
    ct = base64.b64decode(obj["ciphertext"])
    obj["ciphertext"] = base64.b64encode(flip_bit(ct, 5)).decode()

    with pytest.raises(AuthenticationError):
        bob.session.decrypt(Envelope.from_json(obj))

    # The genuine message still decrypts, and the session continues normally.
    assert bob.recv(good) == b"first"
    assert bob.recv(alice.send(b"second")) == b"second"


def test_corrupted_persisted_state_fails_closed(established):
    alice, bob = established
    storage_key = b"\x11" * 32
    blob = bytearray(alice.session.save(storage_key))
    blob[-1] ^= 0x01

    with pytest.raises(SessionStateCorruptError):
        type(alice.session).load(bytes(blob), storage_key, alice.session.session_id)


def test_persisted_state_cannot_be_swapped_between_sessions(established):
    alice, bob = established
    storage_key = b"\x22" * 32
    blob = alice.session.save(storage_key)

    with pytest.raises(SessionStateCorruptError):
        type(alice.session).load(blob, storage_key, "some-other-session-id")


def test_persisted_state_requires_the_correct_storage_key(established):
    alice, bob = established
    blob = alice.session.save(b"\x33" * 32)

    with pytest.raises(SessionStateCorruptError):
        type(alice.session).load(blob, b"\x44" * 32, alice.session.session_id)


# --- T8: malformed input ----------------------------------------------------

@pytest.mark.parametrize("mutation", [
    {"v": 99},
    {"type": "plaintext"},
    {"ciphertext": "!!!not base64!!!"},
    {"header": ""},
    {"ciphertext": ""},
])
def test_malformed_envelopes_are_rejected(established, mutation):
    alice, bob = established
    obj = alice.send(b"payload").to_json()
    obj.update(mutation)
    with pytest.raises((InvalidEncodingError, ValueError)):
        Envelope.from_json(obj)


def test_oversized_ciphertext_is_rejected_before_crypto(established):
    alice, bob = established
    obj = alice.send(b"payload").to_json()
    obj["ciphertext"] = base64.b64encode(b"\x00" * (64 * 1024 + 1)).decode()
    with pytest.raises(InvalidEncodingError):
        Envelope.from_json(obj)
