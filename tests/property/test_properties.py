"""Property-based tests.

Hand-written test cases encode the failures the author already thought of.
These properties are quantified over randomly generated inputs, so they explore
delivery interleavings and mutations nobody wrote down -- and Hypothesis
shrinks any counterexample to a minimal reproduction.
"""

import base64

import pytest
from conftest import Party, wire
from helo_ref.errors import (
    AuthenticationError,
    HeloError,
    ReplayError,
    TooManySkippedMessagesError,
)
from helo_ref.message import Envelope
from helo_ref.primitives import aes256gcm_decrypt, aes256gcm_encrypt
from helo_ref.ratchet import expand_message_key, kdf_chain, kdf_root
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

pytestmark = pytest.mark.property

SETTINGS = settings(
    max_examples=60,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)


def fresh_pair():
    alice, bob = Party("alice"), Party("bob")
    alice.start_with(bob)
    first = alice.send(b"init")
    bob.accept(first)
    bob.recv(first)
    alice.recv(bob.send(b"init-ack"))
    return alice, bob


# --- P1: correctness --------------------------------------------------------

@given(plaintext=st.binary(min_size=0, max_size=2048))
@SETTINGS
def test_encrypt_then_decrypt_is_identity(plaintext):
    """Encrypting and then decrypting valid plaintext with the correct key succeeds."""
    alice, bob = fresh_pair()
    assert bob.recv(alice.send(plaintext)) == plaintext


@given(messages=st.lists(st.binary(min_size=0, max_size=256), min_size=1, max_size=25))
@SETTINGS
def test_all_messages_decrypt_in_order(messages):
    alice, bob = fresh_pair()
    for m in messages:
        assert bob.recv(alice.send(m)) == m


# --- P2: out-of-order delivery ---------------------------------------------

@given(
    count=st.integers(min_value=2, max_value=15),
    seed=st.integers(min_value=0, max_value=2**32 - 1),
)
@SETTINGS
def test_any_delivery_permutation_eventually_decrypts(count, seed):
    """Valid out-of-order delivery eventually decrypts successfully.

    Quantified over ARBITRARY permutations, not just the reversal or the
    1,3,2,4 case that hand-written tests usually cover.
    """
    import random

    rng = random.Random(seed)
    alice, bob = fresh_pair()

    sent = [(i, alice.send(f"msg-{i}".encode())) for i in range(count)]
    order = list(range(count))
    rng.shuffle(order)

    received = {}
    for idx in order:
        i, env = sent[idx]
        received[i] = bob.recv(env)

    assert received == {i: f"msg-{i}".encode() for i in range(count)}


@given(
    count=st.integers(min_value=2, max_value=10),
    seed=st.integers(min_value=0, max_value=2**32 - 1),
)
@SETTINGS
def test_interleaved_bidirectional_traffic_always_decrypts(count, seed):
    import random

    rng = random.Random(seed)
    alice, bob = fresh_pair()

    for i in range(count):
        if rng.random() < 0.5:
            assert bob.recv(alice.send(f"a{i}".encode())) == f"a{i}".encode()
        else:
            assert alice.recv(bob.send(f"b{i}".encode())) == f"b{i}".encode()


# --- P3: tamper resistance --------------------------------------------------

@given(
    plaintext=st.binary(min_size=1, max_size=256),
    offset=st.integers(min_value=0, max_value=2**16),
    bit=st.integers(min_value=0, max_value=7),
)
@SETTINGS
def test_any_ciphertext_mutation_fails_authentication(plaintext, offset, bit):
    """Modifying ciphertext results in authentication failure -- for ANY bit.

    The index is taken modulo the ciphertext length rather than filtered with
    assume(), so every byte position (payload AND tag) is reachable and no
    generated input is wasted.
    """
    alice, bob = fresh_pair()
    env = alice.send(plaintext)
    ct = bytearray(env.ciphertext)
    byte_index = offset % len(ct)
    ct[byte_index] ^= 1 << bit

    obj = env.to_json()
    obj["ciphertext"] = base64.b64encode(bytes(ct)).decode()

    with pytest.raises(AuthenticationError):
        bob.session.decrypt(Envelope.from_json(obj))


@given(
    plaintext=st.binary(min_size=1, max_size=128),
    delta_n=st.integers(min_value=1, max_value=500),
)
@SETTINGS
def test_any_header_counter_mutation_fails(plaintext, delta_n):
    """Modifying authenticated metadata results in authentication failure."""
    from helo_ref.encoding import RatchetHeader

    alice, bob = fresh_pair()
    env = alice.send(plaintext)
    tampered = Envelope(
        session_id=env.session_id,
        sender_device_id=env.sender_device_id,
        header=RatchetHeader(
            dh_pub=env.header.dh_pub, pn=env.header.pn, n=env.header.n + delta_n
        ),
        ciphertext=env.ciphertext,
    )
    with pytest.raises((AuthenticationError, TooManySkippedMessagesError)):
        bob.session.decrypt(wire(tampered))


@given(
    plaintext=st.binary(min_size=1, max_size=128),
    ad_a=st.binary(min_size=0, max_size=64),
    ad_b=st.binary(min_size=0, max_size=64),
)
@SETTINGS
def test_aead_binds_associated_data(plaintext, ad_a, ad_b):
    assume(ad_a != ad_b)
    key, nonce = b"\x01" * 32, b"\x02" * 12
    ct = aes256gcm_encrypt(key, nonce, plaintext, ad_a)
    assert aes256gcm_decrypt(key, nonce, ct, ad_a) == plaintext
    with pytest.raises(AuthenticationError):
        aes256gcm_decrypt(key, nonce, ct, ad_b)


# --- P4: replay resistance --------------------------------------------------

@given(
    count=st.integers(min_value=1, max_value=10),
    replay_index=st.integers(min_value=0, max_value=9),
)
@SETTINGS
def test_replaying_any_delivered_message_is_rejected(count, replay_index):
    """A replayed message does not produce a second accepted logical message."""
    assume(replay_index < count)
    alice, bob = fresh_pair()

    sent = [alice.send(f"m{i}".encode()) for i in range(count)]
    for env in sent:
        bob.recv(env)

    with pytest.raises(ReplayError):
        bob.recv(sent[replay_index])


@given(count=st.integers(min_value=2, max_value=8))
@SETTINGS
def test_no_message_is_ever_delivered_twice(count):
    alice, bob = fresh_pair()
    sent = [alice.send(f"m{i}".encode()) for i in range(count)]

    delivered = 0
    for env in sent + sent:  # every message offered exactly twice
        try:
            bob.recv(env)
            delivered += 1
        except HeloError:
            pass
    assert delivered == count


# --- P5: key uniqueness -----------------------------------------------------

@given(count=st.integers(min_value=2, max_value=40))
@SETTINGS
def test_message_keys_and_nonces_never_repeat(count):
    """Reusing a consumed message key is impossible: every step yields a new one."""
    chain_key = b"\x42" * 32
    keys, nonces = set(), set()
    for _ in range(count):
        mk, chain_key = kdf_chain(chain_key)
        aes_key, nonce = expand_message_key(mk)
        assert mk not in keys
        keys.add(mk)
        nonces.add((aes_key, nonce))
    assert len(keys) == count
    assert len(nonces) == count


@given(
    root=st.binary(min_size=32, max_size=32),
    dh_a=st.binary(min_size=32, max_size=32),
    dh_b=st.binary(min_size=32, max_size=32),
)
@SETTINGS
def test_root_ratchet_is_injective_on_dh_input(root, dh_a, dh_b):
    assume(dh_a != dh_b)
    assert kdf_root(root, dh_a) != kdf_root(root, dh_b)


# --- P6: parser robustness --------------------------------------------------

@given(blob=st.binary(min_size=0, max_size=300))
@SETTINGS
def test_arbitrary_bytes_never_parse_into_a_valid_envelope(blob):
    """The parser must reject junk rather than crash with an unexpected error."""
    obj = {
        "v": 1,
        "type": "normal",
        "session_id": "x",
        "sender_device_id": "y",
        "header": base64.b64encode(blob).decode(),
        "ciphertext": base64.b64encode(blob).decode(),
    }
    with pytest.raises(HeloError):
        Envelope.from_json(obj)


@given(
    text=st.text(max_size=100),
)
@SETTINGS
def test_non_base64_fields_are_rejected_cleanly(text):
    obj = {
        "v": 1,
        "type": "normal",
        "session_id": "x",
        "sender_device_id": "y",
        "header": text,
        "ciphertext": text,
    }
    with pytest.raises(HeloError):
        Envelope.from_json(obj)
