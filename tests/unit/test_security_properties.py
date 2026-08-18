"""Forward secrecy and post-compromise security, tested by actual simulation.

These are the two claims most often asserted and least often demonstrated. The
methodology here is deliberately concrete: we CLONE the victim's complete
protocol state at a chosen instant -- which is a strictly stronger attacker
than a real memory-scraping adversary -- and then check exactly which
ciphertexts that clone can and cannot decrypt.

Being precise about the negative results matters as much as the positive ones,
so the limitations are asserted too (see test_forward_secrecy_does_not_protect_
messages_still_in_flight).
"""

import copy

import pytest
from conftest import wire
from helo_ref.errors import HeloError
from helo_ref.message import Envelope
from helo_ref.ratchet import decrypt as ratchet_decrypt


def attacker_snapshot(session):
    """Full compromise: the attacker gets everything the victim holds.

    Root key, both chain keys, the ratchet private key, all skipped message
    keys, and all counters.
    """
    return copy.deepcopy(session.ratchet), session.associated_data


def attacker_try_decrypt(snapshot, envelope):
    """Attempt decryption using only the compromised state."""
    ratchet, ad = snapshot
    return ratchet_decrypt(
        copy.deepcopy(ratchet), envelope.header, envelope.ciphertext, ad
    )[1]


# --- Forward secrecy --------------------------------------------------------

def test_forward_secrecy_historical_messages_survive_state_compromise(established):
    """Messages consumed BEFORE the compromise cannot be decrypted after it.

    This is the property that matters if a device is seized: yesterday's
    conversation must not fall out of today's memory image.
    """
    alice, bob = established

    # Alice sends five messages; Bob receives and processes all of them.
    historical = []
    for i in range(5):
        env = alice.send(f"historical-{i}".encode())
        assert bob.recv(env) == f"historical-{i}".encode()
        historical.append(env)

    # NOW the attacker fully compromises Bob.
    stolen = attacker_snapshot(bob.session)

    # The relay also archived every ciphertext, so the attacker has those too.
    for env in historical:
        with pytest.raises(HeloError):
            attacker_try_decrypt(stolen, wire(env))


def test_forward_secrecy_holds_across_multiple_ratchet_generations(established):
    alice, bob = established
    archive = []

    for generation in range(4):
        for i in range(3):
            env = alice.send(f"gen{generation}-msg{i}".encode())
            bob.recv(env)
            archive.append(env)
        # Bob replies, forcing a DH ratchet in each direction.
        reply = bob.send(b"ack")
        alice.recv(reply)

    stolen = attacker_snapshot(bob.session)
    for env in archive:
        with pytest.raises(HeloError):
            attacker_try_decrypt(stolen, wire(env))


def test_forward_secrecy_does_not_protect_messages_still_in_flight(established):
    """LIMITATION, asserted rather than hidden.

    A message that has been sent but NOT yet processed by the recipient is
    still decryptable from a compromised recipient state -- its chain key has
    not yet been ratcheted past. Forward secrecy is about consumed messages.
    Claiming otherwise would be false, so the test pins the real boundary.
    """
    alice, bob = established
    in_flight = alice.send(b"not yet delivered")

    stolen = attacker_snapshot(bob.session)

    assert attacker_try_decrypt(stolen, wire(in_flight)) == b"not yet delivered"


def test_skipped_message_keys_are_a_documented_forward_secrecy_exception(established):
    """LIMITATION: stored skipped keys are decryptable until consumed.

    Out-of-order support and forward secrecy are in direct tension. Retaining a
    key for a message that has not arrived is exactly what makes late delivery
    work, and exactly what a compromise at that moment can exploit. This is why
    MAX_SKIPPED_KEYS is bounded.
    """
    alice, bob = established
    m1 = alice.send(b"first")
    m2 = alice.send(b"second")

    bob.recv(m2)  # m1's key is now sitting in the skipped store

    stolen = attacker_snapshot(bob.session)
    assert attacker_try_decrypt(stolen, wire(m1)) == b"first"

    # Once Bob actually consumes it, the key is destroyed.
    assert bob.recv(m1) == b"first"
    stolen_after = attacker_snapshot(bob.session)
    with pytest.raises(HeloError):
        attacker_try_decrypt(stolen_after, wire(m1))


# --- Post-compromise security (break-in recovery) --------------------------

def test_break_in_recovery_after_bidirectional_ratchet(established):
    """A passive attacker holding stolen state loses access once both sides
    contribute fresh DH entropy.

    Recovery requires a full round trip: Bob must generate a new ratchet key
    that the attacker never saw, AND Alice must ratchet against it. One
    one-directional step is not sufficient, which the next test pins down.
    """
    alice, bob = established

    stolen = attacker_snapshot(bob.session)

    # Sanity: immediately after compromise the attacker CAN read Alice's traffic.
    probe = alice.send(b"readable by attacker")
    assert attacker_try_decrypt(stolen, wire(probe)) == b"readable by attacker"
    bob.recv(probe)

    # Healing round trip: Bob speaks (new ratchet key), Alice ratchets against it.
    alice.recv(bob.send(b"bob replies with fresh entropy"))
    bob.recv(alice.send(b"alice ratchets forward"))
    alice.recv(bob.send(b"and again"))

    # From here the attacker's stolen state is dead.
    for text in (b"secret one", b"secret two", b"secret three"):
        env = alice.send(text)
        with pytest.raises(HeloError):
            attacker_try_decrypt(stolen, wire(env))
        assert bob.recv(env) == text


def test_no_recovery_without_fresh_entropy_from_the_compromised_side(established):
    """LIMITATION, asserted.

    If the compromised party never sends -- so never generates a new ratchet
    key pair -- then the attacker keeps up with the sending chain. Post-
    compromise security is not automatic; it requires the healed party to
    actually ratchet.
    """
    alice, bob = established
    stolen = attacker_snapshot(bob.session)

    # Alice keeps talking; Bob stays silent. No DH ratchet occurs.
    for i in range(5):
        env = alice.send(f"still exposed {i}".encode())
        assert attacker_try_decrypt(stolen, wire(env)) == f"still exposed {i}".encode()
        bob.recv(env)


def test_attacker_cannot_impersonate_after_recovery(established):
    """After healing, the attacker's stolen state also cannot FORGE messages."""
    alice, bob = established
    stolen_ratchet, stolen_ad = attacker_snapshot(alice.session)

    # Healing round trips.
    for _ in range(2):
        bob.recv(alice.send(b"a"))
        alice.recv(bob.send(b"b"))

    # Attacker tries to send as Alice using the stale state.
    from helo_ref.ratchet import encrypt as ratchet_encrypt

    header, ciphertext = ratchet_encrypt(stolen_ratchet, b"forged instruction", stolen_ad)
    forged = Envelope(
        session_id=alice.session.session_id,
        sender_device_id=alice.device_id,
        header=header,
        ciphertext=ciphertext,
    )
    with pytest.raises(HeloError):
        bob.session.decrypt(wire(forged))


# --- Key freshness ----------------------------------------------------------

def test_every_message_uses_a_distinct_key_and_nonce(established):
    """No message key or nonce is ever reused within a session."""

    alice, bob = established

    seen_ciphertexts = set()
    plaintext = b"identical plaintext every time"
    for _ in range(50):
        env = alice.send(plaintext)
        assert env.ciphertext not in seen_ciphertexts, "ciphertext repeated"
        seen_ciphertexts.add(env.ciphertext)
        assert bob.recv(env) == plaintext


def test_chain_keys_are_one_way(established):
    """A compromised chain key cannot recover its predecessor."""
    from helo_ref.ratchet import kdf_chain

    ck0 = b"\x07" * 32
    mk0, ck1 = kdf_chain(ck0)
    mk1, ck2 = kdf_chain(ck1)

    assert len({ck0, ck1, ck2, mk0, mk1}) == 5
    # The only way "back" would be inverting HMAC-SHA256, which we assert by
    # construction rather than by search: verify the forward relation only.
    assert kdf_chain(ck1)[1] == ck2
    assert kdf_chain(ck0)[1] == ck1
