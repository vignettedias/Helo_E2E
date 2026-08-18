import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "crypto" / "reference"))

from helo_ref.identity import IdentityKeyPair
from helo_ref.message import Envelope
from helo_ref.prekeys import PreKeyStore
from helo_ref.session import start_as_initiator, start_as_responder


def wire(envelope):
    """Force every message through a full JSON serialise/parse round trip.

    Tests that skip this can accidentally pass by sharing Python objects
    between the two parties, which would hide encoding bugs entirely.
    """
    return Envelope.from_json(envelope.to_json())


class Party:
    def __init__(self, name, one_time_prekeys=10):
        self.name = name
        self.device_id = f"{name}-device-1"
        self.identity = IdentityKeyPair.generate()
        self.prekeys = PreKeyStore(self.identity)
        self.prekeys.rotate_signed_prekey()
        self.prekeys.generate_one_time_prekeys(one_time_prekeys)
        self.session = None

    def bundle(self):
        return self.prekeys.publish_bundle(self.device_id)

    def start_with(self, peer):
        self.session = start_as_initiator(self.identity, self.device_id, peer.bundle())
        return self.session

    def accept(self, envelope):
        self.session = start_as_responder(
            self.identity, self.device_id, self.prekeys, wire(envelope)
        )
        return self.session

    def send(self, text: bytes):
        return self.session.encrypt(text)

    def recv(self, envelope):
        return self.session.decrypt(wire(envelope))


@pytest.fixture
def alice():
    return Party("alice")


@pytest.fixture
def bob():
    return Party("bob")


@pytest.fixture
def established(alice, bob):
    """A live, bidirectional session between Alice and Bob."""
    alice.start_with(bob)
    first = alice.send(b"handshake")
    bob.accept(first)
    assert bob.recv(first) == b"handshake"
    reply = bob.send(b"handshake-ack")
    assert alice.recv(reply) == b"handshake-ack"
    return alice, bob
