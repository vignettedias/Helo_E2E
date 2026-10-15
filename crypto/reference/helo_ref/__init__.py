"""Helo reference protocol implementation.

STATUS: Classical X3DH + Double Ratchet implementation. NOT post-quantum secure.

This package is the NORMATIVE reference for the Helo protocol. The Dart /
Flutter client implementation must reproduce the test vectors this package
generates, byte for byte. Where the two disagree, this package defines the
protocol and the client is wrong.
"""

from .errors import (  # noqa: F401
    AuthenticationError,
    HeloError,
    IdentityChangedError,
    InvalidEncodingError,
    InvalidKeyError,
    InvalidStateTransitionError,
    PreKeyUnavailableError,
    ReplayError,
    SessionStateCorruptError,
    SignatureVerificationError,
    TooManySkippedMessagesError,
    UnknownSessionError,
)
from .identity import IdentityKeyPair, IdentityPublic, safety_number  # noqa: F401
from .message import Envelope  # noqa: F401
from .prekeys import PreKeyBundle, PreKeyStore  # noqa: F401
from .session import (  # noqa: F401
    Session,
    SessionState,
    VerificationStatus,
    start_as_initiator,
    start_as_responder,
)

PROTOCOL_NAME = "Helo/1 X3DH-Curve25519-SHA256 + DoubleRatchet + AES-256-GCM"
POST_QUANTUM = False
