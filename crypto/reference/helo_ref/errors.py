"""Helo protocol error taxonomy.

Every cryptographic failure path in Helo raises one of these. There is
deliberately NO error type that permits degraded operation: the protocol fails
closed. There is no plaintext fallback and no "decrypt best effort" mode.

Callers MUST NOT distinguish between AuthenticationError subcases in any
user-visible or network-visible way beyond "message rejected", to avoid
building an oracle for an active attacker.
"""


class HeloError(Exception):
    """Base class for all protocol errors."""


# --- Input / encoding -------------------------------------------------------

class InvalidEncodingError(HeloError):
    """A wire structure was malformed, truncated, or had illegal field sizes."""


class InvalidKeyError(HeloError):
    """A public key was structurally invalid or a low-order / all-zero point."""


# --- Identity & prekeys -----------------------------------------------------

class SignatureVerificationError(HeloError):
    """A signature over a prekey bundle or identity binding failed to verify."""


class IdentityChangedError(HeloError):
    """The peer presented an identity key differing from the pinned one."""


class PreKeyUnavailableError(HeloError):
    """A required prekey was missing or already consumed."""


# --- Session / ratchet ------------------------------------------------------

class UnknownSessionError(HeloError):
    """No session state exists for the referenced session id."""


class InvalidStateTransitionError(HeloError):
    """The protocol state machine rejected a transition."""


class SessionStateCorruptError(HeloError):
    """Persisted session state failed integrity validation on load."""


class TooManySkippedMessagesError(HeloError):
    """Skipped-message-key derivation exceeded the configured bound.

    Defence against an attacker forcing unbounded key derivation or unbounded
    memory growth by claiming an enormous message counter in a header.
    """


# --- Message layer ----------------------------------------------------------

class AuthenticationError(HeloError):
    """AEAD authentication failed: ciphertext, header, or AD was tampered with."""


class ReplayError(HeloError):
    """A ciphertext was replayed: its message key was already consumed."""
