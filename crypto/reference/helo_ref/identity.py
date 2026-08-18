"""Long-term identity.

DESIGN NOTE — deliberate deviation from Signal
----------------------------------------------
Signal uses a single Curve25519 identity key for both Diffie-Hellman and
signing, via XEdDSA. Helo instead uses TWO keys per identity:

    IK_sig   Ed25519   used only for signatures
    IK_dh    X25519    used only for key agreement

Rationale:
  1. Rule 28 of the specification forbids hand-rolling primitives. XEdDSA has
     no implementation in the mainstream Dart/Flutter crypto packages, so
     honouring Signal exactly would require writing it by hand.
  2. Using one key pair with two different algorithms is cross-algorithm key
     reuse, which is generally discouraged even where it is provably safe.

Cost of the deviation: an identity is 64 bytes of public material instead of
32, and both halves must be bound together. Binding is enforced by:
  * IK_sig signing IK_dh with a domain-separated context string, and
  * BOTH public keys being hashed into the fingerprint, and
  * BOTH public keys being covered by the X3DH associated data.

An attacker who substitutes IK_dh therefore breaks the binding signature, the
fingerprint, and the AEAD associated data simultaneously.
"""

from __future__ import annotations

from dataclasses import dataclass

from .encoding import b64d, b64e, lp, u8
from .errors import InvalidEncodingError
from .primitives import (
    DEFAULT_RANDOM,
    ED25519_PUB_LEN,
    INFO_FINGERPRINT,
    X25519_KEY_LEN,
    RandomSource,
    ed25519_generate,
    ed25519_sign,
    ed25519_verify,
    sha256,
    validate_ed25519_public,
    validate_x25519_public,
    x25519_generate,
)

IDENTITY_BINDING_CONTEXT = b"Helo_IdentityBinding_v1"

# Signal-style safety number: 2 x 30 decimal digits, rendered in 5-digit groups.
FINGERPRINT_ITERATIONS = 5200
SAFETY_NUMBER_CHUNKS = 6
SAFETY_NUMBER_DIGITS_PER_CHUNK = 5


@dataclass(frozen=True)
class IdentityPublic:
    """The public half of an identity. Safe to publish; safe to send to peers."""

    sig_pub: bytes  # Ed25519
    dh_pub: bytes   # X25519
    binding_sig: bytes  # IK_sig over the context + dh_pub

    def __post_init__(self) -> None:
        validate_ed25519_public(self.sig_pub)
        validate_x25519_public(self.dh_pub)

    def encode(self) -> bytes:
        """Canonical encoding used in fingerprints and AEAD associated data."""
        return u8(1) + lp(self.sig_pub) + lp(self.dh_pub)

    def verify_binding(self) -> None:
        """Verify that IK_sig actually attests to IK_dh.

        MUST be called on every identity received from the network before the
        identity is used for anything.
        """
        ed25519_verify(
            self.sig_pub, self.binding_sig, IDENTITY_BINDING_CONTEXT + self.dh_pub
        )

    def fingerprint(self) -> bytes:
        """32-byte identity fingerprint (iterated hash, Signal-style)."""
        data = INFO_FINGERPRINT + self.encode()
        digest = sha256(data)
        for _ in range(FINGERPRINT_ITERATIONS):
            digest = sha256(digest + self.encode())
        return digest

    def to_json(self) -> dict:
        return {
            "sig_pub": b64e(self.sig_pub),
            "dh_pub": b64e(self.dh_pub),
            "binding_sig": b64e(self.binding_sig),
        }

    @staticmethod
    def from_json(obj: dict) -> "IdentityPublic":
        try:
            return IdentityPublic(
                sig_pub=b64d(obj["sig_pub"], expect_len=ED25519_PUB_LEN),
                dh_pub=b64d(obj["dh_pub"], expect_len=X25519_KEY_LEN),
                binding_sig=b64d(obj["binding_sig"], expect_len=64),
            )
        except KeyError as exc:
            raise InvalidEncodingError(f"identity missing field {exc}") from exc


@dataclass
class IdentityKeyPair:
    """The full identity, including private material.

    The private fields of this object MUST NEVER be serialised to disk in the
    clear, transmitted, or logged. On device they live behind the CryptoStorage
    abstraction (Android Keystore / iOS Keychain).
    """

    sig_seed: bytes   # Ed25519 seed  -- SECRET
    sig_pub: bytes
    dh_priv: bytes    # X25519 scalar -- SECRET
    dh_pub: bytes
    binding_sig: bytes

    @staticmethod
    def generate(rng: RandomSource = DEFAULT_RANDOM) -> "IdentityKeyPair":
        sig_seed, sig_pub = ed25519_generate(rng)
        dh_priv, dh_pub = x25519_generate(rng)
        binding_sig = ed25519_sign(sig_seed, IDENTITY_BINDING_CONTEXT + dh_pub)
        return IdentityKeyPair(
            sig_seed=sig_seed,
            sig_pub=sig_pub,
            dh_priv=dh_priv,
            dh_pub=dh_pub,
            binding_sig=binding_sig,
        )

    def public(self) -> IdentityPublic:
        return IdentityPublic(
            sig_pub=self.sig_pub, dh_pub=self.dh_pub, binding_sig=self.binding_sig
        )

    def sign(self, message: bytes) -> bytes:
        return ed25519_sign(self.sig_seed, message)

    def __repr__(self) -> str:  # pragma: no cover - defensive
        # Never allow private material into a repr, a traceback, or a log line.
        return f"<IdentityKeyPair fp={self.public().fingerprint()[:4].hex()}... REDACTED>"


def safety_number(local: IdentityPublic, remote: IdentityPublic) -> str:
    """Compute the 60-digit safety number shown to both users.

    Both parties must see the SAME string, so the two identity fingerprints are
    sorted before combination. Displayed in five-digit groups.
    """
    fps = sorted([local.fingerprint(), remote.fingerprint()])
    combined = sha256(INFO_FINGERPRINT + b"|safety|" + fps[0] + fps[1])

    digits: list[str] = []
    for i in range(SAFETY_NUMBER_CHUNKS * 2):
        chunk = combined[i * 2 : i * 2 + 2] if i * 2 + 2 <= len(combined) else None
        if chunk is None:  # pragma: no cover - 32 bytes always suffices
            raise InvalidEncodingError("insufficient fingerprint material")
        value = int.from_bytes(chunk, "big") % 100000
        digits.append(f"{value:05d}")
    return " ".join(digits)


def qr_payload(local: IdentityPublic, remote_expected: IdentityPublic) -> str:
    """Payload encoded into the verification QR code.

    Contains ONLY public material: the scanner compares what it reads against
    the identity it already holds for that contact. Scanning does not import a
    new identity -- that would let an attacker inject one by QR.
    """
    return (
        "helo:v1:"
        + b64e(local.encode())
        + ":"
        + b64e(remote_expected.encode())
    )
