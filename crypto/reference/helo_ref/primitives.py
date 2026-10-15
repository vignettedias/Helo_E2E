"""Cryptographic primitive layer.

DESIGN RULE: this module contains NO hand-implemented cryptographic
primitives. Every operation delegates to `cryptography` (which binds OpenSSL).
AES, SHA-256, HMAC, HKDF, X25519 and Ed25519 are used as provided.

The only logic implemented here is:
  * domain separation and encoding of KDF inputs,
  * key validation,
  * an injectable randomness source (so test vectors are reproducible while
    production always uses the OS CSPRNG).

Algorithm selection
-------------------
  DH / key agreement   X25519                 (RFC 7748)
  Signatures           Ed25519                (RFC 8032)
  Hash                 SHA-256                (FIPS 180-4)
  MAC                  HMAC-SHA-256           (RFC 2104)
  KDF                  HKDF-SHA-256           (RFC 5869)
  AEAD                 AES-256-GCM            (NIST SP 800-38D)
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Protocol

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .errors import AuthenticationError, InvalidKeyError, SignatureVerificationError

# --- Sizes (bytes) ----------------------------------------------------------

X25519_KEY_LEN = 32
ED25519_PUB_LEN = 32
ED25519_SEED_LEN = 32
ED25519_SIG_LEN = 64
AES256_KEY_LEN = 32
AES_GCM_NONCE_LEN = 12
AES_GCM_TAG_LEN = 16
SHA256_LEN = 32
ROOT_KEY_LEN = 32
CHAIN_KEY_LEN = 32
MESSAGE_KEY_LEN = 32

# --- Domain separation constants -------------------------------------------
# Every KDF invocation in Helo carries a distinct, versioned info string.
# Reusing an info string across contexts is a protocol bug.

INFO_X3DH = b"Helo_X3DH_v1"
INFO_ROOT_RATCHET = b"Helo_RootRatchet_v1"
INFO_MESSAGE_KEYS = b"Helo_MessageKeys_v1"
INFO_FINGERPRINT = b"Helo_Fingerprint_v1"
INFO_STATE_ENCRYPTION = b"Helo_SessionStateKey_v1"

# Chain-key ratchet constants (Signal Double Ratchet spec, section "KDF chains").
CHAIN_CONST_MESSAGE_KEY = b"\x01"
CHAIN_CONST_NEXT_CHAIN_KEY = b"\x02"

ZERO_SALT = b"\x00" * SHA256_LEN


# ---------------------------------------------------------------------------
# Randomness
# ---------------------------------------------------------------------------

class RandomSource(Protocol):
    """Source of cryptographically secure random bytes."""

    def bytes(self, n: int) -> bytes:  # pragma: no cover - protocol
        ...


class SystemRandom:
    """Production randomness: the operating-system CSPRNG.

    This is the ONLY randomness source permitted in a shipping build.
    """

    def bytes(self, n: int) -> bytes:
        return os.urandom(n)


DEFAULT_RANDOM: RandomSource = SystemRandom()


# ---------------------------------------------------------------------------
# Hash / MAC / KDF
# ---------------------------------------------------------------------------

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def constant_time_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA-256 (extract-then-expand)."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


# ---------------------------------------------------------------------------
# Key validation
# ---------------------------------------------------------------------------

# X25519 points of small order. RFC 7748 permits implementations to reject
# these; we reject them explicitly so a hostile peer cannot force a shared
# secret with a known/degenerate value.
_SMALL_ORDER_X25519 = {
    bytes(32),
    b"\x01" + bytes(31),
    bytes.fromhex(
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"
    ),
    bytes.fromhex(
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"
    ),
    bytes.fromhex(
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
    ),
    bytes.fromhex(
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
    ),
    bytes.fromhex(
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
    ),
    bytes.fromhex(
        "cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880"
    ),
    bytes.fromhex(
        "4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7"
    ),
    bytes.fromhex(
        "d9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    ),
    bytes.fromhex(
        "daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    ),
    bytes.fromhex(
        "dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    ),
}


def validate_x25519_public(pub: bytes) -> bytes:
    """Reject structurally invalid or low-order X25519 public keys."""
    if not isinstance(pub, (bytes, bytearray)):
        raise InvalidKeyError("X25519 public key must be bytes")
    pub = bytes(pub)
    if len(pub) != X25519_KEY_LEN:
        raise InvalidKeyError(
            f"X25519 public key must be {X25519_KEY_LEN} bytes, got {len(pub)}"
        )
    if pub in _SMALL_ORDER_X25519:
        raise InvalidKeyError("X25519 public key is a low-order point")
    return pub


def validate_ed25519_public(pub: bytes) -> bytes:
    if not isinstance(pub, (bytes, bytearray)):
        raise InvalidKeyError("Ed25519 public key must be bytes")
    pub = bytes(pub)
    if len(pub) != ED25519_PUB_LEN:
        raise InvalidKeyError(
            f"Ed25519 public key must be {ED25519_PUB_LEN} bytes, got {len(pub)}"
        )
    try:
        Ed25519PublicKey.from_public_bytes(pub)
    except Exception as exc:
        raise InvalidKeyError("Ed25519 public key is not a valid point") from exc
    return pub


# ---------------------------------------------------------------------------
# X25519 (Diffie-Hellman)
# ---------------------------------------------------------------------------

def x25519_generate(rng: RandomSource = DEFAULT_RANDOM) -> tuple[bytes, bytes]:
    """Generate an X25519 key pair. Returns (private_bytes, public_bytes)."""
    seed = rng.bytes(X25519_KEY_LEN)
    return x25519_from_private(seed)


def x25519_from_private(private: bytes) -> tuple[bytes, bytes]:
    """Derive the public key for a raw X25519 private scalar."""
    if len(private) != X25519_KEY_LEN:
        raise InvalidKeyError("X25519 private key must be 32 bytes")
    sk = X25519PrivateKey.from_private_bytes(private)
    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    # Note: `cryptography` clamps internally; re-export the canonical private
    # bytes so serialised state always round-trips identically.
    priv = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return priv, pub


def x25519_dh(private: bytes, peer_public: bytes) -> bytes:
    """X25519 key agreement. Rejects low-order peer keys before use."""
    peer_public = validate_x25519_public(peer_public)
    if len(private) != X25519_KEY_LEN:
        raise InvalidKeyError("X25519 private key must be 32 bytes")
    sk = X25519PrivateKey.from_private_bytes(private)
    shared = sk.exchange(X25519PublicKey.from_public_bytes(peer_public))
    if shared == bytes(X25519_KEY_LEN):
        # Belt-and-braces: an all-zero shared secret means a degenerate point
        # slipped through validation. Fail closed rather than derive from it.
        raise InvalidKeyError("X25519 produced an all-zero shared secret")
    return shared


# ---------------------------------------------------------------------------
# Ed25519 (signatures)
# ---------------------------------------------------------------------------

def ed25519_generate(rng: RandomSource = DEFAULT_RANDOM) -> tuple[bytes, bytes]:
    """Generate an Ed25519 key pair. Returns (seed_bytes, public_bytes)."""
    seed = rng.bytes(ED25519_SEED_LEN)
    return ed25519_from_seed(seed)


def ed25519_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    if len(seed) != ED25519_SEED_LEN:
        raise InvalidKeyError("Ed25519 seed must be 32 bytes")
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return seed, pub


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    if len(seed) != ED25519_SEED_LEN:
        raise InvalidKeyError("Ed25519 seed must be 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(seed).sign(message)


def ed25519_verify(public: bytes, signature: bytes, message: bytes) -> None:
    """Verify an Ed25519 signature. Raises SignatureVerificationError on failure."""
    public = validate_ed25519_public(public)
    if len(signature) != ED25519_SIG_LEN:
        raise SignatureVerificationError("Ed25519 signature must be 64 bytes")
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
    except InvalidSignature as exc:
        raise SignatureVerificationError("Ed25519 signature verification failed") from exc


# ---------------------------------------------------------------------------
# AEAD
# ---------------------------------------------------------------------------

def aes256gcm_encrypt(
    key: bytes, nonce: bytes, plaintext: bytes, associated_data: bytes
) -> bytes:
    """AES-256-GCM seal. Returns ciphertext || tag (tag is the trailing 16 bytes)."""
    if len(key) != AES256_KEY_LEN:
        raise InvalidKeyError("AES-256-GCM key must be 32 bytes")
    if len(nonce) != AES_GCM_NONCE_LEN:
        raise InvalidKeyError("AES-GCM nonce must be 12 bytes")
    return AESGCM(key).encrypt(nonce, plaintext, associated_data)


def aes256gcm_decrypt(
    key: bytes, nonce: bytes, ciphertext_and_tag: bytes, associated_data: bytes
) -> bytes:
    """AES-256-GCM open. Raises AuthenticationError if the tag does not verify.

    The plaintext is NEVER returned on authentication failure, and no partial
    plaintext is exposed: `cryptography` verifies the tag before release.
    """
    if len(key) != AES256_KEY_LEN:
        raise InvalidKeyError("AES-256-GCM key must be 32 bytes")
    if len(nonce) != AES_GCM_NONCE_LEN:
        raise InvalidKeyError("AES-GCM nonce must be 12 bytes")
    if len(ciphertext_and_tag) < AES_GCM_TAG_LEN:
        raise AuthenticationError("ciphertext shorter than the authentication tag")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext_and_tag, associated_data)
    except InvalidTag as exc:
        raise AuthenticationError("AEAD authentication failed") from exc


# ---------------------------------------------------------------------------
# Key hygiene
# ---------------------------------------------------------------------------

def wipe(buf: bytearray) -> None:
    """Best-effort zeroisation of a mutable buffer.

    LIMITATION (documented, not hidden): in a managed runtime this cannot
    guarantee erasure. Copies may persist in GC'd memory, in swap, or in
    hibernation images. This is an accepted limitation recorded in SECURITY.md
    under "Endpoint security limitations"; it is not a claim of secure erasure.
    """
    for i in range(len(buf)):
        buf[i] = 0
