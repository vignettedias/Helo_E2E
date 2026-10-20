"""ML-KEM-768 (FIPS 203) — thin wrapper over pyca/cryptography.

As with every other primitive in this package, nothing here implements the
algorithm: key generation, encapsulation and decapsulation are OpenSSL's,
reached through `cryptography`. This module only fixes the parameter set,
the byte encodings, and the injectable randomness for key generation.

Encodings
---------
  Encode(PQPK) = u8(KEM_ID_MLKEM768) || ek        (1 + 1184 bytes)

The KEM identifier is inside every signed and hashed encoding of a PQ public
key, so a key cannot be presented as belonging to a different KEM. This is the
mitigation the PQXDH specification adopted after formal analysis showed the
risk of KEM confusion.

Private keys are stored as the 64-byte FIPS 203 seed (d || z) and re-expanded
on use. Seeds are what both this package and the Dart client agree on, so a
key generated from the same seed has the same public key in both — checked by
the cross-implementation vectors.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM768PrivateKey,
    MLKEM768PublicKey,
)

from .errors import InvalidEncodingError, InvalidKeyError
from .primitives import DEFAULT_RANDOM, RandomSource

KEM_ID_MLKEM768 = 0x01
MLKEM768_EK_LEN = 1184
MLKEM768_CT_LEN = 1088
MLKEM768_SS_LEN = 32
MLKEM_SEED_LEN = 64
ENCODED_PQ_PUBLIC_LEN = 1 + MLKEM768_EK_LEN


def encode_pq_public(ek: bytes) -> bytes:
    if len(ek) != MLKEM768_EK_LEN:
        raise InvalidKeyError(f"ML-KEM-768 public key must be {MLKEM768_EK_LEN} bytes")
    return bytes([KEM_ID_MLKEM768]) + ek


def decode_pq_public(data: bytes) -> bytes:
    """Return the raw encapsulation key; reject any other KEM or length."""
    if len(data) != ENCODED_PQ_PUBLIC_LEN or data[0] != KEM_ID_MLKEM768:
        raise InvalidEncodingError("PQ public key is not an encoded ML-KEM-768 key")
    ek = bytes(data[1:])
    try:
        # pyca applies the FIPS 203 encapsulation-key modulus check here.
        MLKEM768PublicKey.from_public_bytes(ek)
    except ValueError as exc:
        raise InvalidKeyError("ML-KEM-768 public key failed validation") from exc
    return ek


class MLKEM768:
    """The KEM used by the hybrid handshake. Stateless; methods are static."""

    name = "ML-KEM-768"

    @staticmethod
    def generate(rng: RandomSource = DEFAULT_RANDOM) -> tuple[bytes, bytes]:
        """Return (seed, ek). The seed is the private key at rest."""
        seed = rng.bytes(MLKEM_SEED_LEN)
        return seed, MLKEM768.public_from_seed(seed)

    @staticmethod
    def public_from_seed(seed: bytes) -> bytes:
        if len(seed) != MLKEM_SEED_LEN:
            raise InvalidKeyError("ML-KEM seed must be 64 bytes")
        return MLKEM768PrivateKey.from_seed_bytes(seed).public_key().public_bytes_raw()

    @staticmethod
    def encapsulate(ek: bytes) -> tuple[bytes, bytes]:
        """Return (ciphertext, shared_secret). Randomness is OpenSSL's."""
        try:
            ss, ct = MLKEM768PublicKey.from_public_bytes(ek).encapsulate()
        except ValueError as exc:
            raise InvalidKeyError("ML-KEM-768 public key failed validation") from exc
        return ct, ss

    @staticmethod
    def decapsulate(seed: bytes, ct: bytes) -> bytes:
        """Implicit rejection: a malformed-but-well-sized ciphertext yields an
        unrelated secret rather than an error, so it surfaces later as an AEAD
        failure on the first message -- never as a distinguishable oracle."""
        if len(ct) != MLKEM768_CT_LEN:
            raise InvalidEncodingError(f"ML-KEM-768 ciphertext must be {MLKEM768_CT_LEN} bytes")
        if len(seed) != MLKEM_SEED_LEN:
            raise InvalidKeyError("ML-KEM seed must be 64 bytes")
        return MLKEM768PrivateKey.from_seed_bytes(seed).decapsulate(ct)
