"""End-to-end encrypted attachments: chunked AES-256-GCM in the STREAM construction.

A file is encrypted on the sender's device under a FRESH random 32-byte key,
uploaded to the relay as ciphertext, and the key travels only inside an
end-to-end encrypted message. The relay stores bytes it cannot read.

STREAM (Hoang, Reyhanitabar, Rogaway, Vizar, CRYPTO 2015 -- the construction
behind `age` and Tink's streaming AEAD) splits the file into chunks, each
sealed with AES-256-GCM under a nonce that encodes the chunk's position and
whether it is the last:

    nonce_i = 0x00 * 7 || u32_be(i) || u8(is_final)        (12 bytes)
    AD      = "Helo_Attachment_v1"
    ciphertext = GCM(K, nonce_0, chunk_0) || ... || GCM(K, nonce_n, chunk_n)

Consequences, each covered by a test:
  * reordering chunks fails (a chunk only opens at its own index);
  * dropping trailing chunks fails (the new last chunk was sealed non-final);
  * appending or truncating bytes fails (segment boundaries break);
  * a nonce never repeats under a key, because the key is fresh per file and
    the index increases.

The SHA-256 of the whole ciphertext also travels in the encrypted message, so a
substituted blob is rejected before any decryption is attempted.
"""

from __future__ import annotations

import hashlib

from .encoding import u8, u32
from .errors import AuthenticationError, InvalidEncodingError
from .primitives import (
    AES256_KEY_LEN,
    AES_GCM_TAG_LEN,
    DEFAULT_RANDOM,
    RandomSource,
    aes256gcm_decrypt,
    aes256gcm_encrypt,
    constant_time_eq,
)

ATTACHMENT_AD = b"Helo_Attachment_v1"
CHUNK_SIZE = 64 * 1024
# Plaintext cap. The relay's default upload cap is 25 MiB of ciphertext.
MAX_ATTACHMENT_BYTES = 24 * 1024 * 1024
MAX_CHUNKS = 2**32 - 1


def generate_key(rng: RandomSource = DEFAULT_RANDOM) -> bytes:
    return rng.bytes(AES256_KEY_LEN)


def _nonce(index: int, final: bool) -> bytes:
    return bytes(7) + u32(index) + u8(1 if final else 0)


def ciphertext_length(plaintext_len: int, chunk_size: int = CHUNK_SIZE) -> int:
    chunks = max(1, -(-plaintext_len // chunk_size))
    return plaintext_len + chunks * AES_GCM_TAG_LEN


def encrypt(key: bytes, plaintext: bytes, chunk_size: int = CHUNK_SIZE) -> bytes:
    if len(plaintext) > MAX_ATTACHMENT_BYTES:
        raise InvalidEncodingError("attachment exceeds the maximum size")
    if chunk_size < 1:
        raise ValueError("chunk size must be positive")
    # An empty file is one empty final chunk, so it still authenticates.
    chunks = [plaintext[i : i + chunk_size] for i in range(0, len(plaintext), chunk_size)] or [b""]
    out = bytearray()
    for i, chunk in enumerate(chunks):
        out += aes256gcm_encrypt(key, _nonce(i, i == len(chunks) - 1), chunk, ATTACHMENT_AD)
    return bytes(out)


def decrypt(key: bytes, ciphertext: bytes, chunk_size: int = CHUNK_SIZE) -> bytes:
    """Decrypt and authenticate every chunk. Raises AuthenticationError on any
    tampering, truncation, extension or reordering; never returns partial data."""
    segment = chunk_size + AES_GCM_TAG_LEN
    if len(ciphertext) < AES_GCM_TAG_LEN:
        raise AuthenticationError("attachment ciphertext is truncated")
    count = -(-len(ciphertext) // segment)
    if count > MAX_CHUNKS:
        raise InvalidEncodingError("attachment has too many chunks")
    if len(ciphertext) - (count - 1) * segment < AES_GCM_TAG_LEN:
        # The final segment cannot even hold a tag: bytes were added or cut.
        raise AuthenticationError("attachment ciphertext has a malformed final chunk")
    out = bytearray()
    for i in range(count):
        part = ciphertext[i * segment : (i + 1) * segment]
        out += aes256gcm_decrypt(key, _nonce(i, i == count - 1), part, ATTACHMENT_AD)
    return bytes(out)


def digest(ciphertext: bytes) -> bytes:
    return hashlib.sha256(ciphertext).digest()


def verify_digest(ciphertext: bytes, expected: bytes) -> None:
    if not constant_time_eq(digest(ciphertext), expected):
        raise AuthenticationError("attachment ciphertext does not match its digest")
