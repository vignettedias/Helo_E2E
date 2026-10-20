"""Plaintext padding: hide exact message length from the relay.

Without padding, ciphertext length = plaintext length + 57 bytes exactly, so
the relay learns every message's precise length. Padding rounds the plaintext
up to a size bucket BEFORE encryption, so only the bucket leaks.

Format (ISO/IEC 7816-4 bit padding):

    padded = payload || 0x80 || 0x00 * k        with len(padded) = bucket(len(payload) + 1)

Unpadding strips trailing zeros and requires the byte before them to be 0x80.
Padding is applied INSIDE the AEAD, so the relay cannot see or alter it, and
unpadding runs only on authenticated plaintext -- a malformed pad is never an
oracle an attacker can query.

Policies (compared in research/RESULTS.md)
------------------------------------------
  none     -> exact length + 1 (the marker byte)
  block    -> round up to a multiple of B bytes (default B = 256)
  pow2     -> round up to the next power of two, minimum M
  padme    -> Padmé (Nikitin et al., PETS 2019): at most ~12% overhead,
              leaks O(log log L) bits of length

This hides length within a bucket. It does NOT hide timing, frequency, or who
is talking to whom, and it is not traffic-analysis protection.
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import InvalidEncodingError

PAD_MARKER = 0x80
# Must stay below the envelope's ciphertext cap (message.MAX_CIPHERTEXT_BYTES,
# 64 KiB) after the 16-byte tag.
MAX_PADDED_LEN = 64 * 1024 - 16


@dataclass(frozen=True)
class PaddingPolicy:
    mode: str  # "none" | "block" | "pow2" | "padme"
    size: int = 0  # block size for "block", minimum for "pow2"

    def __post_init__(self) -> None:
        if self.mode not in ("none", "block", "pow2", "padme"):
            raise ValueError(f"unknown padding mode {self.mode!r}")
        if self.mode in ("block", "pow2") and self.size < 1:
            raise ValueError("block/pow2 padding needs a positive size")

    def target_length(self, n: int) -> int:
        """Padded length for `n` bytes INCLUDING the 0x80 marker (n >= 1)."""
        if n < 1:
            raise ValueError("length includes the marker byte, so it is >= 1")
        if self.mode == "none":
            return n
        if self.mode == "block":
            return -(-n // self.size) * self.size
        if self.mode == "pow2":
            target = max(self.size, 1)
            while target < n:
                target <<= 1
            return target
        return padme(n)

    @property
    def label(self) -> str:
        return self.mode if self.mode in ("none", "padme") else f"{self.mode}-{self.size}"


def padme(length: int) -> int:
    """Padmé padded length (Nikitin, Barman, Lueks, Underwood, Hubaux, Ford)."""
    if length < 2:
        return length
    e = length.bit_length() - 1       # floor(log2 L)
    s = e.bit_length()                # floor(log2 E) + 1
    last_bits = e - s
    mask = (1 << last_bits) - 1
    return (length + mask) & ~mask


DEFAULT_POLICY = PaddingPolicy("block", 256)
POLICIES = {
    "none": PaddingPolicy("none"),
    "block-160": PaddingPolicy("block", 160),
    "block-256": PaddingPolicy("block", 256),
    "pow2-256": PaddingPolicy("pow2", 256),
    "padme": PaddingPolicy("padme"),
}


def pad(payload: bytes, policy: PaddingPolicy = DEFAULT_POLICY) -> bytes:
    target = policy.target_length(len(payload) + 1)
    if target > MAX_PADDED_LEN:
        raise InvalidEncodingError(
            f"padded message would be {target} bytes; limit is {MAX_PADDED_LEN}"
        )
    return payload + bytes([PAD_MARKER]) + bytes(target - len(payload) - 1)


def unpad(padded: bytes) -> bytes:
    """Strip padding. Any input not of the form `... 0x80 0x00*` is rejected."""
    end = len(padded)
    while end > 0 and padded[end - 1] == 0x00:
        end -= 1
    if end == 0 or padded[end - 1] != PAD_MARKER:
        raise InvalidEncodingError("invalid padding: no 0x80 marker before the zero fill")
    return bytes(padded[: end - 1])
