"""Canonical wire encoding.

Everything that is fed into a signature, a KDF, or AEAD associated data must
have exactly one byte representation. Ambiguous encoding is a real attack
surface: if two distinct logical structures can serialise to the same bytes,
an attacker can substitute one for the other without breaking authentication.

Rules enforced here:
  * All variable-length fields are length-prefixed (big-endian uint16).
  * All integers are fixed-width big-endian.
  * Structures carry a leading version byte.
  * Decoders reject trailing bytes and short reads.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from .errors import InvalidEncodingError
from .primitives import X25519_KEY_LEN, validate_x25519_public

PROTOCOL_VERSION = 1
MAX_LP_LEN = 0xFFFF


# --- Integer / length-prefix helpers ---------------------------------------

def u8(value: int) -> bytes:
    if not 0 <= value <= 0xFF:
        raise InvalidEncodingError(f"uint8 out of range: {value}")
    return value.to_bytes(1, "big")


def u32(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFFFF:
        raise InvalidEncodingError(f"uint32 out of range: {value}")
    return value.to_bytes(4, "big")


def lp(data: bytes) -> bytes:
    """Length-prefix a byte string with a big-endian uint16."""
    if len(data) > MAX_LP_LEN:
        raise InvalidEncodingError("field exceeds maximum length-prefixed size")
    return len(data).to_bytes(2, "big") + data


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str, *, expect_len: int | None = None) -> bytes:
    try:
        raw = base64.b64decode(text, validate=True)
    except Exception as exc:
        raise InvalidEncodingError("invalid base64 field") from exc
    if expect_len is not None and len(raw) != expect_len:
        raise InvalidEncodingError(
            f"field must decode to {expect_len} bytes, got {len(raw)}"
        )
    return raw


class Reader:
    """Strict sequential byte reader."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def take(self, n: int) -> bytes:
        if n < 0 or self._pos + n > len(self._data):
            raise InvalidEncodingError("truncated structure")
        chunk = self._data[self._pos : self._pos + n]
        self._pos += n
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "big")

    def finish(self) -> None:
        if self._pos != len(self._data):
            raise InvalidEncodingError("trailing bytes after structure")


# --- Double Ratchet header --------------------------------------------------

HEADER_LEN = 1 + X25519_KEY_LEN + 4 + 4  # version | dh_pub | pn | n


@dataclass(frozen=True)
class RatchetHeader:
    """Plaintext-but-authenticated Double Ratchet header.

    These fields are visible to the relay by necessity (the recipient needs
    them to select a chain). They are covered by AEAD associated data, so the
    relay cannot modify them without causing decryption to fail.

      dh_pub  sender's current ratchet public key
      pn      number of messages in the sender's PREVIOUS sending chain
      n       message index within the sender's CURRENT sending chain
    """

    dh_pub: bytes
    pn: int
    n: int
    version: int = PROTOCOL_VERSION

    def encode(self) -> bytes:
        return u8(self.version) + validate_x25519_public(self.dh_pub) + u32(self.pn) + u32(self.n)

    @staticmethod
    def decode(data: bytes) -> RatchetHeader:
        r = Reader(data)
        version = r.u8()
        if version != PROTOCOL_VERSION:
            raise InvalidEncodingError(f"unsupported protocol version {version}")
        dh_pub = validate_x25519_public(r.take(X25519_KEY_LEN))
        pn = r.u32()
        n = r.u32()
        r.finish()
        return RatchetHeader(dh_pub=dh_pub, pn=pn, n=n, version=version)
