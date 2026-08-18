"""Prekey infrastructure.

The relay stores PUBLIC prekey material so that Alice can start a session while
Bob is offline. The relay is untrusted, so every field Alice consumes is either
signed by Bob's identity key or bound into the session transcript.

  SignedPreKey    X25519, rotated periodically, signature by IK_sig.
  OneTimePreKey   X25519, consumed once, NOT individually signed.

Why one-time prekeys are not signed
-----------------------------------
Signal does not sign them either. A malicious relay can serve a stale or absent
OPK, which downgrades Alice to the three-DH variant. That does not break
authentication (DH1 and DH2 still bind both identity keys) but it does weaken
forward secrecy for the very first message if Bob's signed prekey private key
is later compromised. This is documented in SECURITY.md rather than papered
over: a relay CAN force OPK omission, and the client surfaces it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .encoding import b64d, b64e, lp, u8, u32
from .errors import InvalidEncodingError, PreKeyUnavailableError
from .identity import IdentityKeyPair, IdentityPublic
from .primitives import (
    DEFAULT_RANDOM,
    ED25519_SIG_LEN,
    X25519_KEY_LEN,
    RandomSource,
    ed25519_verify,
    validate_x25519_public,
    x25519_generate,
)

SIGNED_PREKEY_CONTEXT = b"Helo_SignedPreKey_v1"

# Lifecycle policy (see docs/protocol/key-lifecycle.md)
SIGNED_PREKEY_ROTATION_SECONDS = 7 * 24 * 60 * 60      # rotate weekly
SIGNED_PREKEY_RETENTION_SECONDS = 30 * 24 * 60 * 60    # keep old private key 30d
ONE_TIME_PREKEY_BATCH = 100
ONE_TIME_PREKEY_LOW_WATERMARK = 20


def signed_prekey_signing_input(key_id: int, public: bytes) -> bytes:
    """Exactly what IK_sig signs. Includes the key id to prevent id swapping."""
    return SIGNED_PREKEY_CONTEXT + u32(key_id) + lp(public)


@dataclass
class PreKeyPrivate:
    """A prekey private half. SECRET; lives only in secure storage."""

    key_id: int
    private: bytes
    public: bytes
    created_at: int


@dataclass
class SignedPreKeyPublic:
    key_id: int
    public: bytes
    signature: bytes
    created_at: int

    def verify(self, identity: IdentityPublic) -> None:
        """Verify the signed prekey against the peer identity. Fails closed."""
        validate_x25519_public(self.public)
        ed25519_verify(
            identity.sig_pub,
            self.signature,
            signed_prekey_signing_input(self.key_id, self.public),
        )

    def to_json(self) -> dict:
        return {
            "key_id": self.key_id,
            "public": b64e(self.public),
            "signature": b64e(self.signature),
            "created_at": self.created_at,
        }

    @staticmethod
    def from_json(obj: dict) -> "SignedPreKeyPublic":
        try:
            return SignedPreKeyPublic(
                key_id=int(obj["key_id"]),
                public=b64d(obj["public"], expect_len=X25519_KEY_LEN),
                signature=b64d(obj["signature"], expect_len=ED25519_SIG_LEN),
                created_at=int(obj["created_at"]),
            )
        except KeyError as exc:
            raise InvalidEncodingError(f"signed prekey missing field {exc}") from exc


@dataclass
class OneTimePreKeyPublic:
    key_id: int
    public: bytes

    def to_json(self) -> dict:
        return {"key_id": self.key_id, "public": b64e(self.public)}

    @staticmethod
    def from_json(obj: dict) -> "OneTimePreKeyPublic":
        try:
            return OneTimePreKeyPublic(
                key_id=int(obj["key_id"]),
                public=b64d(obj["public"], expect_len=X25519_KEY_LEN),
            )
        except KeyError as exc:
            raise InvalidEncodingError(f"one-time prekey missing field {exc}") from exc


@dataclass
class PreKeyBundle:
    """What the relay serves to a client wishing to start a session.

    Data classification:
      identity            PUBLIC (cryptographic material)
      signed_prekey       PUBLIC (cryptographic material)
      one_time_prekey     PUBLIC (cryptographic material), consumed on fetch
      device_id           SENSITIVE METADATA
    """

    device_id: str
    identity: IdentityPublic
    signed_prekey: SignedPreKeyPublic
    one_time_prekey: OneTimePreKeyPublic | None = None

    def verify(self) -> None:
        """Validate everything before any DH is performed.

        Order matters: the identity binding is checked FIRST, because the
        signed-prekey signature is only meaningful once IK_sig is known to
        genuinely belong to this identity.
        """
        self.identity.verify_binding()
        self.signed_prekey.verify(self.identity)
        if self.one_time_prekey is not None:
            validate_x25519_public(self.one_time_prekey.public)

    def to_json(self) -> dict:
        return {
            "device_id": self.device_id,
            "identity": self.identity.to_json(),
            "signed_prekey": self.signed_prekey.to_json(),
            "one_time_prekey": (
                self.one_time_prekey.to_json() if self.one_time_prekey else None
            ),
        }

    @staticmethod
    def from_json(obj: dict) -> "PreKeyBundle":
        try:
            otp = obj.get("one_time_prekey")
            return PreKeyBundle(
                device_id=str(obj["device_id"]),
                identity=IdentityPublic.from_json(obj["identity"]),
                signed_prekey=SignedPreKeyPublic.from_json(obj["signed_prekey"]),
                one_time_prekey=OneTimePreKeyPublic.from_json(otp) if otp else None,
            )
        except KeyError as exc:
            raise InvalidEncodingError(f"prekey bundle missing field {exc}") from exc


class PreKeyStore:
    """Client-side prekey lifecycle manager.

    Owns generation, publication, consumption and expiry of prekey material.
    Private halves never leave this object; on device it is backed by
    CryptoStorage.
    """

    def __init__(
        self,
        identity: IdentityKeyPair,
        rng: RandomSource = DEFAULT_RANDOM,
        clock=time.time,
    ) -> None:
        self._identity = identity
        self._rng = rng
        self._clock = clock
        self._signed: dict[int, PreKeyPrivate] = {}
        self._signed_public: dict[int, SignedPreKeyPublic] = {}
        self._current_signed_id: int | None = None
        self._one_time: dict[int, PreKeyPrivate] = {}
        self._next_signed_id = 1
        self._next_one_time_id = 1

    # -- Signed prekeys ----------------------------------------------------

    def rotate_signed_prekey(self) -> SignedPreKeyPublic:
        key_id = self._next_signed_id
        self._next_signed_id += 1
        priv, pub = x25519_generate(self._rng)
        now = int(self._clock())
        signature = self._identity.sign(signed_prekey_signing_input(key_id, pub))
        self._signed[key_id] = PreKeyPrivate(key_id, priv, pub, now)
        record = SignedPreKeyPublic(key_id, pub, signature, now)
        self._signed_public[key_id] = record
        self._current_signed_id = key_id
        return record

    def current_signed_prekey(self) -> SignedPreKeyPublic:
        if self._current_signed_id is None:
            return self.rotate_signed_prekey()
        return self._signed_public[self._current_signed_id]

    def needs_signed_prekey_rotation(self) -> bool:
        if self._current_signed_id is None:
            return True
        created = self._signed[self._current_signed_id].created_at
        return int(self._clock()) - created >= SIGNED_PREKEY_ROTATION_SECONDS

    def prune_expired_signed_prekeys(self) -> list[int]:
        """Delete signed-prekey private halves past their retention window.

        Deleting the private half is what actually delivers forward secrecy for
        the initial message; keeping it forever would silently defeat it.
        """
        now = int(self._clock())
        removed = []
        for key_id, record in list(self._signed.items()):
            if key_id == self._current_signed_id:
                continue
            if now - record.created_at >= SIGNED_PREKEY_RETENTION_SECONDS:
                del self._signed[key_id]
                self._signed_public.pop(key_id, None)
                removed.append(key_id)
        return removed

    # -- One-time prekeys --------------------------------------------------

    def generate_one_time_prekeys(
        self, count: int = ONE_TIME_PREKEY_BATCH
    ) -> list[OneTimePreKeyPublic]:
        out = []
        now = int(self._clock())
        for _ in range(count):
            key_id = self._next_one_time_id
            self._next_one_time_id += 1
            priv, pub = x25519_generate(self._rng)
            self._one_time[key_id] = PreKeyPrivate(key_id, priv, pub, now)
            out.append(OneTimePreKeyPublic(key_id, pub))
        return out

    def one_time_prekey_count(self) -> int:
        return len(self._one_time)

    def needs_one_time_replenishment(self) -> bool:
        return len(self._one_time) < ONE_TIME_PREKEY_LOW_WATERMARK

    # -- Consumption (receiver side) ---------------------------------------

    def signed_prekey_private(self, key_id: int) -> bytes:
        record = self._signed.get(key_id)
        if record is None:
            raise PreKeyUnavailableError(
                f"signed prekey {key_id} unknown or already expired"
            )
        return record.private

    def consume_one_time_prekey(self, key_id: int) -> bytes:
        """Return and DESTROY a one-time prekey private half.

        Destruction is what makes it one-time. A second attempt to use the same
        prekey id raises PreKeyUnavailableError, which is one of the layers
        that makes replay of an initial message fail.
        """
        record = self._one_time.pop(key_id, None)
        if record is None:
            raise PreKeyUnavailableError(
                f"one-time prekey {key_id} unknown or already consumed"
            )
        return record.private

    def publish_bundle(self, device_id: str) -> PreKeyBundle:
        """Build the bundle this device publishes to the relay."""
        one_time = None
        if self._one_time:
            first = min(self._one_time)
            one_time = OneTimePreKeyPublic(first, self._one_time[first].public)
        return PreKeyBundle(
            device_id=device_id,
            identity=self._identity.public(),
            signed_prekey=self.current_signed_prekey(),
            one_time_prekey=one_time,
        )
