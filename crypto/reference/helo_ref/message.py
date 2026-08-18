"""The wire envelope: exactly what the untrusted relay sees.

Data classification of every field
----------------------------------
  version            PUBLIC
  type               PUBLIC              prekey (session-initiating) or normal
  session_id         SENSITIVE METADATA  links two devices' traffic together
  sender_device_id   SENSITIVE METADATA  routing
  x3dh               CRYPTOGRAPHIC MATERIAL (public halves only)
  header             CRYPTOGRAPHIC MATERIAL, authenticated but NOT encrypted
  ciphertext         CIPHERTEXT (includes the 16-byte GCM tag)

What the relay can therefore learn: who is talking to whom, when, how often,
how long each message is (to within the AEAD's exact expansion), and the
delivery state. It cannot learn message content. This is stated plainly here
rather than described as "zero knowledge", which would be false.

There is no `nonce` field. The nonce is derived from the message key -- see
ratchet.expand_message_key for why that is stronger than transmitting one.
"""

from __future__ import annotations

from dataclasses import dataclass

from .encoding import HEADER_LEN, PROTOCOL_VERSION, RatchetHeader, b64d, b64e
from .errors import InvalidEncodingError
from .primitives import AES_GCM_TAG_LEN
from .x3dh import InitialMessageHeader

MESSAGE_TYPE_PREKEY = "prekey"
MESSAGE_TYPE_NORMAL = "normal"

# Hard cap on accepted ciphertext, enforced before any crypto runs.
MAX_CIPHERTEXT_BYTES = 64 * 1024


@dataclass(frozen=True)
class Envelope:
    session_id: str
    sender_device_id: str
    header: RatchetHeader
    ciphertext: bytes
    x3dh: InitialMessageHeader | None = None
    version: int = PROTOCOL_VERSION

    @property
    def message_type(self) -> str:
        return MESSAGE_TYPE_PREKEY if self.x3dh is not None else MESSAGE_TYPE_NORMAL

    def to_json(self) -> dict:
        obj = {
            "v": self.version,
            "type": self.message_type,
            "session_id": self.session_id,
            "sender_device_id": self.sender_device_id,
            "header": b64e(self.header.encode()),
            "ciphertext": b64e(self.ciphertext),
        }
        if self.x3dh is not None:
            obj["x3dh"] = self.x3dh.to_json()
        return obj

    @staticmethod
    def from_json(obj: dict) -> "Envelope":
        """Parse and validate. Every bound is checked before any crypto runs."""
        try:
            version = int(obj["v"])
            if version != PROTOCOL_VERSION:
                raise InvalidEncodingError(f"unsupported envelope version {version}")

            msg_type = str(obj["type"])
            if msg_type not in (MESSAGE_TYPE_PREKEY, MESSAGE_TYPE_NORMAL):
                raise InvalidEncodingError(f"unknown message type {msg_type!r}")

            ciphertext = b64d(obj["ciphertext"])
            if len(ciphertext) < AES_GCM_TAG_LEN:
                raise InvalidEncodingError("ciphertext shorter than authentication tag")
            if len(ciphertext) > MAX_CIPHERTEXT_BYTES:
                raise InvalidEncodingError("ciphertext exceeds maximum accepted size")

            header = RatchetHeader.decode(b64d(obj["header"], expect_len=HEADER_LEN))

            x3dh_obj = obj.get("x3dh")
            if msg_type == MESSAGE_TYPE_PREKEY and x3dh_obj is None:
                raise InvalidEncodingError("prekey message is missing its x3dh header")
            if msg_type == MESSAGE_TYPE_NORMAL and x3dh_obj is not None:
                raise InvalidEncodingError("normal message must not carry an x3dh header")

            return Envelope(
                version=version,
                session_id=str(obj["session_id"]),
                sender_device_id=str(obj["sender_device_id"]),
                header=header,
                ciphertext=ciphertext,
                x3dh=InitialMessageHeader.from_json(x3dh_obj) if x3dh_obj else None,
            )
        except KeyError as exc:
            raise InvalidEncodingError(f"envelope missing field {exc}") from exc
        except (TypeError, ValueError) as exc:
            raise InvalidEncodingError("envelope contains a malformed field") from exc

    def ciphertext_expansion(self, plaintext_len: int) -> int:
        """Bytes of overhead this envelope adds over the raw plaintext."""
        return len(self.ciphertext) - plaintext_len + HEADER_LEN
