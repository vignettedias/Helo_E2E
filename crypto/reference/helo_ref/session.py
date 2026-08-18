"""Session layer: the protocol state machine and encrypted state persistence.

State machine (enforced -- invalid transitions raise)
----------------------------------------------------

    UNINITIALIZED
         |  create identity
         v
    IDENTITY_CREATED
         |  publish prekey bundle
         v
    PREKEY_PUBLISHED
         |  X3DH completes (either role)
         v
    SESSION_ESTABLISHED
         |  first successful encrypt/decrypt
         v
    SESSION_ACTIVE  <---> RATCHETING   (DH ratchet step in flight)
         |
         |  device revoked / identity changed / account reset
         v
    SESSION_REVOKED   (terminal -- no further crypto permitted)

A revoked session is terminal on purpose. "Recover by resetting the state" is
how implementations accidentally build a downgrade path.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum

from .encoding import b64d, b64e
from .errors import (
    IdentityChangedError,
    InvalidStateTransitionError,
    SessionStateCorruptError,
    UnknownSessionError,
)
from .identity import IdentityKeyPair, IdentityPublic
from .message import Envelope
from .prekeys import PreKeyBundle, PreKeyStore
from .primitives import (
    AES256_KEY_LEN,
    AES_GCM_NONCE_LEN,
    DEFAULT_RANDOM,
    INFO_STATE_ENCRYPTION,
    RandomSource,
    aes256gcm_decrypt,
    aes256gcm_encrypt,
    hkdf,
    sha256,
)
from .ratchet import RatchetState, init_initiator, init_responder
from .ratchet import decrypt as ratchet_decrypt
from .ratchet import encrypt as ratchet_encrypt
from .x3dh import ClassicalX3DH, X3DHResult

# Module-level singleton. Constructing this inside a default argument builds the
# instance once at import time and shares it implicitly -- the mutable-default
# trap. Naming it here makes the sharing explicit, and gives PQXDH a single
# place to be swapped in later.
DEFAULT_KEY_ESTABLISHMENT = ClassicalX3DH()

STATE_FORMAT_VERSION = 1


class SessionState(Enum):
    UNINITIALIZED = "UNINITIALIZED"
    IDENTITY_CREATED = "IDENTITY_CREATED"
    PREKEY_PUBLISHED = "PREKEY_PUBLISHED"
    SESSION_ESTABLISHED = "SESSION_ESTABLISHED"
    RATCHETING = "RATCHETING"
    SESSION_ACTIVE = "SESSION_ACTIVE"
    SESSION_REVOKED = "SESSION_REVOKED"


_ALLOWED_TRANSITIONS: dict[SessionState, set[SessionState]] = {
    SessionState.UNINITIALIZED: {SessionState.IDENTITY_CREATED},
    SessionState.IDENTITY_CREATED: {SessionState.PREKEY_PUBLISHED},
    SessionState.PREKEY_PUBLISHED: {SessionState.SESSION_ESTABLISHED},
    SessionState.SESSION_ESTABLISHED: {
        SessionState.SESSION_ACTIVE,
        SessionState.RATCHETING,
        SessionState.SESSION_REVOKED,
    },
    SessionState.SESSION_ACTIVE: {
        SessionState.RATCHETING,
        SessionState.SESSION_ACTIVE,
        SessionState.SESSION_REVOKED,
    },
    SessionState.RATCHETING: {
        SessionState.SESSION_ACTIVE,
        SessionState.SESSION_REVOKED,
    },
    SessionState.SESSION_REVOKED: set(),
}


class VerificationStatus(Enum):
    UNVERIFIED = "UNVERIFIED"
    VERIFIED = "VERIFIED"
    IDENTITY_CHANGED = "IDENTITY_CHANGED"


@dataclass
class Session:
    """One end of one cryptographic conversation with one peer device."""

    session_id: str
    local_device_id: str
    remote_identity: IdentityPublic
    ratchet: RatchetState
    associated_data: bytes
    state: SessionState = SessionState.SESSION_ESTABLISHED
    verification: VerificationStatus = VerificationStatus.UNVERIFIED
    # Alice repeats the X3DH header until Bob demonstrably has the session.
    pending_x3dh: object | None = None
    used_one_time_prekey: bool = True

    # -- state machine ------------------------------------------------------

    def _transition(self, target: SessionState) -> None:
        if target not in _ALLOWED_TRANSITIONS[self.state]:
            raise InvalidStateTransitionError(
                f"illegal transition {self.state.value} -> {target.value}"
            )
        self.state = target

    def _require_usable(self) -> None:
        if self.state is SessionState.SESSION_REVOKED:
            raise InvalidStateTransitionError("session is revoked")
        if self.state in (SessionState.UNINITIALIZED, SessionState.IDENTITY_CREATED):
            raise InvalidStateTransitionError("session is not established")

    def revoke(self) -> None:
        """Terminal. Used on logout, device revocation, or identity change."""
        self.state = SessionState.SESSION_REVOKED
        self.ratchet.skipped.clear()

    # -- messaging ----------------------------------------------------------

    def encrypt(self, plaintext: bytes) -> Envelope:
        self._require_usable()
        header, ciphertext = ratchet_encrypt(
            self.ratchet, plaintext, self.associated_data
        )
        self._transition(SessionState.SESSION_ACTIVE)
        return Envelope(
            session_id=self.session_id,
            sender_device_id=self.local_device_id,
            header=header,
            ciphertext=ciphertext,
            x3dh=self.pending_x3dh,
        )

    def decrypt(self, envelope: Envelope, rng: RandomSource = DEFAULT_RANDOM) -> bytes:
        self._require_usable()

        if envelope.x3dh is not None:
            # A repeated X3DH header on an established session is expected
            # (the sender has not yet seen our reply). It must, however, carry
            # the SAME identity -- otherwise this is an identity substitution.
            incoming = envelope.x3dh.initiator_identity
            if incoming.encode() != self.remote_identity.encode():
                self.verification = VerificationStatus.IDENTITY_CHANGED
                raise IdentityChangedError(
                    "peer identity differs from the one bound to this session"
                )

        new_ratchet, plaintext = ratchet_decrypt(
            self.ratchet, envelope.header, envelope.ciphertext, self.associated_data, rng
        )
        # Commit only after full success.
        self.ratchet = new_ratchet
        self.pending_x3dh = None
        self._transition(SessionState.SESSION_ACTIVE)
        return plaintext

    # -- verification -------------------------------------------------------

    def mark_verified(self) -> None:
        if self.verification is VerificationStatus.IDENTITY_CHANGED:
            raise InvalidStateTransitionError(
                "cannot mark verified while an identity change is unresolved"
            )
        self.verification = VerificationStatus.VERIFIED

    # -- diagnostics (safe to display) --------------------------------------

    def diagnostics(self) -> dict:
        """Developer diagnostics containing NO secret material.

        Fingerprints are truncated hashes; counters and inventory sizes are
        metadata the relay can already infer. Nothing here can be used to
        derive a key.
        """
        return {
            "session_id_hash": sha256(self.session_id.encode())[:8].hex(),
            "device_id_hash": sha256(self.local_device_id.encode())[:8].hex(),
            "protocol_version": self.ratchet.session_version,
            "state": self.state.value,
            "verification": self.verification.value,
            "messages_sent": self.ratchet.n_send,
            "messages_received": self.ratchet.n_recv,
            "previous_chain_length": self.ratchet.prev_chain_len,
            "skipped_keys_stored": len(self.ratchet.skipped),
            "local_ratchet_fingerprint": sha256(self.ratchet.dh_send_pub)[:8].hex(),
            "remote_ratchet_fingerprint": (
                sha256(self.ratchet.dh_recv_pub)[:8].hex()
                if self.ratchet.dh_recv_pub
                else None
            ),
            "remote_identity_fingerprint": self.remote_identity.fingerprint()[:8].hex(),
            "used_one_time_prekey": self.used_one_time_prekey,
        }

    # -- encrypted persistence ---------------------------------------------

    def _serialise(self) -> bytes:
        r = self.ratchet
        obj = {
            "format": STATE_FORMAT_VERSION,
            "session_id": self.session_id,
            "local_device_id": self.local_device_id,
            "remote_identity": self.remote_identity.to_json(),
            "associated_data": b64e(self.associated_data),
            "state": self.state.value,
            "verification": self.verification.value,
            "used_one_time_prekey": self.used_one_time_prekey,
            "ratchet": {
                "root_key": b64e(r.root_key),
                "dh_send_priv": b64e(r.dh_send_priv),
                "dh_send_pub": b64e(r.dh_send_pub),
                "dh_recv_pub": b64e(r.dh_recv_pub) if r.dh_recv_pub else None,
                "chain_key_send": b64e(r.chain_key_send) if r.chain_key_send else None,
                "chain_key_recv": b64e(r.chain_key_recv) if r.chain_key_recv else None,
                "n_send": r.n_send,
                "n_recv": r.n_recv,
                "prev_chain_len": r.prev_chain_len,
                "session_version": r.session_version,
                "skipped": [
                    {"dh": b64e(dh), "n": n, "mk": b64e(mk)}
                    for (dh, n), mk in r.skipped.items()
                ],
                "seen_remote_ratchets": [b64e(k) for k in r.seen_remote_ratchets],
            },
        }
        return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()

    def save(self, storage_key: bytes, rng: RandomSource = DEFAULT_RANDOM) -> bytes:
        """Encrypt session state for persistence.

        Session state contains chain keys and the ratchet private key. Writing
        it to disk in the clear would defeat the entire design, so it is sealed
        under a key that itself lives in the platform keystore.

        The session id is bound as associated data, so a stored blob cannot be
        swapped between sessions.
        """
        key = hkdf(
            ikm=storage_key,
            salt=b"",
            info=INFO_STATE_ENCRYPTION + self.session_id.encode(),
            length=AES256_KEY_LEN,
        )
        nonce = rng.bytes(AES_GCM_NONCE_LEN)
        ad = b"Helo_State_v1|" + self.session_id.encode()
        return nonce + aes256gcm_encrypt(key, nonce, self._serialise(), ad)

    @staticmethod
    def load(blob: bytes, storage_key: bytes, session_id: str) -> Session:
        """Decrypt and validate persisted state. Fails closed on corruption."""
        if len(blob) < AES_GCM_NONCE_LEN + 16:
            raise SessionStateCorruptError("stored session blob is truncated")
        key = hkdf(
            ikm=storage_key,
            salt=b"",
            info=INFO_STATE_ENCRYPTION + session_id.encode(),
            length=AES256_KEY_LEN,
        )
        nonce, sealed = blob[:AES_GCM_NONCE_LEN], blob[AES_GCM_NONCE_LEN:]
        ad = b"Helo_State_v1|" + session_id.encode()
        try:
            raw = aes256gcm_decrypt(key, nonce, sealed, ad)
        except Exception as exc:
            raise SessionStateCorruptError(
                "stored session state failed authentication"
            ) from exc

        try:
            obj = json.loads(raw)
            if int(obj["format"]) != STATE_FORMAT_VERSION:
                raise SessionStateCorruptError("unsupported state format version")
            r = obj["ratchet"]
            ratchet = RatchetState(
                root_key=b64d(r["root_key"]),
                dh_send_priv=b64d(r["dh_send_priv"]),
                dh_send_pub=b64d(r["dh_send_pub"]),
                dh_recv_pub=b64d(r["dh_recv_pub"]) if r["dh_recv_pub"] else None,
                chain_key_send=b64d(r["chain_key_send"]) if r["chain_key_send"] else None,
                chain_key_recv=b64d(r["chain_key_recv"]) if r["chain_key_recv"] else None,
                n_send=int(r["n_send"]),
                n_recv=int(r["n_recv"]),
                prev_chain_len=int(r["prev_chain_len"]),
                skipped={
                    (b64d(e["dh"]), int(e["n"])): b64d(e["mk"]) for e in r["skipped"]
                },
                seen_remote_ratchets=[b64d(k) for k in r["seen_remote_ratchets"]],
                session_version=int(r["session_version"]),
            )
            ratchet.validate()
            return Session(
                session_id=obj["session_id"],
                local_device_id=obj["local_device_id"],
                remote_identity=IdentityPublic.from_json(obj["remote_identity"]),
                ratchet=ratchet,
                associated_data=b64d(obj["associated_data"]),
                state=SessionState(obj["state"]),
                verification=VerificationStatus(obj["verification"]),
                used_one_time_prekey=bool(obj["used_one_time_prekey"]),
            )
        except SessionStateCorruptError:
            raise
        except Exception as exc:
            raise SessionStateCorruptError("stored session state is malformed") from exc


# ---------------------------------------------------------------------------
# Session construction
# ---------------------------------------------------------------------------

def start_as_initiator(
    identity: IdentityKeyPair,
    local_device_id: str,
    bundle: PreKeyBundle,
    rng: RandomSource = DEFAULT_RANDOM,
    kex=DEFAULT_KEY_ESTABLISHMENT,
) -> Session:
    """Alice starts a session against a bundle fetched from the relay.

    Works with Bob entirely offline: nothing here requires his participation.
    """
    result, x3dh_header = kex.initiate(identity, bundle, rng)
    ratchet = init_initiator(
        result.shared_secret, bundle.signed_prekey.public, rng
    )
    return Session(
        session_id=result.session_id,
        local_device_id=local_device_id,
        remote_identity=bundle.identity,
        ratchet=ratchet,
        associated_data=result.associated_data,
        pending_x3dh=x3dh_header,
        used_one_time_prekey=result.used_one_time_prekey,
    )


def start_as_responder(
    identity: IdentityKeyPair,
    local_device_id: str,
    prekeys: PreKeyStore,
    envelope: Envelope,
    kex=DEFAULT_KEY_ESTABLISHMENT,
) -> Session:
    """Bob builds his side from Alice's first (prekey) message."""
    if envelope.x3dh is None:
        raise UnknownSessionError(
            "cannot establish a session from a message without an X3DH header"
        )
    result: X3DHResult = kex.respond(identity, prekeys, envelope.x3dh)
    spk_priv = prekeys.signed_prekey_private(envelope.x3dh.signed_prekey_id)
    ratchet = init_responder(result.shared_secret, spk_priv)
    return Session(
        session_id=result.session_id,
        local_device_id=local_device_id,
        remote_identity=envelope.x3dh.initiator_identity,
        ratchet=ratchet,
        associated_data=result.associated_data,
        used_one_time_prekey=result.used_one_time_prekey,
    )
