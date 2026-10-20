"""X3DH asynchronous session establishment.

STATUS: Classical X3DH + Double Ratchet implementation.
        This is NOT post-quantum secure. No PQ primitive is used anywhere in
        this file. See `KeyEstablishment` at the bottom for the abstraction
        boundary that PQXDH will later replace.

Construction
------------
Alice has:  IK_A (identity, sig+dh), EK_A (fresh ephemeral)
Bob has published: IK_B, SPK_B (signed), optionally OPK_B (one-time)

    DH1 = DH(IK_A.dh, SPK_B)      binds Alice's identity to Bob's signed prekey
    DH2 = DH(EK_A,    IK_B.dh)    binds Bob's identity to Alice's ephemeral
    DH3 = DH(EK_A,    SPK_B)      forward secrecy from the ephemeral
    DH4 = DH(EK_A,    OPK_B)      forward secrecy from the one-time prekey
                                  (omitted if Bob has no OPK left)

    SK  = HKDF-SHA256(
              ikm  = F || DH1 || DH2 || DH3 [|| DH4],
              salt = 0x00 * 32,
              info = "Helo_X3DH_v1",
              L    = 32)

F is 32 bytes of 0xFF, as specified by X3DH for the 32-byte-curve case. Its
purpose is domain separation between X3DH output and any other use of HKDF over
raw curve outputs.

Mutual authentication comes from DH1 and DH2: an attacker without IK_A.dh's
private half cannot produce DH1, and an attacker without IK_B.dh's private half
cannot produce DH2. Note that this authenticates KEYS, not humans -- binding a
key to a person requires out-of-band verification (see identity.py).

Associated data
---------------
AD = "Helo_AD_v1" || encode(IK_A_public) || encode(IK_B_public)

AD is fed into every AEAD operation in the resulting session. Both identities
are therefore cryptographically bound to every single message, not just to the
handshake. Identity substitution breaks decryption of all traffic, not merely
the first message.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .encoding import PROTOCOL_VERSION, b64d, b64e, lp
from .errors import InvalidEncodingError
from .identity import IdentityKeyPair, IdentityPublic
from .pq import MLKEM768_CT_LEN
from .prekeys import PreKeyBundle, PreKeyStore
from .primitives import (
    DEFAULT_RANDOM,
    INFO_X3DH,
    ROOT_KEY_LEN,
    X25519_KEY_LEN,
    ZERO_SALT,
    RandomSource,
    hkdf,
    sha256,
    x25519_dh,
    x25519_generate,
)

X3DH_F = b"\xff" * 32
AD_CONTEXT = b"Helo_AD_v1"

# Initial-header versions. v1 = classical X3DH; v2 = hybrid PQXDH, which must
# carry the ML-KEM ciphertext. A header can never be half of each.
HEADER_VERSION_CLASSICAL = PROTOCOL_VERSION
HEADER_VERSION_HYBRID = 2


def associated_data(initiator: IdentityPublic, responder: IdentityPublic) -> bytes:
    """Session-wide AEAD associated data.

    Order is ALWAYS (initiator, responder) -- never sorted. Both sides know
    which role they played, and fixing the order prevents an attacker from
    reflecting a message back at its own sender as if the roles were swapped.
    """
    return AD_CONTEXT + initiator.encode() + responder.encode()


def session_id(
    initiator: IdentityPublic,
    responder: IdentityPublic,
    ephemeral_pub: bytes,
) -> str:
    """Deterministic, non-secret session identifier.

    Derived from public material only, so both parties compute the same value
    without an extra round trip. It is a HASH, so it leaks nothing beyond the
    fact that these two identities have a session -- which the relay already
    knows from routing.
    """
    digest = sha256(
        b"Helo_SessionId_v1"
        + initiator.encode()
        + responder.encode()
        + lp(ephemeral_pub)
    )
    return digest[:16].hex()


@dataclass(frozen=True)
class X3DHResult:
    """Output of the handshake, consumed by the Double Ratchet."""

    shared_secret: bytes
    associated_data: bytes
    session_id: str
    used_one_time_prekey: bool


@dataclass(frozen=True)
class InitialMessageHeader:
    """Prepended to the FIRST message Alice sends, so Bob can build his side.

    Every field here is public. Bob validates all of it before touching any
    private key material.
    """

    version: int
    initiator_identity: IdentityPublic
    ephemeral_pub: bytes
    signed_prekey_id: int
    one_time_prekey_id: int | None
    pq_prekey_id: int | None = None
    pq_ciphertext: bytes | None = None

    @property
    def is_hybrid(self) -> bool:
        return self.version == HEADER_VERSION_HYBRID

    def to_json(self) -> dict:
        obj = {
            "version": self.version,
            "initiator_identity": self.initiator_identity.to_json(),
            "ephemeral_pub": b64e(self.ephemeral_pub),
            "signed_prekey_id": self.signed_prekey_id,
            "one_time_prekey_id": self.one_time_prekey_id,
        }
        if self.pq_ciphertext is not None:
            obj["pq"] = {"key_id": self.pq_prekey_id, "ct": b64e(self.pq_ciphertext)}
        return obj

    @staticmethod
    def from_json(obj: dict) -> InitialMessageHeader:
        try:
            version = int(obj["version"])
            if version not in (HEADER_VERSION_CLASSICAL, HEADER_VERSION_HYBRID):
                raise InvalidEncodingError(f"unsupported version {version}")
            pq = obj.get("pq")
            # The version and the presence of the KEM ciphertext must agree. A
            # v1 header with a ciphertext, or a v2 header without one, is
            # malformed -- not something to be "repaired" into either mode.
            if version == HEADER_VERSION_CLASSICAL and pq is not None:
                raise InvalidEncodingError("classical initial header carries PQ data")
            if version == HEADER_VERSION_HYBRID and not isinstance(pq, dict):
                raise InvalidEncodingError("hybrid initial header lacks PQ data")
            otp = obj.get("one_time_prekey_id")
            return InitialMessageHeader(
                version=version,
                initiator_identity=IdentityPublic.from_json(obj["initiator_identity"]),
                ephemeral_pub=b64d(obj["ephemeral_pub"], expect_len=X25519_KEY_LEN),
                signed_prekey_id=int(obj["signed_prekey_id"]),
                one_time_prekey_id=int(otp) if otp is not None else None,
                pq_prekey_id=int(pq["key_id"]) if pq else None,
                pq_ciphertext=b64d(pq["ct"], expect_len=MLKEM768_CT_LEN) if pq else None,
            )
        except KeyError as exc:
            raise InvalidEncodingError(f"initial header missing field {exc}") from exc


def _derive(dh_outputs: list[bytes]) -> bytes:
    ikm = X3DH_F + b"".join(dh_outputs)
    return hkdf(ikm=ikm, salt=ZERO_SALT, info=INFO_X3DH, length=ROOT_KEY_LEN)


def initiate(
    identity: IdentityKeyPair,
    bundle: PreKeyBundle,
    rng: RandomSource = DEFAULT_RANDOM,
) -> tuple[X3DHResult, InitialMessageHeader]:
    """Alice's side. Returns (result, initial header).

    The ephemeral private key is deliberately NOT returned. It is used for
    three DH operations and then goes out of scope immediately. Nothing
    downstream needs it -- the Double Ratchet generates its own fresh ratchet
    key pair -- and returning it would invite a caller to persist it, which
    would silently destroy the forward secrecy the ephemeral exists to provide.

    Signature verification happens BEFORE any DH: a bundle that fails
    validation never touches Alice's private keys.
    """
    bundle.verify()

    eph_priv, eph_pub = x25519_generate(rng)

    dh1 = x25519_dh(identity.dh_priv, bundle.signed_prekey.public)
    dh2 = x25519_dh(eph_priv, bundle.identity.dh_pub)
    dh3 = x25519_dh(eph_priv, bundle.signed_prekey.public)
    outputs = [dh1, dh2, dh3]

    used_otp = bundle.one_time_prekey is not None
    if used_otp:
        outputs.append(x25519_dh(eph_priv, bundle.one_time_prekey.public))

    shared = _derive(outputs)
    ad = associated_data(identity.public(), bundle.identity)
    sid = session_id(identity.public(), bundle.identity, eph_pub)

    header = InitialMessageHeader(
        version=PROTOCOL_VERSION,
        initiator_identity=identity.public(),
        ephemeral_pub=eph_pub,
        signed_prekey_id=bundle.signed_prekey.key_id,
        one_time_prekey_id=(
            bundle.one_time_prekey.key_id if bundle.one_time_prekey else None
        ),
    )
    return (
        X3DHResult(
            shared_secret=shared,
            associated_data=ad,
            session_id=sid,
            used_one_time_prekey=used_otp,
        ),
        header,
    )


def respond(
    identity: IdentityKeyPair,
    prekeys: PreKeyStore,
    header: InitialMessageHeader,
) -> X3DHResult:
    """Bob's side. Recomputes the identical shared secret.

    Bob validates the initiator's identity binding before performing any DH.
    The one-time prekey is CONSUMED here (destroyed), which is one of the
    layers defending against replay of the initial message.
    """
    if header.is_hybrid:
        raise InvalidEncodingError("hybrid initial message passed to classical X3DH")
    header.initiator_identity.verify_binding()

    spk_priv = prekeys.signed_prekey_private(header.signed_prekey_id)

    dh1 = x25519_dh(spk_priv, header.initiator_identity.dh_pub)
    dh2 = x25519_dh(identity.dh_priv, header.ephemeral_pub)
    dh3 = x25519_dh(spk_priv, header.ephemeral_pub)
    outputs = [dh1, dh2, dh3]

    used_otp = header.one_time_prekey_id is not None
    if used_otp:
        otp_priv = prekeys.consume_one_time_prekey(header.one_time_prekey_id)
        outputs.append(x25519_dh(otp_priv, header.ephemeral_pub))

    shared = _derive(outputs)
    ad = associated_data(header.initiator_identity, identity.public())
    sid = session_id(header.initiator_identity, identity.public(), header.ephemeral_pub)

    return X3DHResult(
        shared_secret=shared,
        associated_data=ad,
        session_id=sid,
        used_one_time_prekey=used_otp,
    )


# ---------------------------------------------------------------------------
# PQXDH migration boundary
# ---------------------------------------------------------------------------

class KeyEstablishment(Protocol):
    """The seam at which PQXDH replaces classical X3DH.

    The Double Ratchet consumes ONLY `X3DHResult.shared_secret`. It has no
    knowledge of how that secret was produced. A PQXDH implementation therefore
    needs to satisfy exactly this interface:

        * `initiate` additionally encapsulates against Bob's published KEM
          public key (e.g. ML-KEM-768) and includes the KEM ciphertext in the
          initial header,
        * `respond` decapsulates it,
        * the KEM shared secret is concatenated into the HKDF input alongside
          the classical DH outputs (hybrid construction -- the classical DHs are
          RETAINED, not replaced, so a break in either primitive alone is not
          fatal),
        * `INFO_X3DH` becomes `Helo_PQXDH_v1` so the two schemes cannot
          derive colliding secrets.

    Nothing in ratchet.py or message.py changes. That is the point of the seam.
    """

    def initiate(
        self, identity: IdentityKeyPair, bundle: PreKeyBundle, rng: RandomSource
    ) -> tuple[X3DHResult, InitialMessageHeader]: ...

    def respond(
        self, identity: IdentityKeyPair, prekeys: PreKeyStore, header: InitialMessageHeader
    ) -> X3DHResult: ...


class ClassicalX3DH:
    """Concrete classical implementation. NOT post-quantum secure."""

    id = "x3dh"
    name = "X3DH-Curve25519-SHA256"
    post_quantum = False

    def initiate(self, identity, bundle, rng=DEFAULT_RANDOM):
        return initiate(identity, bundle, rng)

    def respond(self, identity, prekeys, header):
        return respond(identity, prekeys, header)
