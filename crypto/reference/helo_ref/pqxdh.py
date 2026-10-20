"""Hybrid post-quantum session establishment (PQXDH structure).

STATUS: EXPERIMENTAL. This follows the structure of Signal's PQXDH
specification -- the X3DH Diffie-Hellman outputs and an ML-KEM shared secret
are the input keying material of ONE HKDF invocation, under an info string
naming the scheme. PQXDH is a published construction with a published formal
analysis. Our *instantiation* differs from Signal's (separate Ed25519 signing
key, ML-KEM-768, our own encodings) and has NOT been formally analysed.

Construction
------------
    Bob publishes IK_B, SPK_B (+sig), OPK_B (optional), and a signed ML-KEM
    prekey PQPK_B: a one-time key when available, else the last-resort key.

    Alice verifies the identity binding, the SPK signature and the PQPK
    signature -- all before any DH or encapsulation -- then:

        (CT, SS) = ML-KEM-768.Encaps(PQPK_B)
        DH1..DH4 exactly as in X3DH
        SK = HKDF-SHA256(ikm  = F || DH1 || DH2 || DH3 [|| DH4] || SS,
                         salt = 0x00 * 32,
                         info = "Helo_PQXDH_X25519_SHA-256_ML-KEM-768_v1",
                         L    = 32)

Why this is a hybrid and not "concatenate and hope"
---------------------------------------------------
HKDF-Extract is used as a dual-PRF/randomness extractor over all inputs, and
the info string differs from X3DH's (`Helo_X3DH_v1`), so the two schemes can
never derive colliding keys. An attacker must break BOTH X25519 (all of the
DH outputs that matter) AND ML-KEM-768 to learn SK. The KEM identifier is
inside the signed PQ key encoding (see pq.py), so a PQ key cannot be passed off
as another KEM's.

What it does NOT provide
------------------------
Only session ESTABLISHMENT is hybrid. The Double Ratchet that follows uses
classical X25519 for every subsequent DH step; there is no post-quantum
ratchet. A future quantum adversary recording traffic cannot recover SK, but
post-compromise recovery steps after establishment are classical.

Downgrade
---------
There is no in-band negotiation for an attacker to edit. `PQXDH.initiate`
refuses a bundle with no valid PQ prekey (PostQuantumUnavailableError) rather
than falling back; responders refuse classical initial messages when their
policy requires the hybrid (see session.start_as_responder). Editing the
header in flight makes the two sides derive different SKs, so the first
message fails AEAD authentication.
"""

from __future__ import annotations

from .errors import InvalidEncodingError, PostQuantumUnavailableError
from .identity import IdentityKeyPair
from .pq import MLKEM768
from .prekeys import PreKeyBundle, PreKeyStore
from .primitives import (
    DEFAULT_RANDOM,
    ROOT_KEY_LEN,
    ZERO_SALT,
    RandomSource,
    hkdf,
    x25519_dh,
    x25519_generate,
)
from .x3dh import (
    HEADER_VERSION_HYBRID,
    X3DH_F,
    InitialMessageHeader,
    X3DHResult,
    associated_data,
    session_id,
)

INFO_PQXDH = b"Helo_PQXDH_X25519_SHA-256_ML-KEM-768_v1"


def _derive(dh_outputs: list[bytes], kem_secret: bytes) -> bytes:
    ikm = X3DH_F + b"".join(dh_outputs) + kem_secret
    return hkdf(ikm=ikm, salt=ZERO_SALT, info=INFO_PQXDH, length=ROOT_KEY_LEN)


def initiate(
    identity: IdentityKeyPair,
    bundle: PreKeyBundle,
    rng: RandomSource = DEFAULT_RANDOM,
    kem=MLKEM768,
) -> tuple[X3DHResult, InitialMessageHeader]:
    """Alice's side of the hybrid handshake.

    `kem` is injectable ONLY so the vector generator can pin the KEM
    ciphertext (OpenSSL offers no derandomized encapsulation). Production code
    uses the default.
    """
    if bundle.pq_prekey is None:
        raise PostQuantumUnavailableError(
            "peer bundle has no signed ML-KEM prekey; refusing to fall back to X3DH"
        )
    bundle.verify()  # identity binding, SPK signature and PQ-prekey signature

    ct, kem_secret = kem.encapsulate(bundle.pq_prekey.encapsulation_key())

    eph_priv, eph_pub = x25519_generate(rng)
    dh1 = x25519_dh(identity.dh_priv, bundle.signed_prekey.public)
    dh2 = x25519_dh(eph_priv, bundle.identity.dh_pub)
    dh3 = x25519_dh(eph_priv, bundle.signed_prekey.public)
    outputs = [dh1, dh2, dh3]
    used_otp = bundle.one_time_prekey is not None
    if used_otp:
        outputs.append(x25519_dh(eph_priv, bundle.one_time_prekey.public))

    shared = _derive(outputs, kem_secret)
    header = InitialMessageHeader(
        version=HEADER_VERSION_HYBRID,
        initiator_identity=identity.public(),
        ephemeral_pub=eph_pub,
        signed_prekey_id=bundle.signed_prekey.key_id,
        one_time_prekey_id=bundle.one_time_prekey.key_id if used_otp else None,
        pq_prekey_id=bundle.pq_prekey.key_id,
        pq_ciphertext=ct,
    )
    return (
        X3DHResult(
            shared_secret=shared,
            associated_data=associated_data(identity.public(), bundle.identity),
            session_id=session_id(identity.public(), bundle.identity, eph_pub),
            used_one_time_prekey=used_otp,
        ),
        header,
    )


def respond(
    identity: IdentityKeyPair,
    prekeys: PreKeyStore,
    header: InitialMessageHeader,
) -> X3DHResult:
    """Bob's side. Consumes the one-time EC prekey and one-time PQ prekey."""
    if not header.is_hybrid or header.pq_ciphertext is None or header.pq_prekey_id is None:
        raise InvalidEncodingError("classical initial message passed to PQXDH")
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

    pq_seed = prekeys.consume_pq_prekey(header.pq_prekey_id)
    kem_secret = MLKEM768.decapsulate(pq_seed, header.pq_ciphertext)

    shared = _derive(outputs, kem_secret)
    return X3DHResult(
        shared_secret=shared,
        associated_data=associated_data(header.initiator_identity, identity.public()),
        session_id=session_id(header.initiator_identity, identity.public(), header.ephemeral_pub),
        used_one_time_prekey=used_otp,
    )


class PQXDH:
    """Hybrid X25519 + ML-KEM-768 key establishment. EXPERIMENTAL."""

    id = "pqxdh-mlkem768"
    name = "PQXDH-X25519-MLKEM768-SHA256"
    post_quantum = True  # for the HANDSHAKE only; see module docstring

    def __init__(self, kem=MLKEM768) -> None:
        self._kem = kem

    def initiate(self, identity, bundle, rng=DEFAULT_RANDOM):
        return initiate(identity, bundle, rng, kem=self._kem)

    def respond(self, identity, prekeys, header):
        return respond(identity, prekeys, header)
