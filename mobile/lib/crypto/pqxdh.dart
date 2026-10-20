/// Hybrid post-quantum session establishment — port of `helo_ref/pqxdh.py`.
///
/// STATUS: EXPERIMENTAL. The structure of Signal's PQXDH: the X3DH DH outputs
/// and an ML-KEM-768 shared secret form the input keying material of ONE HKDF
/// call under a scheme-specific info string. Our instantiation (separate
/// Ed25519 signing key, ML-KEM-768, our encodings) has not been formally
/// analysed.
///
///     SK = HKDF-SHA256(F ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4] ‖ SS_kem, salt 0^32,
///                      "Helo_PQXDH_X25519_SHA-256_ML-KEM-768_v1")
///
/// Only ESTABLISHMENT is hybrid. Every later DH ratchet step is classical
/// X25519; there is no post-quantum ratchet.
///
/// There is no fallback: a bundle without a valid signed ML-KEM prekey raises
/// [PostQuantumUnavailableError]. Whether to allow classical X3DH instead is a
/// client policy decision, made explicitly and shown to the user.
library;

import 'dart:typed_data';

import 'encoding.dart';
import 'errors.dart';
import 'identity.dart';
import 'pq.dart';
import 'prekeys.dart';
import 'primitives.dart';
import 'x3dh.dart';

final Uint8List infoPqxdh =
    Uint8List.fromList('Helo_PQXDH_X25519_SHA-256_ML-KEM-768_v1'.codeUnits);

Future<Uint8List> pqxdhDerive(List<Uint8List> dhOutputs, List<int> kemSecret) =>
    hkdf(
      ikm: concat(<List<int>>[x3dhF, ...dhOutputs, kemSecret]),
      salt: zeroSalt,
      info: infoPqxdh,
      length: rootKeyLen,
    );

/// Alice's side. [kem] is injectable for tests; production uses ML-KEM-768.
Future<InitiateOutcome> pqxdhInitiate({
  required IdentityKeyPair identity,
  required PreKeyBundle bundle,
  RandomSource? rng,
  Kem kem = const MlKem768(),
}) async {
  final PqPreKeyPublic? pq = bundle.pqPreKey;
  if (pq == null) {
    throw const PostQuantumUnavailableError(
        'peer bundle has no signed ML-KEM prekey; refusing to fall back to X3DH');
  }
  // Identity binding, SPK signature and PQ-prekey signature, all BEFORE any
  // DH or encapsulation touches key material.
  await bundle.verify();

  final KemEncapsulation encaps = kem.encapsulate(pq.encapsulationKey);
  final KeyPairBytes eph = await x25519Generate(rng);
  final List<Uint8List> outputs = <Uint8List>[
    await x25519Dh(identity.dhPriv, bundle.signedPreKey.publicKey),
    await x25519Dh(eph.privateKey, bundle.identity.dhPub),
    await x25519Dh(eph.privateKey, bundle.signedPreKey.publicKey),
  ];
  final bool usedOtp = bundle.oneTimePreKey != null;
  if (usedOtp) {
    outputs.add(await x25519Dh(eph.privateKey, bundle.oneTimePreKey!.publicKey));
  }

  final Uint8List shared = await pqxdhDerive(outputs, encaps.sharedSecret);
  wipe(encaps.sharedSecret);
  return InitiateOutcome(
    X3dhResult(
      sharedSecret: shared,
      associatedData: associatedData(identity.public, bundle.identity),
      sessionId: await sessionId(identity.public, bundle.identity, eph.publicKey),
      usedOneTimePreKey: usedOtp,
    ),
    InitialMessageHeader(
      version: headerVersionHybrid,
      initiatorIdentity: identity.public,
      ephemeralPub: eph.publicKey,
      signedPreKeyId: bundle.signedPreKey.keyId,
      oneTimePreKeyId: bundle.oneTimePreKey?.keyId,
      pqPreKeyId: pq.keyId,
      pqCiphertext: encaps.ciphertext,
    ),
  );
}

/// Bob's side. Consumes the one-time EC prekey and the one-time PQ prekey.
Future<X3dhResult> pqxdhRespond({
  required IdentityKeyPair identity,
  required PreKeyStore prekeys,
  required InitialMessageHeader header,
}) async {
  final Uint8List? ct = header.pqCiphertext;
  final int? pqId = header.pqPreKeyId;
  if (!header.isHybrid || ct == null || pqId == null) {
    throw const InvalidEncodingError('classical initial message passed to PQXDH');
  }
  await header.initiatorIdentity.verifyBinding();

  final Uint8List spkPriv = prekeys.signedPreKeyPrivate(header.signedPreKeyId);
  final List<Uint8List> outputs = <Uint8List>[
    await x25519Dh(spkPriv, header.initiatorIdentity.dhPub),
    await x25519Dh(identity.dhPriv, header.ephemeralPub),
    await x25519Dh(spkPriv, header.ephemeralPub),
  ];
  final bool usedOtp = header.oneTimePreKeyId != null;
  if (usedOtp) {
    final Uint8List otpPriv =
        prekeys.consumeOneTimePreKey(header.oneTimePreKeyId!);
    outputs.add(await x25519Dh(otpPriv, header.ephemeralPub));
  }

  final Uint8List kemSecret =
      MlKem768.decapsulate(prekeys.consumePqPreKey(pqId), ct);
  final Uint8List shared = await pqxdhDerive(outputs, kemSecret);
  wipe(kemSecret);
  return X3dhResult(
    sharedSecret: shared,
    associatedData: associatedData(header.initiatorIdentity, identity.public),
    sessionId: await sessionId(
        header.initiatorIdentity, identity.public, header.ephemeralPub),
    usedOneTimePreKey: usedOtp,
  );
}

class Pqxdh implements KeyEstablishment {
  const Pqxdh({this.kem = const MlKem768()});
  final Kem kem;

  @override
  String get id => 'pqxdh-mlkem768';
  @override
  String get name => 'PQXDH-X25519-MLKEM768-SHA256';

  /// True for the HANDSHAKE only; the ratchet that follows is classical.
  @override
  bool get postQuantum => true;

  @override
  Future<InitiateOutcome> initiate({
    required IdentityKeyPair identity,
    required PreKeyBundle bundle,
    RandomSource? rng,
  }) =>
      pqxdhInitiate(identity: identity, bundle: bundle, rng: rng, kem: kem);

  @override
  Future<X3dhResult> respond({
    required IdentityKeyPair identity,
    required PreKeyStore prekeys,
    required InitialMessageHeader header,
  }) =>
      pqxdhRespond(identity: identity, prekeys: prekeys, header: header);
}
