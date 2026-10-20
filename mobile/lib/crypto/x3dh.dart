/// X3DH asynchronous session establishment — port of `helo_ref/x3dh.py`.
///
/// Classical X3DH, plus the initial-message header shared with the hybrid
/// PQXDH handshake (`pqxdh.dart`). No PQ primitive is used in this file.
library;

import 'dart:typed_data';

import 'encoding.dart';
import 'errors.dart';
import 'identity.dart';
import 'pq.dart';
import 'prekeys.dart';
import 'primitives.dart';

/// Initial-header versions: v1 = classical X3DH, v2 = hybrid PQXDH (must carry
/// the ML-KEM ciphertext). A header can never be half of each.
const int headerVersionClassical = protocolVersion;
const int headerVersionHybrid = 2;

final Uint8List x3dhF = Uint8List.fromList(List<int>.filled(32, 0xFF));
final Uint8List adContext = Uint8List.fromList('Helo_AD_v1'.codeUnits);
final Uint8List sessionIdContext =
    Uint8List.fromList('Helo_SessionId_v1'.codeUnits);

/// Session-wide AEAD associated data.
///
/// Order is ALWAYS (initiator, responder) and never sorted. Fixing the order
/// prevents an attacker reflecting a message back at its own sender as though
/// the roles were reversed.
Uint8List associatedData(IdentityPublic initiator, IdentityPublic responder) =>
    concat(<List<int>>[adContext, initiator.encode(), responder.encode()]);

/// Deterministic, non-secret session identifier derived from public material.
Future<String> sessionId(
  IdentityPublic initiator,
  IdentityPublic responder,
  Uint8List ephemeralPub,
) async {
  final Uint8List digest = await sha256Hash(concat(<List<int>>[
    sessionIdContext,
    initiator.encode(),
    responder.encode(),
    lp(ephemeralPub),
  ]));
  final StringBuffer sb = StringBuffer();
  for (int i = 0; i < 16; i++) {
    sb.write(digest[i].toRadixString(16).padLeft(2, '0'));
  }
  return sb.toString();
}

class X3dhResult {
  const X3dhResult({
    required this.sharedSecret,
    required this.associatedData,
    required this.sessionId,
    required this.usedOneTimePreKey,
  });
  final Uint8List sharedSecret;
  final Uint8List associatedData;
  final String sessionId;
  final bool usedOneTimePreKey;
}

/// Prepended to Alice's first message so Bob can build his side.
class InitialMessageHeader {
  const InitialMessageHeader({
    required this.version,
    required this.initiatorIdentity,
    required this.ephemeralPub,
    required this.signedPreKeyId,
    this.oneTimePreKeyId,
    this.pqPreKeyId,
    this.pqCiphertext,
  });

  final int version;
  final IdentityPublic initiatorIdentity;
  final Uint8List ephemeralPub;
  final int signedPreKeyId;
  final int? oneTimePreKeyId;
  final int? pqPreKeyId;
  final Uint8List? pqCiphertext;

  bool get isHybrid => version == headerVersionHybrid;

  Map<String, dynamic> toJson() => <String, dynamic>{
        'version': version,
        'initiator_identity': initiatorIdentity.toJson(),
        'ephemeral_pub': b64e(ephemeralPub),
        'signed_prekey_id': signedPreKeyId,
        'one_time_prekey_id': oneTimePreKeyId,
        if (pqCiphertext != null)
          'pq': <String, dynamic>{
            'key_id': pqPreKeyId,
            'ct': b64e(pqCiphertext!),
          },
      };

  static InitialMessageHeader fromJson(Map<String, dynamic> obj) {
    final Object? version = obj['version'];
    if (version is! int ||
        (version != headerVersionClassical && version != headerVersionHybrid)) {
      throw const InvalidEncodingError('unsupported X3DH header version');
    }
    // Version and KEM ciphertext must agree; a mismatched header is
    // malformed, never "repaired" into either mode.
    final Object? pq = obj['pq'];
    if (version == headerVersionClassical && pq != null) {
      throw const InvalidEncodingError('classical initial header carries PQ data');
    }
    if (version == headerVersionHybrid && pq is! Map<String, dynamic>) {
      throw const InvalidEncodingError('hybrid initial header lacks PQ data');
    }
    int? pqId;
    Uint8List? pqCt;
    if (pq is Map<String, dynamic>) {
      final Object? id = pq['key_id'];
      final Object? ct = pq['ct'];
      if (id is! int || ct is! String) {
        throw const InvalidEncodingError('hybrid initial header is malformed');
      }
      pqId = id;
      pqCt = b64d(ct, expectLen: mlKem768CtLen);
    }
    final Object? identity = obj['initiator_identity'];
    final Object? eph = obj['ephemeral_pub'];
    final Object? spk = obj['signed_prekey_id'];
    if (identity is! Map<String, dynamic> || eph is! String || spk is! int) {
      throw const InvalidEncodingError('X3DH header is missing a field');
    }
    final Object? otp = obj['one_time_prekey_id'];
    return InitialMessageHeader(
      version: version,
      initiatorIdentity: IdentityPublic.fromJson(identity),
      ephemeralPub: b64d(eph, expectLen: x25519KeyLen),
      signedPreKeyId: spk,
      oneTimePreKeyId: otp is int ? otp : null,
      pqPreKeyId: pqId,
      pqCiphertext: pqCt,
    );
  }
}

Future<Uint8List> _derive(List<Uint8List> dhOutputs) => hkdf(
      ikm: concat(<List<int>>[x3dhF, ...dhOutputs]),
      salt: zeroSalt,
      info: infoX3dh,
      length: rootKeyLen,
    );

class InitiateOutcome {
  const InitiateOutcome(this.result, this.header);
  final X3dhResult result;
  final InitialMessageHeader header;
}

/// Alice's side.
///
/// The ephemeral private key is deliberately NOT returned. It is used for three
/// DH operations and then goes out of scope; returning it would invite a caller
/// to persist it, destroying the forward secrecy it exists to provide.
///
/// Signature verification happens BEFORE any DH: a bundle that fails validation
/// never touches Alice's private keys.
Future<InitiateOutcome> x3dhInitiate({
  required IdentityKeyPair identity,
  required PreKeyBundle bundle,
  RandomSource? rng,
}) async {
  await bundle.verify();

  final KeyPairBytes eph = await x25519Generate(rng);

  final List<Uint8List> outputs = <Uint8List>[
    await x25519Dh(identity.dhPriv, bundle.signedPreKey.publicKey),
    await x25519Dh(eph.privateKey, bundle.identity.dhPub),
    await x25519Dh(eph.privateKey, bundle.signedPreKey.publicKey),
  ];

  final bool usedOtp = bundle.oneTimePreKey != null;
  if (usedOtp) {
    outputs.add(
        await x25519Dh(eph.privateKey, bundle.oneTimePreKey!.publicKey));
  }

  final Uint8List shared = await _derive(outputs);
  final Uint8List ad = associatedData(identity.public, bundle.identity);
  final String sid =
      await sessionId(identity.public, bundle.identity, eph.publicKey);

  return InitiateOutcome(
    X3dhResult(
      sharedSecret: shared,
      associatedData: ad,
      sessionId: sid,
      usedOneTimePreKey: usedOtp,
    ),
    InitialMessageHeader(
      version: protocolVersion,
      initiatorIdentity: identity.public,
      ephemeralPub: eph.publicKey,
      signedPreKeyId: bundle.signedPreKey.keyId,
      oneTimePreKeyId: bundle.oneTimePreKey?.keyId,
    ),
  );
}

/// Bob's side. Recomputes the identical shared secret.
///
/// The one-time prekey is CONSUMED here, which is one of the layers defending
/// against replay of the initial message.
Future<X3dhResult> x3dhRespond({
  required IdentityKeyPair identity,
  required PreKeyStore prekeys,
  required InitialMessageHeader header,
}) async {
  if (header.isHybrid) {
    throw const InvalidEncodingError(
        'hybrid initial message passed to classical X3DH');
  }
  await header.initiatorIdentity.verifyBinding();

  final Uint8List spkPriv =
      prekeys.signedPreKeyPrivate(header.signedPreKeyId);

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

  return X3dhResult(
    sharedSecret: await _derive(outputs),
    associatedData:
        associatedData(header.initiatorIdentity, identity.public),
    sessionId: await sessionId(
        header.initiatorIdentity, identity.public, header.ephemeralPub),
    usedOneTimePreKey: usedOtp,
  );
}

/// The seam between session establishment and the Double Ratchet.
///
/// The ratchet consumes ONLY [X3dhResult.sharedSecret], so classical X3DH and
/// hybrid PQXDH (`pqxdh.dart`) are interchangeable here; nothing in
/// ratchet.dart or envelope.dart knows which produced the secret.
abstract class KeyEstablishment {
  /// Short id recorded on the session: `x3dh` or `pqxdh-mlkem768`.
  String get id;
  String get name;
  bool get postQuantum;
  Future<InitiateOutcome> initiate({
    required IdentityKeyPair identity,
    required PreKeyBundle bundle,
    RandomSource? rng,
  });
  Future<X3dhResult> respond({
    required IdentityKeyPair identity,
    required PreKeyStore prekeys,
    required InitialMessageHeader header,
  });
}

class ClassicalX3dh implements KeyEstablishment {
  const ClassicalX3dh();
  @override
  String get id => 'x3dh';
  @override
  String get name => 'X3DH-Curve25519-SHA256';
  @override
  bool get postQuantum => false;
  @override
  Future<InitiateOutcome> initiate({
    required IdentityKeyPair identity,
    required PreKeyBundle bundle,
    RandomSource? rng,
  }) =>
      // Must call the top-level function, NOT this method. Naming them
      // identically previously caused unbounded recursion.
      x3dhInitiate(identity: identity, bundle: bundle, rng: rng);
  @override
  Future<X3dhResult> respond({
    required IdentityKeyPair identity,
    required PreKeyStore prekeys,
    required InitialMessageHeader header,
  }) =>
      x3dhRespond(identity: identity, prekeys: prekeys, header: header);
}
