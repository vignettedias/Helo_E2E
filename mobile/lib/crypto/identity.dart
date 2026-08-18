/// Long-term identity — port of `helo_ref/identity.py`.
///
/// DELIBERATE DEVIATION from Signal: two keys per identity rather than one
/// Curve25519 key used for both DH and signing via XEdDSA.
///
///   IK_sig   Ed25519   signatures only
///   IK_dh    X25519    key agreement only
///
/// XEdDSA has no implementation in mainstream Dart crypto packages, and
/// hand-rolling it would violate the no-custom-primitives rule. Cross-algorithm
/// key reuse is also generally discouraged. The two halves are bound by a
/// signature, by the fingerprint, and by the AEAD associated data — so
/// substituting either breaks all three simultaneously.
library;

import 'dart:typed_data';

import 'encoding.dart';
import 'errors.dart';
import 'primitives.dart';

final Uint8List identityBindingContext =
    Uint8List.fromList('Helo_IdentityBinding_v1'.codeUnits);

const int fingerprintIterations = 5200;

/// Public half of an identity. Safe to publish.
class IdentityPublic {
  IdentityPublic({
    required this.sigPub,
    required this.dhPub,
    required this.bindingSig,
  }) {
    validateEd25519Public(sigPub);
    validateX25519Public(dhPub);
  }

  final Uint8List sigPub;
  final Uint8List dhPub;
  final Uint8List bindingSig;

  /// Canonical encoding used in fingerprints and AEAD associated data.
  Uint8List encode() =>
      concat(<List<int>>[u8(1), lp(sigPub), lp(dhPub)]);

  /// Verify that IK_sig actually attests to IK_dh.
  ///
  /// MUST be called on every identity received from the network before that
  /// identity is used for anything at all.
  Future<void> verifyBinding() async {
    await ed25519Verify(
      sigPub,
      bindingSig,
      concat(<List<int>>[identityBindingContext, dhPub]),
    );
  }

  /// 32-byte iterated identity fingerprint.
  Future<Uint8List> fingerprint() async {
    final Uint8List body = encode();
    Uint8List digest =
        await sha256Hash(concat(<List<int>>[infoFingerprint, body]));
    for (int i = 0; i < fingerprintIterations; i++) {
      digest = await sha256Hash(concat(<List<int>>[digest, body]));
    }
    return digest;
  }

  Map<String, dynamic> toJson() => <String, dynamic>{
        'sig_pub': b64e(sigPub),
        'dh_pub': b64e(dhPub),
        'binding_sig': b64e(bindingSig),
      };

  static IdentityPublic fromJson(Map<String, dynamic> obj) {
    final Object? sig = obj['sig_pub'];
    final Object? dh = obj['dh_pub'];
    final Object? bind = obj['binding_sig'];
    if (sig is! String || dh is! String || bind is! String) {
      throw const InvalidEncodingError('identity is missing a field');
    }
    return IdentityPublic(
      sigPub: b64d(sig, expectLen: ed25519PubLen),
      dhPub: b64d(dh, expectLen: x25519KeyLen),
      bindingSig: b64d(bind, expectLen: ed25519SigLen),
    );
  }
}

/// Full identity including private material.
///
/// Private fields must never be serialised in the clear, transmitted, or
/// logged. On device they live behind CryptoStorage (Android Keystore / iOS
/// Keychain).
class IdentityKeyPair {
  IdentityKeyPair({
    required this.sigSeed,
    required this.sigPub,
    required this.dhPriv,
    required this.dhPub,
    required this.bindingSig,
  });

  final Uint8List sigSeed; // SECRET
  final Uint8List sigPub;
  final Uint8List dhPriv; // SECRET
  final Uint8List dhPub;
  final Uint8List bindingSig;

  static Future<IdentityKeyPair> generate([RandomSource? rng]) async {
    final KeyPairBytes sig = await ed25519Generate(rng);
    final KeyPairBytes dh = await x25519Generate(rng);
    final Uint8List binding = await ed25519Sign(
      sig.privateKey,
      concat(<List<int>>[identityBindingContext, dh.publicKey]),
    );
    return IdentityKeyPair(
      sigSeed: sig.privateKey,
      sigPub: sig.publicKey,
      dhPriv: dh.privateKey,
      dhPub: dh.publicKey,
      bindingSig: binding,
    );
  }

  IdentityPublic get public =>
      IdentityPublic(sigPub: sigPub, dhPub: dhPub, bindingSig: bindingSig);

  Future<Uint8List> sign(List<int> message) => ed25519Sign(sigSeed, message);

  /// Never allow private material into a repr, a traceback, or a log line.
  @override
  String toString() => '<IdentityKeyPair REDACTED>';
}

/// The 60-digit safety number shown to both users.
///
/// Both parties must see the SAME string, so the two fingerprints are sorted
/// before combination.
Future<String> safetyNumber(IdentityPublic a, IdentityPublic b) async {
  final Uint8List fa = await a.fingerprint();
  final Uint8List fb = await b.fingerprint();
  final String ha = b64e(fa);
  final String hb = b64e(fb);
  final List<Uint8List> ordered =
      ha.compareTo(hb) <= 0 ? <Uint8List>[fa, fb] : <Uint8List>[fb, fa];

  final Uint8List combined = await sha256Hash(concat(<List<int>>[
    infoFingerprint,
    '|safety|'.codeUnits,
    ordered[0],
    ordered[1],
  ]));

  final List<String> groups = <String>[];
  for (int i = 0; i < 12; i++) {
    final int value =
        ((combined[i * 2] << 8) | combined[i * 2 + 1]) % 100000;
    groups.add(value.toString().padLeft(5, '0'));
  }
  return groups.join(' ');
}
