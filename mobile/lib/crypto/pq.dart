/// ML-KEM-768 (FIPS 203) — port of `helo_ref/pq.py`.
///
/// No KEM code is written here. Key generation, encapsulation and
/// decapsulation are the `pqcrypto` package's (pure Dart, runs on the web).
/// This file fixes the parameter set and the encodings, and adapts errors.
///
/// Conformance: the vectors pin an ML-KEM seed and an OpenSSL-produced
/// ciphertext. `test/vector_conformance_test.dart` requires this wrapper to
/// reproduce OpenSSL's public key from the seed and OpenSSL's shared secret
/// from the ciphertext — so the two implementations are checked against each
/// other, not each against itself.
library;

import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart';

import 'errors.dart';
import 'primitives.dart';

const int kemIdMlKem768 = 0x01;
const int mlKem768EkLen = 1184;
const int mlKem768CtLen = 1088;
const int mlKem768SsLen = 32;
const int mlKemSeedLen = 64;
const int encodedPqPublicLen = 1 + mlKem768EkLen;

final KyberKem _kem = PqcKem.kyber768;

/// `Encode(PQPK) = u8(KEM id) ‖ ek`. The KEM id is inside every signed
/// encoding, so a key cannot be passed off as another KEM's.
Uint8List encodePqPublic(List<int> ek) {
  if (ek.length != mlKem768EkLen) {
    throw const InvalidKeyError('ML-KEM-768 public key must be 1184 bytes');
  }
  return Uint8List.fromList(<int>[kemIdMlKem768, ...ek]);
}

/// Return the raw encapsulation key; reject any other KEM or length.
Uint8List decodePqPublic(List<int> data) {
  if (data.length != encodedPqPublicLen || data[0] != kemIdMlKem768) {
    throw const InvalidEncodingError(
        'PQ public key is not an encoded ML-KEM-768 key');
  }
  return Uint8List.fromList(data.sublist(1));
}

class KemEncapsulation {
  const KemEncapsulation(this.ciphertext, this.sharedSecret);
  final Uint8List ciphertext;
  final Uint8List sharedSecret;
}

/// What the hybrid handshake needs from a KEM. Injectable for tests only.
abstract class Kem {
  KemEncapsulation encapsulate(Uint8List ek);
}

class MlKem768 implements Kem {
  const MlKem768();

  /// Returns (seed, ek). The 64-byte FIPS 203 seed (d ‖ z) is the private key
  /// at rest; the expanded key is re-derived from it when needed.
  static (Uint8List, Uint8List) generate([RandomSource? rng]) {
    final Uint8List seed = (rng ?? defaultRandom).bytes(mlKemSeedLen);
    return (seed, publicFromSeed(seed));
  }

  static Uint8List publicFromSeed(Uint8List seed) {
    if (seed.length != mlKemSeedLen) {
      throw const InvalidKeyError('ML-KEM seed must be 64 bytes');
    }
    final (Uint8List pk, Uint8List _) = _kem.generateKeyPair(seed);
    return pk;
  }

  /// Validates the key (FIPS 203 modulus check, inside `pqcrypto`) and
  /// encapsulates with the platform CSPRNG.
  @override
  KemEncapsulation encapsulate(Uint8List ek) {
    try {
      final (Uint8List ct, Uint8List ss) = _kem.encapsulate(ek);
      return KemEncapsulation(ct, ss);
    } on ArgumentError {
      throw const InvalidKeyError('ML-KEM-768 public key failed validation');
    }
  }

  /// Implicit rejection: a wrong-but-well-sized ciphertext yields an unrelated
  /// secret, which surfaces as an AEAD failure on the first message — never
  /// as a distinguishable error an attacker could probe.
  static Uint8List decapsulate(Uint8List seed, Uint8List ct) {
    if (ct.length != mlKem768CtLen) {
      throw const InvalidEncodingError(
          'ML-KEM-768 ciphertext must be 1088 bytes');
    }
    if (seed.length != mlKemSeedLen) {
      throw const InvalidKeyError('ML-KEM seed must be 64 bytes');
    }
    final (Uint8List _, Uint8List sk) = _kem.generateKeyPair(seed);
    try {
      return _kem.decapsulate(sk, ct);
    } finally {
      wipe(sk);
    }
  }
}
