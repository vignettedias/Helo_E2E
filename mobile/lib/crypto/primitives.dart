/// Cryptographic primitive layer for the Helo client.
///
/// This file is a DIRECT PORT of `crypto/reference/helo_ref/primitives.py`.
/// The Python implementation is normative: where the two disagree, this file is
/// wrong. Conformance is enforced by `test/vector_conformance_test.dart`, which
/// replays the vectors the reference generates.
///
/// DESIGN RULE (identical to the reference): no cryptographic primitive is
/// implemented here. Everything delegates to the audited `cryptography`
/// package. The only original logic is domain separation, key validation, and
/// an injectable randomness source for reproducible tests.
///
/// Algorithm selection — must match the reference byte for byte:
///   DH            X25519         (RFC 7748)
///   Signatures    Ed25519        (RFC 8032)
///   Hash          SHA-256        (FIPS 180-4)
///   MAC           HMAC-SHA-256   (RFC 2104)
///   KDF           HKDF-SHA-256   (RFC 5869)
///   AEAD          AES-256-GCM    (NIST SP 800-38D)
library;

import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'errors.dart';

// --- Sizes ------------------------------------------------------------------

const int x25519KeyLen = 32;
const int ed25519PubLen = 32;
const int ed25519SeedLen = 32;
const int ed25519SigLen = 64;
const int aes256KeyLen = 32;
const int aesGcmNonceLen = 12;
const int aesGcmTagLen = 16;
const int sha256Len = 32;
const int rootKeyLen = 32;
const int chainKeyLen = 32;

// --- Domain separation ------------------------------------------------------
// These strings are part of the protocol. Changing one changes every derived
// key and breaks compatibility with the reference implementation.

final Uint8List infoX3dh = _ascii('Helo_X3DH_v1');
final Uint8List infoRootRatchet = _ascii('Helo_RootRatchet_v1');
final Uint8List infoMessageKeys = _ascii('Helo_MessageKeys_v1');
final Uint8List infoFingerprint = _ascii('Helo_Fingerprint_v1');
final Uint8List infoStateEncryption = _ascii('Helo_SessionStateKey_v1');

const int chainConstMessageKey = 0x01;
const int chainConstNextChainKey = 0x02;

final Uint8List zeroSalt = Uint8List(sha256Len);

Uint8List _ascii(String s) => Uint8List.fromList(s.codeUnits);

// --- Algorithm instances ----------------------------------------------------

final X25519 _x25519 = X25519();
final Ed25519 _ed25519 = Ed25519();
final AesGcm _aesGcm = AesGcm.with256bits();
final Hmac _hmacSha256 = Hmac.sha256();
final Sha256 _sha256 = Sha256();

// --- Randomness -------------------------------------------------------------

/// Source of cryptographically secure random bytes.
abstract class RandomSource {
  Uint8List bytes(int n);
}

/// Production randomness: the platform CSPRNG.
///
/// `Random.secure()` maps to the OS entropy source. This is the ONLY randomness
/// source permitted in a shipping build; `Random()` (the deterministic one)
/// must never appear in this codebase and is blocked by a CI pattern scan.
class SystemRandomSource implements RandomSource {
  SystemRandomSource();
  final Random _random = Random.secure();

  @override
  Uint8List bytes(int n) {
    final Uint8List out = Uint8List(n);
    for (int i = 0; i < n; i++) {
      out[i] = _random.nextInt(256);
    }
    return out;
  }
}

final RandomSource defaultRandom = SystemRandomSource();

// --- Hash / MAC / KDF -------------------------------------------------------

Future<Uint8List> sha256Hash(List<int> data) async {
  final Hash h = await _sha256.hash(data);
  return Uint8List.fromList(h.bytes);
}

Future<Uint8List> hmacSha256(List<int> key, List<int> data) async {
  final Mac mac = await _hmacSha256.calculateMac(
    data,
    secretKey: SecretKey(key),
  );
  return Uint8List.fromList(mac.bytes);
}

/// HKDF-SHA-256 (extract-then-expand).
///
/// NOTE for reviewers: the `cryptography` package names the HKDF salt `nonce`.
/// It IS the salt, not an AEAD nonce. Passing the wrong value here would derive
/// different keys from the reference while still "working" locally — exactly
/// the class of bug the vector tests exist to catch.
Future<Uint8List> hkdf({
  required List<int> ikm,
  required List<int> salt,
  required List<int> info,
  required int length,
}) async {
  final Hkdf kdf = Hkdf(hmac: _hmacSha256, outputLength: length);
  final SecretKey key = await kdf.deriveKey(
    secretKey: SecretKey(ikm),
    nonce: salt,
    info: info,
  );
  return Uint8List.fromList(await key.extractBytes());
}

/// Constant-time comparison. Never use `==` on secret bytes.
bool constantTimeEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  int diff = 0;
  for (int i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

// --- Key validation ---------------------------------------------------------

/// X25519 points of small order, rejected so a hostile peer cannot force a
/// shared secret with a known or degenerate value.
final Set<String> _smallOrderX25519 = <String>{
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0100000000000000000000000000000000000000000000000000000000000000',
  'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
  '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880',
  '4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7',
  'd9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  'daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  'dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
};

String _hex(List<int> bytes) {
  final StringBuffer sb = StringBuffer();
  for (final int b in bytes) {
    sb.write(b.toRadixString(16).padLeft(2, '0'));
  }
  return sb.toString();
}

Uint8List validateX25519Public(List<int> pub) {
  if (pub.length != x25519KeyLen) {
    throw const InvalidKeyError('X25519 public key must be $x25519KeyLen bytes');
  }
  if (_smallOrderX25519.contains(_hex(pub))) {
    throw const InvalidKeyError('X25519 public key is a low-order point');
  }
  return Uint8List.fromList(pub);
}

Uint8List validateEd25519Public(List<int> pub) {
  if (pub.length != ed25519PubLen) {
    throw const InvalidKeyError('Ed25519 public key must be $ed25519PubLen bytes');
  }
  return Uint8List.fromList(pub);
}

// --- X25519 -----------------------------------------------------------------

class KeyPairBytes {
  const KeyPairBytes(this.privateKey, this.publicKey);
  final Uint8List privateKey;
  final Uint8List publicKey;
}

Future<KeyPairBytes> x25519Generate([RandomSource? rng]) =>
    x25519FromPrivate((rng ?? defaultRandom).bytes(x25519KeyLen));

Future<KeyPairBytes> x25519FromPrivate(List<int> priv) async {
  if (priv.length != x25519KeyLen) {
    throw const InvalidKeyError('X25519 private key must be 32 bytes');
  }
  final SimpleKeyPair kp = await _x25519.newKeyPairFromSeed(priv);
  final SimplePublicKey pub = await kp.extractPublicKey();
  final List<int> canonical = await kp.extractPrivateKeyBytes();
  return KeyPairBytes(
    Uint8List.fromList(canonical),
    Uint8List.fromList(pub.bytes),
  );
}

/// X25519 key agreement. Rejects low-order peer keys before use, and rejects an
/// all-zero shared secret as a belt-and-braces check.
Future<Uint8List> x25519Dh(List<int> priv, List<int> peerPublic) async {
  final Uint8List peer = validateX25519Public(peerPublic);
  if (priv.length != x25519KeyLen) {
    throw const InvalidKeyError('X25519 private key must be 32 bytes');
  }
  final SimpleKeyPair kp = await _x25519.newKeyPairFromSeed(priv);
  final SecretKey shared = await _x25519.sharedSecretKey(
    keyPair: kp,
    remotePublicKey: SimplePublicKey(peer, type: KeyPairType.x25519),
  );
  final Uint8List bytes = Uint8List.fromList(await shared.extractBytes());
  if (constantTimeEquals(bytes, Uint8List(x25519KeyLen))) {
    throw const InvalidKeyError('X25519 produced an all-zero shared secret');
  }
  return bytes;
}

// --- Ed25519 ----------------------------------------------------------------

Future<KeyPairBytes> ed25519Generate([RandomSource? rng]) =>
    ed25519FromSeed((rng ?? defaultRandom).bytes(ed25519SeedLen));

Future<KeyPairBytes> ed25519FromSeed(List<int> seed) async {
  if (seed.length != ed25519SeedLen) {
    throw const InvalidKeyError('Ed25519 seed must be 32 bytes');
  }
  final SimpleKeyPair kp = await _ed25519.newKeyPairFromSeed(seed);
  final SimplePublicKey pub = await kp.extractPublicKey();
  return KeyPairBytes(Uint8List.fromList(seed), Uint8List.fromList(pub.bytes));
}

Future<Uint8List> ed25519Sign(List<int> seed, List<int> message) async {
  final SimpleKeyPair kp = await _ed25519.newKeyPairFromSeed(seed);
  final Signature sig = await _ed25519.sign(message, keyPair: kp);
  return Uint8List.fromList(sig.bytes);
}

/// Verify an Ed25519 signature. Throws [SignatureVerificationError] on failure.
Future<void> ed25519Verify(
  List<int> publicKey,
  List<int> signature,
  List<int> message,
) async {
  validateEd25519Public(publicKey);
  if (signature.length != ed25519SigLen) {
    throw const SignatureVerificationError('Ed25519 signature must be 64 bytes');
  }
  final bool ok = await _ed25519.verify(
    message,
    signature: Signature(
      signature,
      publicKey: SimplePublicKey(publicKey, type: KeyPairType.ed25519),
    ),
  );
  if (!ok) {
    throw const SignatureVerificationError('Ed25519 verification failed');
  }
}

// --- AEAD -------------------------------------------------------------------

/// AES-256-GCM seal. Returns ciphertext ‖ tag, matching the reference layout.
Future<Uint8List> aes256GcmEncrypt({
  required List<int> key,
  required List<int> nonce,
  required List<int> plaintext,
  required List<int> associatedData,
}) async {
  if (key.length != aes256KeyLen) {
    throw const InvalidKeyError('AES-256-GCM key must be 32 bytes');
  }
  if (nonce.length != aesGcmNonceLen) {
    throw const InvalidKeyError('AES-GCM nonce must be 12 bytes');
  }
  final SecretBox box = await _aesGcm.encrypt(
    plaintext,
    secretKey: SecretKey(key),
    nonce: nonce,
    aad: associatedData,
  );
  return Uint8List.fromList(<int>[...box.cipherText, ...box.mac.bytes]);
}

/// AES-256-GCM open. Throws [AuthenticationError] if the tag does not verify.
///
/// No plaintext is returned on failure and no partial plaintext is exposed.
Future<Uint8List> aes256GcmDecrypt({
  required List<int> key,
  required List<int> nonce,
  required List<int> ciphertextAndTag,
  required List<int> associatedData,
}) async {
  if (key.length != aes256KeyLen) {
    throw const InvalidKeyError('AES-256-GCM key must be 32 bytes');
  }
  if (nonce.length != aesGcmNonceLen) {
    throw const InvalidKeyError('AES-GCM nonce must be 12 bytes');
  }
  if (ciphertextAndTag.length < aesGcmTagLen) {
    throw const AuthenticationError('ciphertext shorter than the tag');
  }
  final int split = ciphertextAndTag.length - aesGcmTagLen;
  final SecretBox box = SecretBox(
    ciphertextAndTag.sublist(0, split),
    nonce: nonce,
    mac: Mac(ciphertextAndTag.sublist(split)),
  );
  try {
    final List<int> plaintext = await _aesGcm.decrypt(
      box,
      secretKey: SecretKey(key),
      aad: associatedData,
    );
    return Uint8List.fromList(plaintext);
  } on SecretBoxAuthenticationError {
    throw const AuthenticationError('AEAD authentication failed');
  }
}

/// Best-effort zeroisation.
///
/// LIMITATION, documented rather than hidden: in a managed runtime this cannot
/// guarantee erasure. Copies may persist in GC'd memory, in swap, or in
/// hibernation images. Recorded in SECURITY_CLAIMS.md under endpoint security
/// limitations; this is not a claim of secure erasure.
void wipe(Uint8List buffer) {
  buffer.fillRange(0, buffer.length, 0);
}
