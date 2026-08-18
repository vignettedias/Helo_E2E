/// Prekey infrastructure — port of `helo_ref/prekeys.py`.
///
/// The relay stores PUBLIC prekey material so Alice can start a session while
/// Bob is offline. The relay is untrusted, so every field Alice consumes is
/// either signed by Bob's identity key or bound into the session transcript.
///
/// One-time prekeys are NOT individually signed (Signal does not sign them
/// either). A malicious relay can therefore serve a stale or absent OPK,
/// downgrading Alice to the three-DH variant. That does not break
/// authentication, but it does weaken forward secrecy for the very first
/// message. The relay surfaces `one_time_prekey_available` so the client can
/// warn rather than silently accept the downgrade.
library;

import 'dart:typed_data';

import 'encoding.dart';
import 'errors.dart';
import 'identity.dart';
import 'primitives.dart';

final Uint8List signedPreKeyContext =
    Uint8List.fromList('Helo_SignedPreKey_v1'.codeUnits);

const int signedPreKeyRotationSeconds = 7 * 24 * 60 * 60;
const int signedPreKeyRetentionSeconds = 30 * 24 * 60 * 60;
const int oneTimePreKeyBatch = 100;
const int oneTimePreKeyLowWatermark = 20;

/// Exactly what IK_sig signs. Includes the key id, to prevent id swapping.
Uint8List signedPreKeySigningInput(int keyId, List<int> publicKey) =>
    concat(<List<int>>[signedPreKeyContext, u32(keyId), lp(publicKey)]);

class PreKeyPrivate {
  const PreKeyPrivate(this.keyId, this.privateKey, this.publicKey, this.createdAt);
  final int keyId;
  final Uint8List privateKey; // SECRET
  final Uint8List publicKey;
  final int createdAt;
}

class SignedPreKeyPublic {
  const SignedPreKeyPublic({
    required this.keyId,
    required this.publicKey,
    required this.signature,
    required this.createdAt,
  });

  final int keyId;
  final Uint8List publicKey;
  final Uint8List signature;
  final int createdAt;

  Future<void> verify(IdentityPublic identity) async {
    validateX25519Public(publicKey);
    await ed25519Verify(
      identity.sigPub,
      signature,
      signedPreKeySigningInput(keyId, publicKey),
    );
  }

  Map<String, dynamic> toJson() => <String, dynamic>{
        'key_id': keyId,
        'public': b64e(publicKey),
        'signature': b64e(signature),
        'created_at': createdAt,
      };

  static SignedPreKeyPublic fromJson(Map<String, dynamic> obj) {
    final Object? keyId = obj['key_id'];
    final Object? pub = obj['public'];
    final Object? sig = obj['signature'];
    final Object? created = obj['created_at'];
    if (keyId is! int || pub is! String || sig is! String || created is! int) {
      throw const InvalidEncodingError('signed prekey is missing a field');
    }
    return SignedPreKeyPublic(
      keyId: keyId,
      publicKey: b64d(pub, expectLen: x25519KeyLen),
      signature: b64d(sig, expectLen: ed25519SigLen),
      createdAt: created,
    );
  }
}

class OneTimePreKeyPublic {
  const OneTimePreKeyPublic(this.keyId, this.publicKey);
  final int keyId;
  final Uint8List publicKey;

  Map<String, dynamic> toJson() =>
      <String, dynamic>{'key_id': keyId, 'public': b64e(publicKey)};

  static OneTimePreKeyPublic fromJson(Map<String, dynamic> obj) {
    final Object? keyId = obj['key_id'];
    final Object? pub = obj['public'];
    if (keyId is! int || pub is! String) {
      throw const InvalidEncodingError('one-time prekey is missing a field');
    }
    return OneTimePreKeyPublic(keyId, b64d(pub, expectLen: x25519KeyLen));
  }
}

class PreKeyBundle {
  const PreKeyBundle({
    required this.deviceId,
    required this.identity,
    required this.signedPreKey,
    this.oneTimePreKey,
  });

  final String deviceId;
  final IdentityPublic identity;
  final SignedPreKeyPublic signedPreKey;
  final OneTimePreKeyPublic? oneTimePreKey;

  /// Validate everything before any DH is performed.
  ///
  /// Order matters: the identity binding is checked FIRST, because the
  /// signed-prekey signature is only meaningful once IK_sig is known to
  /// genuinely belong to this identity.
  Future<void> verify() async {
    await identity.verifyBinding();
    await signedPreKey.verify(identity);
    if (oneTimePreKey != null) {
      validateX25519Public(oneTimePreKey!.publicKey);
    }
  }

  static PreKeyBundle fromJson(Map<String, dynamic> obj) {
    final Object? deviceId = obj['device_id'];
    final Object? identity = obj['identity'];
    final Object? signed = obj['signed_prekey'];
    if (deviceId is! String ||
        identity is! Map<String, dynamic> ||
        signed is! Map<String, dynamic>) {
      throw const InvalidEncodingError('prekey bundle is missing a field');
    }
    final Object? otp = obj['one_time_prekey'];
    return PreKeyBundle(
      deviceId: deviceId,
      identity: IdentityPublic.fromJson(identity),
      signedPreKey: SignedPreKeyPublic.fromJson(signed),
      oneTimePreKey: otp is Map<String, dynamic>
          ? OneTimePreKeyPublic.fromJson(otp)
          : null,
    );
  }
}

/// Client-side prekey lifecycle manager. Private halves never leave this
/// object; on device it is backed by CryptoStorage.
class PreKeyStore {
  PreKeyStore(this._identity, {RandomSource? rng, int Function()? clock})
      : _rng = rng ?? defaultRandom,
        _clock = clock ?? (() => DateTime.now().millisecondsSinceEpoch ~/ 1000);

  final IdentityKeyPair _identity;
  final RandomSource _rng;
  final int Function() _clock;

  final Map<int, PreKeyPrivate> _signed = <int, PreKeyPrivate>{};
  final Map<int, SignedPreKeyPublic> _signedPublic =
      <int, SignedPreKeyPublic>{};
  final Map<int, PreKeyPrivate> _oneTime = <int, PreKeyPrivate>{};
  int? _currentSignedId;
  int _nextSignedId = 1;
  int _nextOneTimeId = 1;

  Future<SignedPreKeyPublic> rotateSignedPreKey() async {
    final int keyId = _nextSignedId++;
    final KeyPairBytes kp = await x25519Generate(_rng);
    final int now = _clock();
    final Uint8List signature = await _identity
        .sign(signedPreKeySigningInput(keyId, kp.publicKey));
    _signed[keyId] = PreKeyPrivate(keyId, kp.privateKey, kp.publicKey, now);
    final SignedPreKeyPublic record = SignedPreKeyPublic(
      keyId: keyId,
      publicKey: kp.publicKey,
      signature: signature,
      createdAt: now,
    );
    _signedPublic[keyId] = record;
    _currentSignedId = keyId;
    return record;
  }

  SignedPreKeyPublic get currentSignedPreKey {
    final int? id = _currentSignedId;
    if (id == null) {
      throw const PreKeyUnavailableError('no signed prekey has been generated');
    }
    return _signedPublic[id]!;
  }

  bool get needsSignedPreKeyRotation {
    final int? id = _currentSignedId;
    if (id == null) return true;
    return _clock() - _signed[id]!.createdAt >= signedPreKeyRotationSeconds;
  }

  /// Delete signed-prekey private halves past their retention window.
  ///
  /// Deleting the private half is what actually delivers forward secrecy for
  /// the initial message; keeping it forever silently defeats it.
  List<int> pruneExpiredSignedPreKeys() {
    final int now = _clock();
    final List<int> removed = <int>[];
    for (final int keyId in _signed.keys.toList()) {
      if (keyId == _currentSignedId) continue;
      if (now - _signed[keyId]!.createdAt >= signedPreKeyRetentionSeconds) {
        _signed.remove(keyId);
        _signedPublic.remove(keyId);
        removed.add(keyId);
      }
    }
    return removed;
  }

  Future<List<OneTimePreKeyPublic>> generateOneTimePreKeys([
    int count = oneTimePreKeyBatch,
  ]) async {
    final List<OneTimePreKeyPublic> out = <OneTimePreKeyPublic>[];
    final int now = _clock();
    for (int i = 0; i < count; i++) {
      final int keyId = _nextOneTimeId++;
      final KeyPairBytes kp = await x25519Generate(_rng);
      _oneTime[keyId] = PreKeyPrivate(keyId, kp.privateKey, kp.publicKey, now);
      out.add(OneTimePreKeyPublic(keyId, kp.publicKey));
    }
    return out;
  }

  int get oneTimePreKeyCount => _oneTime.length;
  bool get needsOneTimeReplenishment =>
      _oneTime.length < oneTimePreKeyLowWatermark;

  Uint8List signedPreKeyPrivate(int keyId) {
    final PreKeyPrivate? record = _signed[keyId];
    if (record == null) {
      throw PreKeyUnavailableError('signed prekey $keyId unknown or expired');
    }
    return record.privateKey;
  }

  /// Return and DESTROY a one-time prekey private half.
  ///
  /// Destruction is what makes it one-time, and is one of the layers that makes
  /// replay of an initial message fail.
  Uint8List consumeOneTimePreKey(int keyId) {
    final PreKeyPrivate? record = _oneTime.remove(keyId);
    if (record == null) {
      throw PreKeyUnavailableError(
          'one-time prekey $keyId unknown or already consumed');
    }
    return record.privateKey;
  }

  /// Import persisted prekey material after a restart.
  void restore({
    required Iterable<PreKeyPrivate> signed,
    required Iterable<PreKeyPrivate> oneTime,
    required Map<int, SignedPreKeyPublic> signedPublic,
    required int currentSignedId,
  }) {
    for (final PreKeyPrivate p in signed) {
      _signed[p.keyId] = p;
      _nextSignedId = _nextSignedId > p.keyId ? _nextSignedId : p.keyId + 1;
    }
    for (final PreKeyPrivate p in oneTime) {
      _oneTime[p.keyId] = p;
      _nextOneTimeId = _nextOneTimeId > p.keyId ? _nextOneTimeId : p.keyId + 1;
    }
    _signedPublic.addAll(signedPublic);
    _currentSignedId = currentSignedId;
  }
}
