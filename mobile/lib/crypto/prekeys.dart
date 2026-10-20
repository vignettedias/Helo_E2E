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
import 'pq.dart';
import 'primitives.dart';

final Uint8List signedPreKeyContext =
    Uint8List.fromList('Helo_SignedPreKey_v1'.codeUnits);
final Uint8List pqPreKeyContext =
    Uint8List.fromList('Helo_PQPreKey_v1'.codeUnits);

const int signedPreKeyRotationSeconds = 7 * 24 * 60 * 60;
const int signedPreKeyRetentionSeconds = 30 * 24 * 60 * 60;
const int oneTimePreKeyBatch = 100;
const int oneTimePreKeyLowWatermark = 20;
// ML-KEM public keys are ~1.2 KB each, so the one-time batch is smaller.
const int pqOneTimePreKeyBatch = 20;
const int pqOneTimePreKeyLowWatermark = 5;

/// Exactly what IK_sig signs. Includes the key id, to prevent id swapping.
Uint8List signedPreKeySigningInput(int keyId, List<int> publicKey) =>
    concat(<List<int>>[signedPreKeyContext, u32(keyId), lp(publicKey)]);

/// What IK_sig signs for a PQ prekey. [encodedPublic] carries the KEM id, so
/// the signature also fixes which KEM the key belongs to.
Uint8List pqPreKeySigningInput(int keyId, List<int> encodedPublic) =>
    concat(<List<int>>[pqPreKeyContext, u32(keyId), lp(encodedPublic)]);

/// An ML-KEM prekey. SECRET: [seed] is the FIPS 203 (d ‖ z) private key.
class PqPreKeyPrivate {
  const PqPreKeyPrivate(
      this.keyId, this.seed, this.encodedPublic, this.lastResort, this.createdAt);
  final int keyId;
  final Uint8List seed;
  final Uint8List encodedPublic;
  final bool lastResort;
  final int createdAt;
}

class PqPreKeyPublic {
  const PqPreKeyPublic({
    required this.keyId,
    required this.encodedPublic,
    required this.signature,
    required this.oneTime,
  });

  final int keyId;
  final Uint8List encodedPublic; // Encode(PQPK) = KEM id ‖ ek
  final Uint8List signature;
  final bool oneTime;

  /// Check the encoding and the IK_sig signature. Fails closed.
  Future<void> verify(IdentityPublic identity) async {
    decodePqPublic(encodedPublic);
    await ed25519Verify(
      identity.sigPub,
      signature,
      pqPreKeySigningInput(keyId, encodedPublic),
    );
  }

  Uint8List get encapsulationKey => decodePqPublic(encodedPublic);

  Map<String, dynamic> toJson() => <String, dynamic>{
        'key_id': keyId,
        'public': b64e(encodedPublic),
        'signature': b64e(signature),
        'one_time': oneTime,
      };

  static PqPreKeyPublic fromJson(Map<String, dynamic> obj) {
    final Object? keyId = obj['key_id'];
    final Object? pub = obj['public'];
    final Object? sig = obj['signature'];
    if (keyId is! int || pub is! String || sig is! String) {
      throw const InvalidEncodingError('PQ prekey is missing a field');
    }
    return PqPreKeyPublic(
      keyId: keyId,
      encodedPublic: b64d(pub, expectLen: encodedPqPublicLen),
      signature: b64d(sig, expectLen: ed25519SigLen),
      oneTime: obj['one_time'] == true,
    );
  }
}

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
    this.pqPreKey,
  });

  final String deviceId;
  final IdentityPublic identity;
  final SignedPreKeyPublic signedPreKey;
  final OneTimePreKeyPublic? oneTimePreKey;
  final PqPreKeyPublic? pqPreKey;

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
    if (pqPreKey != null) await pqPreKey!.verify(identity);
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
    final Object? pq = obj['pq_prekey'];
    return PreKeyBundle(
      deviceId: deviceId,
      identity: IdentityPublic.fromJson(identity),
      signedPreKey: SignedPreKeyPublic.fromJson(signed),
      oneTimePreKey: otp is Map<String, dynamic>
          ? OneTimePreKeyPublic.fromJson(otp)
          : null,
      pqPreKey: pq is Map<String, dynamic> ? PqPreKeyPublic.fromJson(pq) : null,
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

  final Map<int, PqPreKeyPrivate> _pq = <int, PqPreKeyPrivate>{};
  final Map<int, Uint8List> _pqSignatures = <int, Uint8List>{};
  int? _currentPqLastResort;
  int _nextPqId = 1;

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

  // --- Post-quantum (ML-KEM-768) prekeys -----------------------------------

  Future<PqPreKeyPublic> _newPqPreKey({required bool lastResort}) async {
    final int keyId = _nextPqId++;
    final (Uint8List seed, Uint8List ek) = MlKem768.generate(_rng);
    final Uint8List encoded = encodePqPublic(ek);
    final Uint8List signature =
        await _identity.sign(pqPreKeySigningInput(keyId, encoded));
    _pq[keyId] = PqPreKeyPrivate(keyId, seed, encoded, lastResort, _clock());
    _pqSignatures[keyId] = signature;
    return PqPreKeyPublic(
      keyId: keyId,
      encodedPublic: encoded,
      signature: signature,
      oneTime: !lastResort,
    );
  }

  /// Replace the last-resort PQ prekey. The old seed is retained until
  /// pruned, so initial messages already in flight still decrypt.
  Future<PqPreKeyPublic> rotatePqLastResort() async {
    final PqPreKeyPublic record = await _newPqPreKey(lastResort: true);
    _currentPqLastResort = record.keyId;
    return record;
  }

  PqPreKeyPublic? get currentPqLastResort {
    final int? id = _currentPqLastResort;
    if (id == null) return null;
    return PqPreKeyPublic(
      keyId: id,
      encodedPublic: _pq[id]!.encodedPublic,
      signature: _pqSignatures[id]!,
      oneTime: false,
    );
  }

  Future<List<PqPreKeyPublic>> generatePqOneTimePreKeys([
    int count = pqOneTimePreKeyBatch,
  ]) async {
    final List<PqPreKeyPublic> out = <PqPreKeyPublic>[];
    for (int i = 0; i < count; i++) {
      out.add(await _newPqPreKey(lastResort: false));
    }
    return out;
  }

  int get pqOneTimePreKeyCount =>
      _pq.values.where((PqPreKeyPrivate k) => !k.lastResort).length;
  bool get needsPqReplenishment =>
      pqOneTimePreKeyCount < pqOneTimePreKeyLowWatermark;
  bool get hasPqLastResort => _currentPqLastResort != null;

  /// Return the seed for [keyId], DESTROYING it if one-time. The last-resort
  /// key keeps answering until rotated — the documented cost of having one.
  Uint8List consumePqPreKey(int keyId) {
    final PqPreKeyPrivate? record = _pq[keyId];
    if (record == null) {
      throw PreKeyUnavailableError(
          'PQ prekey $keyId unknown or already consumed');
    }
    if (!record.lastResort) {
      _pq.remove(keyId);
      _pqSignatures.remove(keyId);
    }
    return record.seed;
  }

  /// Snapshot of every prekey private half, for secure storage ONLY.
  ///
  /// The id counters are persisted explicitly rather than recomputed from the
  /// surviving keys. Recomputing would reuse the id of a consumed key whose
  /// public half the relay still holds, and the relay keeps the FIRST public
  /// key it saw for an id — so the device would end up holding a private key
  /// that matches nothing the relay serves.
  Map<String, Object?> toStorageJson() {
    Map<String, Object?> priv(PreKeyPrivate p) => <String, Object?>{
          'key_id': p.keyId,
          'private': b64e(p.privateKey),
          'public': b64e(p.publicKey),
          'created_at': p.createdAt,
        };
    return <String, Object?>{
      'v': 1,
      'current_signed_id': _currentSignedId,
      'next_signed_id': _nextSignedId,
      'next_one_time_id': _nextOneTimeId,
      'signed': _signed.values
          .map((PreKeyPrivate p) => <String, Object?>{
                ...priv(p),
                'signature': b64e(_signedPublic[p.keyId]!.signature),
              })
          .toList(),
      'one_time': _oneTime.values.map(priv).toList(),
      'pq': _pq.values
          .map((PqPreKeyPrivate k) => <String, Object?>{
                'key_id': k.keyId,
                'seed': b64e(k.seed),
                'public': b64e(k.encodedPublic),
                'signature': b64e(_pqSignatures[k.keyId]!),
                'last_resort': k.lastResort,
                'created_at': k.createdAt,
              })
          .toList(),
      'current_pq_last_resort': _currentPqLastResort,
      'next_pq_id': _nextPqId,
    };
  }

  /// Rebuild a store from [toStorageJson] output. Fails closed: malformed
  /// state raises rather than yielding a store with silently missing keys.
  static PreKeyStore fromStorageJson(
    IdentityKeyPair identity,
    Map<String, dynamic> obj, {
    RandomSource? rng,
    int Function()? clock,
  }) {
    final PreKeyStore store = PreKeyStore(identity, rng: rng, clock: clock);
    try {
      if (obj['v'] != 1) {
        throw const SessionStateCorruptError('unsupported prekey state');
      }
      PreKeyPrivate priv(Map<String, dynamic> e) => PreKeyPrivate(
            e['key_id']! as int,
            b64d(e['private']! as String, expectLen: x25519KeyLen),
            b64d(e['public']! as String, expectLen: x25519KeyLen),
            e['created_at']! as int,
          );
      for (final Object? raw in obj['signed']! as List<Object?>) {
        final Map<String, dynamic> e = raw! as Map<String, dynamic>;
        final PreKeyPrivate p = priv(e);
        store._signed[p.keyId] = p;
        store._signedPublic[p.keyId] = SignedPreKeyPublic(
          keyId: p.keyId,
          publicKey: p.publicKey,
          signature: b64d(e['signature']! as String, expectLen: ed25519SigLen),
          createdAt: p.createdAt,
        );
      }
      for (final Object? raw in obj['one_time']! as List<Object?>) {
        final PreKeyPrivate p = priv(raw! as Map<String, dynamic>);
        store._oneTime[p.keyId] = p;
      }
      store._currentSignedId = obj['current_signed_id'] as int?;
      store._nextSignedId = obj['next_signed_id']! as int;
      store._nextOneTimeId = obj['next_one_time_id']! as int;
      // PQ fields are absent in states written before HELO 2.0.
      for (final Object? raw in (obj['pq'] as List<Object?>?) ?? <Object?>[]) {
        final Map<String, dynamic> e = raw! as Map<String, dynamic>;
        final int id = e['key_id']! as int;
        store._pq[id] = PqPreKeyPrivate(
          id,
          b64d(e['seed']! as String, expectLen: mlKemSeedLen),
          b64d(e['public']! as String, expectLen: encodedPqPublicLen),
          e['last_resort']! as bool,
          e['created_at']! as int,
        );
        store._pqSignatures[id] =
            b64d(e['signature']! as String, expectLen: ed25519SigLen);
      }
      store._currentPqLastResort = obj['current_pq_last_resort'] as int?;
      store._nextPqId = (obj['next_pq_id'] as int?) ?? 1;
    } on SessionStateCorruptError {
      rethrow;
    } catch (_) {
      throw const SessionStateCorruptError('stored prekey state is malformed');
    }
    if (store._currentSignedId != null &&
        !store._signed.containsKey(store._currentSignedId)) {
      throw const SessionStateCorruptError('current signed prekey is missing');
    }
    if (store._currentPqLastResort != null &&
        !store._pq.containsKey(store._currentPqLastResort)) {
      throw const SessionStateCorruptError('current PQ last-resort key is missing');
    }
    return store;
  }
}
