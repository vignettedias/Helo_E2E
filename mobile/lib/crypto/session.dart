/// Session layer — port of `helo_ref/session.py`.
///
/// State machine (enforced; invalid transitions throw):
///
///     UNINITIALIZED → IDENTITY_CREATED → PREKEY_PUBLISHED
///                                              ↓
///                                     SESSION_ESTABLISHED
///                                              ↓
///                            SESSION_ACTIVE ⇄ RATCHETING
///                                              ↓
///                                     SESSION_REVOKED (terminal)
///
/// A revoked session is terminal on purpose. "Recover by resetting the state"
/// is how implementations accidentally build a downgrade path.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'encoding.dart';
import 'envelope.dart';
import 'errors.dart';
import 'identity.dart';
import 'prekeys.dart';
import 'primitives.dart';
import 'ratchet.dart';
import 'x3dh.dart';

const int stateFormatVersion = 1;

enum SessionState {
  uninitialized('UNINITIALIZED'),
  identityCreated('IDENTITY_CREATED'),
  prekeyPublished('PREKEY_PUBLISHED'),
  sessionEstablished('SESSION_ESTABLISHED'),
  ratcheting('RATCHETING'),
  sessionActive('SESSION_ACTIVE'),
  sessionRevoked('SESSION_REVOKED');

  const SessionState(this.wire);
  final String wire;

  static SessionState fromWire(String value) => SessionState.values
      .firstWhere((SessionState s) => s.wire == value,
          orElse: () => throw const SessionStateCorruptError('unknown state'));
}

const Map<SessionState, Set<SessionState>> allowedTransitions =
    <SessionState, Set<SessionState>>{
  SessionState.uninitialized: <SessionState>{SessionState.identityCreated},
  SessionState.identityCreated: <SessionState>{SessionState.prekeyPublished},
  SessionState.prekeyPublished: <SessionState>{
    SessionState.sessionEstablished
  },
  SessionState.sessionEstablished: <SessionState>{
    SessionState.sessionActive,
    SessionState.ratcheting,
    SessionState.sessionRevoked,
  },
  SessionState.sessionActive: <SessionState>{
    SessionState.ratcheting,
    SessionState.sessionActive,
    SessionState.sessionRevoked,
  },
  SessionState.ratcheting: <SessionState>{
    SessionState.sessionActive,
    SessionState.sessionRevoked,
  },
  SessionState.sessionRevoked: <SessionState>{},
};

enum VerificationStatus {
  unverified('UNVERIFIED'),
  verified('VERIFIED'),
  identityChanged('IDENTITY_CHANGED');

  const VerificationStatus(this.wire);
  final String wire;

  static VerificationStatus fromWire(String value) =>
      VerificationStatus.values.firstWhere(
          (VerificationStatus s) => s.wire == value,
          orElse: () =>
              throw const SessionStateCorruptError('unknown verification'));
}

/// One end of one cryptographic conversation with one peer device.
class Session {
  Session({
    required this.sessionId,
    required this.localDeviceId,
    required this.remoteIdentity,
    required this.ratchet,
    required this.associatedData,
    this.state = SessionState.sessionEstablished,
    this.verification = VerificationStatus.unverified,
    this.pendingX3dh,
    this.usedOneTimePreKey = true,
  });

  final String sessionId;
  final String localDeviceId;
  IdentityPublic remoteIdentity;
  RatchetState ratchet;
  final Uint8List associatedData;
  SessionState state;
  VerificationStatus verification;

  /// Alice repeats the X3DH header until Bob demonstrably has the session.
  InitialMessageHeader? pendingX3dh;
  bool usedOneTimePreKey;

  void _transition(SessionState target) {
    if (!allowedTransitions[state]!.contains(target)) {
      throw InvalidStateTransitionError(
          'illegal transition ${state.wire} -> ${target.wire}');
    }
    state = target;
  }

  void _requireUsable() {
    if (state == SessionState.sessionRevoked) {
      throw const InvalidStateTransitionError('session is revoked');
    }
    if (state == SessionState.uninitialized ||
        state == SessionState.identityCreated) {
      throw const InvalidStateTransitionError('session is not established');
    }
  }

  /// Terminal. Used on logout, device revocation, or identity change.
  void revoke() {
    state = SessionState.sessionRevoked;
    ratchet.skipped.clear();
  }

  Future<Envelope> encryptMessage(List<int> plaintext) async {
    _requireUsable();
    final EncryptedMessage msg =
        await encrypt(ratchet, plaintext, associatedData);
    _transition(SessionState.sessionActive);
    return Envelope(
      sessionId: sessionId,
      senderDeviceId: localDeviceId,
      header: msg.header,
      ciphertext: msg.ciphertext,
      x3dh: pendingX3dh,
    );
  }

  Future<Uint8List> decryptMessage(Envelope envelope) async {
    _requireUsable();

    if (envelope.x3dh != null) {
      // A repeated X3DH header on an established session is expected — the
      // sender has not yet seen our reply. It must carry the SAME identity;
      // otherwise this is an identity substitution attempt.
      final IdentityPublic incoming = envelope.x3dh!.initiatorIdentity;
      if (!constantTimeEquals(incoming.encode(), remoteIdentity.encode())) {
        verification = VerificationStatus.identityChanged;
        throw const IdentityChangedError(
            'peer identity differs from the one bound to this session');
      }
    }

    final DecryptResult result = await decrypt(
      ratchet,
      envelope.header,
      envelope.ciphertext,
      associatedData,
    );
    // Commit only after full success.
    ratchet = result.state;
    pendingX3dh = null;
    _transition(SessionState.sessionActive);
    return result.plaintext;
  }

  void markVerified() {
    if (verification == VerificationStatus.identityChanged) {
      throw const InvalidStateTransitionError(
          'cannot mark verified while an identity change is unresolved');
    }
    verification = VerificationStatus.verified;
  }

  /// Developer diagnostics containing NO secret material.
  ///
  /// Fingerprints are truncated hashes; counters and inventory sizes are
  /// metadata the relay can already infer. Nothing here derives a key.
  Future<Map<String, Object?>> diagnostics() async {
    String short(List<int> b) => b64e(b).substring(0, 12);
    return <String, Object?>{
      'session_id_hash':
          short((await sha256Hash(utf8.encode(sessionId))).sublist(0, 8)),
      'device_id_hash':
          short((await sha256Hash(utf8.encode(localDeviceId))).sublist(0, 8)),
      'protocol_version': ratchet.sessionVersion,
      'state': state.wire,
      'verification': verification.wire,
      'messages_sent': ratchet.nSend,
      'messages_received': ratchet.nRecv,
      'previous_chain_length': ratchet.prevChainLen,
      'skipped_keys_stored': ratchet.skipped.length,
      'local_ratchet_fingerprint':
          short((await sha256Hash(ratchet.dhSendPub)).sublist(0, 8)),
      'remote_ratchet_fingerprint': ratchet.dhRecvPub == null
          ? null
          : short((await sha256Hash(ratchet.dhRecvPub!)).sublist(0, 8)),
      'remote_identity_fingerprint':
          short((await remoteIdentity.fingerprint()).sublist(0, 8)),
      'used_one_time_prekey': usedOneTimePreKey,
    };
  }

  Uint8List _serialise() {
    final RatchetState r = ratchet;
    final Map<String, Object?> obj = <String, Object?>{
      'format': stateFormatVersion,
      'session_id': sessionId,
      'local_device_id': localDeviceId,
      'remote_identity': remoteIdentity.toJson(),
      'associated_data': b64e(associatedData),
      'state': state.wire,
      'verification': verification.wire,
      'used_one_time_prekey': usedOneTimePreKey,
      // Kept until the peer replies. Without it, a session started but not yet
      // used before a restart would send its first message with no X3DH header,
      // and the peer could never establish its side.
      'pending_x3dh': pendingX3dh?.toJson(),
      'ratchet': <String, Object?>{
        'root_key': b64e(r.rootKey),
        'dh_send_priv': b64e(r.dhSendPriv),
        'dh_send_pub': b64e(r.dhSendPub),
        'dh_recv_pub': r.dhRecvPub == null ? null : b64e(r.dhRecvPub!),
        'chain_key_send':
            r.chainKeySend == null ? null : b64e(r.chainKeySend!),
        'chain_key_recv':
            r.chainKeyRecv == null ? null : b64e(r.chainKeyRecv!),
        'n_send': r.nSend,
        'n_recv': r.nRecv,
        'prev_chain_len': r.prevChainLen,
        'session_version': r.sessionVersion,
        'skipped': r.skipped.entries
            .map((MapEntry<SkippedKeyId, Uint8List> e) => <String, Object?>{
                  'dh': b64e(e.key.dhPub),
                  'n': e.key.n,
                  'mk': b64e(e.value),
                })
            .toList(),
        'seen_remote_ratchets':
            r.seenRemoteRatchets.map<String>(b64e).toList(),
      },
    };
    return Uint8List.fromList(utf8.encode(jsonEncode(obj)));
  }

  /// Encrypt session state for persistence.
  ///
  /// Session state contains chain keys and the ratchet private key. Writing it
  /// to disk in the clear would defeat the entire design, so it is sealed under
  /// a key that itself lives in the platform keystore. The session id is bound
  /// as associated data, so a stored blob cannot be swapped between sessions.
  Future<Uint8List> save(Uint8List storageKey, {RandomSource? rng}) async {
    final Uint8List key = await hkdf(
      ikm: storageKey,
      salt: <int>[],
      info: concat(<List<int>>[infoStateEncryption, utf8.encode(sessionId)]),
      length: aes256KeyLen,
    );
    final Uint8List nonce = (rng ?? defaultRandom).bytes(aesGcmNonceLen);
    final Uint8List ad =
        concat(<List<int>>[utf8.encode('Helo_State_v1|'), utf8.encode(sessionId)]);
    final Uint8List sealed = await aes256GcmEncrypt(
      key: key,
      nonce: nonce,
      plaintext: _serialise(),
      associatedData: ad,
    );
    return concat(<List<int>>[nonce, sealed]);
  }

  /// Decrypt and validate persisted state. Fails closed on corruption.
  static Future<Session> load(
    Uint8List blob,
    Uint8List storageKey,
    String sessionId,
  ) async {
    if (blob.length < aesGcmNonceLen + aesGcmTagLen) {
      throw const SessionStateCorruptError('stored session blob is truncated');
    }
    final Uint8List key = await hkdf(
      ikm: storageKey,
      salt: <int>[],
      info: concat(<List<int>>[infoStateEncryption, utf8.encode(sessionId)]),
      length: aes256KeyLen,
    );
    final Uint8List ad =
        concat(<List<int>>[utf8.encode('Helo_State_v1|'), utf8.encode(sessionId)]);

    Uint8List raw;
    try {
      raw = await aes256GcmDecrypt(
        key: key,
        nonce: blob.sublist(0, aesGcmNonceLen),
        ciphertextAndTag: blob.sublist(aesGcmNonceLen),
        associatedData: ad,
      );
    } on HeloError {
      throw const SessionStateCorruptError(
          'stored session state failed authentication');
    }

    try {
      final Object? decoded = jsonDecode(utf8.decode(raw));
      if (decoded is! Map<String, dynamic>) {
        throw const SessionStateCorruptError('state is not an object');
      }
      if (decoded['format'] != stateFormatVersion) {
        throw const SessionStateCorruptError('unsupported state format');
      }
      final Object? rObj = decoded['ratchet'];
      if (rObj is! Map<String, dynamic>) {
        throw const SessionStateCorruptError('missing ratchet state');
      }

      final Map<SkippedKeyId, Uint8List> skipped =
          <SkippedKeyId, Uint8List>{};
      final Object? skippedList = rObj['skipped'];
      if (skippedList is List<Object?>) {
        for (final Object? entry in skippedList) {
          if (entry is! Map<String, dynamic>) continue;
          skipped[SkippedKeyId(
            b64d(entry['dh']! as String),
            entry['n']! as int,
          )] = b64d(entry['mk']! as String);
        }
      }

      final List<Uint8List> seen = <Uint8List>[];
      final Object? seenList = rObj['seen_remote_ratchets'];
      if (seenList is List<Object?>) {
        for (final Object? k in seenList) {
          if (k is String) seen.add(b64d(k));
        }
      }

      final RatchetState ratchet = RatchetState(
        rootKey: b64d(rObj['root_key']! as String),
        dhSendPriv: b64d(rObj['dh_send_priv']! as String),
        dhSendPub: b64d(rObj['dh_send_pub']! as String),
        dhRecvPub: rObj['dh_recv_pub'] == null
            ? null
            : b64d(rObj['dh_recv_pub']! as String),
        chainKeySend: rObj['chain_key_send'] == null
            ? null
            : b64d(rObj['chain_key_send']! as String),
        chainKeyRecv: rObj['chain_key_recv'] == null
            ? null
            : b64d(rObj['chain_key_recv']! as String),
        nSend: rObj['n_send']! as int,
        nRecv: rObj['n_recv']! as int,
        prevChainLen: rObj['prev_chain_len']! as int,
        skipped: skipped,
        seenRemoteRatchets: seen,
        sessionVersion: rObj['session_version']! as int,
      );
      await ratchet.validate();

      return Session(
        sessionId: decoded['session_id']! as String,
        localDeviceId: decoded['local_device_id']! as String,
        remoteIdentity: IdentityPublic.fromJson(
            decoded['remote_identity']! as Map<String, dynamic>),
        ratchet: ratchet,
        associatedData: b64d(decoded['associated_data']! as String),
        state: SessionState.fromWire(decoded['state']! as String),
        verification:
            VerificationStatus.fromWire(decoded['verification']! as String),
        usedOneTimePreKey: decoded['used_one_time_prekey']! as bool,
        pendingX3dh: decoded['pending_x3dh'] is Map<String, dynamic>
            ? InitialMessageHeader.fromJson(
                decoded['pending_x3dh']! as Map<String, dynamic>)
            : null,
      );
    } on SessionStateCorruptError {
      rethrow;
    } catch (_) {
      throw const SessionStateCorruptError('stored session state is malformed');
    }
  }
}

/// Alice starts a session against a bundle fetched from the relay.
///
/// Works with Bob entirely offline: nothing here requires his participation.
Future<Session> startAsInitiator({
  required IdentityKeyPair identity,
  required String localDeviceId,
  required PreKeyBundle bundle,
  RandomSource? rng,
}) async {
  final InitiateOutcome outcome =
      await x3dhInitiate(identity: identity, bundle: bundle, rng: rng);
  final RatchetState ratchet = await initInitiator(
    sharedSecret: outcome.result.sharedSecret,
    remoteSignedPreKeyPub: bundle.signedPreKey.publicKey,
    rng: rng,
  );
  return Session(
    sessionId: outcome.result.sessionId,
    localDeviceId: localDeviceId,
    remoteIdentity: bundle.identity,
    ratchet: ratchet,
    associatedData: outcome.result.associatedData,
    pendingX3dh: outcome.header,
    usedOneTimePreKey: outcome.result.usedOneTimePreKey,
  );
}

/// Bob builds his side from Alice's first (prekey) message.
Future<Session> startAsResponder({
  required IdentityKeyPair identity,
  required String localDeviceId,
  required PreKeyStore prekeys,
  required Envelope envelope,
}) async {
  final InitialMessageHeader? header = envelope.x3dh;
  if (header == null) {
    throw const UnknownSessionError(
        'cannot establish a session from a message without an X3DH header');
  }
  final X3dhResult result = await x3dhRespond(
    identity: identity,
    prekeys: prekeys,
    header: header,
  );
  final RatchetState ratchet = await initResponder(
    sharedSecret: result.sharedSecret,
    signedPreKeyPriv: prekeys.signedPreKeyPrivate(header.signedPreKeyId),
  );
  return Session(
    sessionId: result.sessionId,
    localDeviceId: localDeviceId,
    remoteIdentity: header.initiatorIdentity,
    ratchet: ratchet,
    associatedData: result.associatedData,
    usedOneTimePreKey: result.usedOneTimePreKey,
  );
}
