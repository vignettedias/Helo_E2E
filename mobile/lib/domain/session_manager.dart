/// SessionManager — the boundary where plaintext becomes ciphertext.
///
/// This is the ONLY class in the app that holds both. Everything above it
/// (the UI) sees plaintext; everything below it (RelayClient) sees ciphertext.
/// Keeping that boundary in one auditable place is deliberate: a reviewer can
/// check this one file to confirm no plaintext reaches the network layer.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import '../crypto/encoding.dart';
import '../crypto/envelope.dart';
import '../crypto/errors.dart';
import '../crypto/identity.dart';
import '../crypto/prekeys.dart';
import '../crypto/primitives.dart';
import '../crypto/session.dart';
import '../data/relay_client.dart';
import '../security/secure_log.dart';
import '../storage/crypto_storage.dart';

/// Per-conversation history is capped so one busy chat cannot grow a single
/// storage entry without bound.
const int maxStoredMessagesPerConversation = 500;

/// A decrypted message held in memory for display.
class ChatMessage {
  ChatMessage({
    required this.peerDeviceId,
    required this.body,
    required this.outgoing,
    required this.timestamp,
    this.delivered = false,
  });

  final String peerDeviceId;
  final String body;
  final bool outgoing;
  final DateTime timestamp;
  bool delivered;

  Map<String, Object?> toJson() => <String, Object?>{
        'body': body,
        'out': outgoing,
        'ts': timestamp.millisecondsSinceEpoch,
        'delivered': delivered,
      };

  static ChatMessage fromJson(String peer, Map<String, dynamic> obj) =>
      ChatMessage(
        peerDeviceId: peer,
        body: obj['body']! as String,
        outgoing: obj['out']! as bool,
        timestamp: DateTime.fromMillisecondsSinceEpoch(obj['ts']! as int),
        delivered: obj['delivered'] as bool? ?? false,
      );
}

/// Why a conversation is showing a warning, if it is.
enum ConversationWarning {
  none,

  /// The peer's one-time prekeys were exhausted, so this session used the
  /// weaker three-DH handshake. An attacker can force this by draining prekeys,
  /// so it is surfaced rather than silently accepted.
  weakenedHandshake,

  /// The peer presented a different identity key. Never dismiss this silently.
  identityChanged;

  static ConversationWarning fromName(Object? name) =>
      ConversationWarning.values.firstWhere(
        (ConversationWarning w) => w.name == name,
        orElse: () => ConversationWarning.none,
      );
}

class Conversation {
  Conversation({required this.peerDeviceId, required this.session});
  final String peerDeviceId;
  Session session;
  final List<ChatMessage> messages = <ChatMessage>[];
  ConversationWarning warning = ConversationWarning.none;
}

class SessionManager {
  SessionManager({
    required this.storage,
    required this.relay,
    required this.deviceId,
    this.username,
  });

  final CryptoStorage storage;
  final RelayClient relay;
  final String deviceId;
  String? username;

  /// Called after [resetEverything], so the app can return to onboarding.
  void Function()? onReset;

  IdentityKeyPair? _identity;
  PreKeyStore? _prekeys;
  Uint8List? _stateKey;

  /// Guards against overlapping polls. Two concurrent receives would fetch the
  /// same queue twice and race to build the same responder session.
  bool _receiving = false;

  /// Shared in-flight token renewal, so concurrent 401s renew once.
  Future<void>? _reauth;

  final Map<String, Conversation> conversations = <String, Conversation>{};
  final StreamController<void> _changes = StreamController<void>.broadcast();
  Stream<void> get changes => _changes.stream;

  IdentityKeyPair get identity {
    final IdentityKeyPair? id = _identity;
    if (id == null) {
      throw const InvalidStateTransitionError('identity not initialised');
    }
    return id;
  }

  PreKeyStore get prekeys {
    final PreKeyStore? p = _prekeys;
    if (p == null) {
      throw const InvalidStateTransitionError('prekeys not initialised');
    }
    return p;
  }

  // --- identity lifecycle -------------------------------------------------

  /// Load an existing identity from secure storage, or create one.
  ///
  /// Returns true if a NEW identity was generated. That distinction matters:
  /// a new identity means peers will see an identity change and must re-verify.
  Future<bool> loadOrCreateIdentity() async {
    final Uint8List? sigSeed = await storage.get(StorageKeys.identitySigSeed);
    final Uint8List? dhPriv = await storage.get(StorageKeys.identityDhPriv);

    if (sigSeed != null && dhPriv != null) {
      final KeyPairBytes sig = await ed25519FromSeed(sigSeed);
      final KeyPairBytes dh = await x25519FromPrivate(dhPriv);
      final Uint8List binding = await ed25519Sign(
        sig.privateKey,
        Uint8List.fromList(<int>[...identityBindingContext, ...dh.publicKey]),
      );
      _identity = IdentityKeyPair(
        sigSeed: sig.privateKey,
        sigPub: sig.publicKey,
        dhPriv: dh.privateKey,
        dhPub: dh.publicKey,
        bindingSig: binding,
      );
      _prekeys = await _loadPreKeys(_identity!);
      await _loadStateKey();
      logger.info('identity_loaded');
      return false;
    }

    final IdentityKeyPair fresh = await IdentityKeyPair.generate();
    await storage.put(StorageKeys.identitySigSeed, fresh.sigSeed);
    await storage.put(StorageKeys.identityDhPriv, fresh.dhPriv);
    // Prekeys signed by a previous identity are useless and must not linger.
    await storage.delete(StorageKeys.preKeyState);
    _identity = fresh;
    _prekeys = PreKeyStore(fresh);
    await _loadStateKey();
    logger.info('identity_created');
    return true;
  }

  Future<PreKeyStore> _loadPreKeys(IdentityKeyPair id) async {
    final Uint8List? raw = await storage.get(StorageKeys.preKeyState);
    if (raw == null) return PreKeyStore(id);
    final Object? decoded = jsonDecode(utf8.decode(raw));
    if (decoded is! Map<String, dynamic>) {
      throw const SessionStateCorruptError('stored prekey state is malformed');
    }
    return PreKeyStore.fromStorageJson(id, decoded);
  }

  Future<void> _loadStateKey() async {
    Uint8List? key = await storage.get(StorageKeys.sessionStateKey);
    if (key == null) {
      key = defaultRandom.bytes(aes256KeyLen);
      await storage.put(StorageKeys.sessionStateKey, key);
    }
    _stateKey = key;
  }

  /// Restore a registered device after an app restart: identity, prekeys,
  /// relay tokens, sessions and history.
  ///
  /// Returns false when no identity is stored. The caller must then treat the
  /// device as unregistered, rather than silently minting a fresh identity
  /// under a device id the relay associates with the old one.
  Future<bool> restore() async {
    if (!await storage.containsKey(StorageKeys.identitySigSeed) ||
        !await storage.containsKey(StorageKeys.identityDhPriv)) {
      return false;
    }
    await loadOrCreateIdentity();
    username = await _getString(StorageKeys.username);
    relay.restoreTokens(
      account: await _getString(StorageKeys.accessToken),
      device: await _getString(StorageKeys.deviceToken),
      refresh: await _getString(StorageKeys.refreshToken),
    );
    await _loadConversations();
    return true;
  }

  // --- registration -------------------------------------------------------

  Future<void> registerWithRelay({
    required String username,
    required String password,
    bool createAccount = false,
  }) async {
    if (createAccount) {
      await relay.register(username, password);
    }
    await relay.login(username, password);
    await relay.registerDevice(
      deviceId: deviceId,
      identityPublic: identity.public.toJson(),
    );
    await publishPreKeys();

    this.username = username;
    await _putString(StorageKeys.username, username);
    await _persistTokens();
    // Written LAST: its presence is what marks this device as registered, so
    // a failure anywhere above leaves the app on the onboarding screen.
    await _putString(StorageKeys.deviceId, deviceId);
    logger.info('device_registered');
  }

  Future<int> publishPreKeys({int count = oneTimePreKeyBatch}) async {
    if (prekeys.needsSignedPreKeyRotation) {
      await prekeys.rotateSignedPreKey();
    }
    prekeys.pruneExpiredSignedPreKeys();
    final List<OneTimePreKeyPublic> batch =
        await prekeys.generateOneTimePreKeys(count);
    // Persist BEFORE publishing. The relay must never hold a public prekey
    // whose private half a crash could lose: a peer would then build a session
    // this device can never answer.
    await _persistPreKeys();
    final int available = await _authed(() => relay.publishPreKeys(
          deviceId: deviceId,
          signedPreKey: prekeys.currentSignedPreKey,
          oneTimePreKeys: batch,
        ));
    logger.info('prekeys_published', <String, Object?>{
      'prekey_count': available,
    });
    return available;
  }

  /// Rotate the signed prekey when it is due, and replenish one-time prekeys
  /// when the local store runs low.
  Future<void> maintainPreKeys() async {
    final bool rotate = prekeys.needsSignedPreKeyRotation;
    final bool replenish = prekeys.needsOneTimeReplenishment;
    if (rotate || replenish) {
      await publishPreKeys(count: replenish ? oneTimePreKeyBatch : 0);
    }
  }

  // --- relay authentication -----------------------------------------------

  /// Run a relay call, renewing tokens once if the relay reports them expired.
  ///
  /// Access and device tokens live for an hour. Without renewal the app would
  /// silently stop receiving an hour after sign-in.
  Future<T> _authed<T>(Future<T> Function() call) async {
    try {
      return await call();
    } on RelayException catch (e) {
      if (!e.isAuthFailure || relay.refreshToken == null) rethrow;
      await (_reauth ??= _reauthenticate().whenComplete(() => _reauth = null));
      return call();
    }
  }

  Future<void> _reauthenticate() async {
    await relay.refresh();
    // A device token cannot be refreshed directly; re-registering the same
    // device id with the same public identity issues a new one.
    await relay.registerDevice(
      deviceId: deviceId,
      identityPublic: identity.public.toJson(),
    );
    await _persistTokens();
    logger.info('relay_session_renewed');
  }

  // --- conversations ------------------------------------------------------

  Future<Conversation> startConversation(String peerDeviceId) async {
    final Conversation? existing = conversations[peerDeviceId];
    if (existing != null) return existing;
    if (peerDeviceId == deviceId) {
      throw const InvalidStateTransitionError(
          'cannot start a conversation with this device');
    }

    final FetchedBundle fetched =
        await _authed(() => relay.fetchBundle(peerDeviceId));

    // bundle.verify() runs inside startAsInitiator BEFORE any DH. A bundle
    // that fails validation never touches our private keys.
    final Session session = await startAsInitiator(
      identity: identity,
      localDeviceId: deviceId,
      bundle: fetched.bundle,
    );

    final Conversation conversation =
        Conversation(peerDeviceId: peerDeviceId, session: session);
    if (!fetched.oneTimePreKeyAvailable) {
      conversation.warning = ConversationWarning.weakenedHandshake;
      logger.security('handshake_downgraded', <String, Object?>{
        'used_one_time_prekey': false,
      });
    }
    conversations[peerDeviceId] = conversation;
    await _persist(conversation);
    _changes.add(null);
    return conversation;
  }

  Future<void> send(String peerDeviceId, String text) async {
    final Conversation conversation =
        conversations[peerDeviceId] ?? await startConversation(peerDeviceId);

    final Envelope envelope =
        await conversation.session.encryptMessage(utf8.encode(text));

    // Persist the advanced ratchet BEFORE the ciphertext leaves the device.
    // The AEAD nonce is derived from the message key, so if a crash rolled the
    // ratchet back after sending, the next message would reuse the same key
    // AND nonce for different plaintext -- the one failure AES-GCM cannot
    // survive. Saving first makes that sequence impossible.
    await _persist(conversation);
    await _authed(() => relay.sendEnvelope(
        recipientDeviceId: peerDeviceId, envelope: envelope));

    conversation.messages.add(ChatMessage(
      peerDeviceId: peerDeviceId,
      body: text,
      outgoing: true,
      timestamp: DateTime.now(),
      delivered: true,
    ));
    await _persist(conversation);
    _changes.add(null);
  }

  /// Fetch, decrypt, and acknowledge queued messages.
  ///
  /// A message that fails to decrypt is dropped and acknowledged, NOT retried
  /// forever: retrying a ciphertext the relay may have tampered with achieves
  /// nothing and lets a malicious relay wedge the queue permanently.
  Future<int> receive() async {
    if (_receiving || _identity == null) return 0;
    _receiving = true;
    try {
      return await _receiveOnce();
    } finally {
      _receiving = false;
    }
  }

  Future<int> _receiveOnce() async {
    final List<QueuedMessage> queued =
        await _authed(() => relay.fetchMessages());
    final List<String> toAck = <String>[];
    int accepted = 0;
    bool prekeysConsumed = false;

    for (final QueuedMessage item in queued) {
      toAck.add(item.messageId);
      try {
        Conversation? conversation = conversations[item.senderDeviceId];
        final bool isNew = conversation == null;

        if (conversation == null) {
          if (item.envelope.x3dh == null) {
            logger.warning('unknown_session', <String, Object?>{
              'outcome': 'dropped',
              'message_type': item.envelope.messageType,
            });
            continue;
          }
          prekeysConsumed = true;
          final Session session = await startAsResponder(
            identity: identity,
            localDeviceId: deviceId,
            prekeys: prekeys,
            envelope: item.envelope,
          );
          conversation =
              Conversation(peerDeviceId: item.senderDeviceId, session: session);
        }

        final Uint8List plaintext =
            await conversation.session.decryptMessage(item.envelope);
        // A new conversation is adopted only after its first message
        // authenticates, so a forged prekey message cannot plant a session.
        if (isNew) conversations[item.senderDeviceId] = conversation;
        conversation.messages.add(ChatMessage(
          peerDeviceId: item.senderDeviceId,
          body: utf8.decode(plaintext, allowMalformed: true),
          outgoing: false,
          timestamp: DateTime.fromMillisecondsSinceEpoch(item.queuedAt * 1000),
        ));
        accepted += 1;
        await _persist(conversation);
      } on IdentityChangedError {
        final Conversation? c = conversations[item.senderDeviceId];
        if (c != null) {
          c.warning = ConversationWarning.identityChanged;
          await _persist(c);
        }
        logger.security('identity_changed', <String, Object?>{
          'outcome': 'rejected',
        });
      } on ReplayError {
        logger.security('replay_rejected', <String, Object?>{
          'outcome': 'rejected',
        });
      } on AuthenticationError {
        logger.security('authentication_failed', <String, Object?>{
          'outcome': 'rejected',
        });
      } on HeloError catch (e) {
        logger.warning('message_rejected', <String, Object?>{
          'outcome': 'rejected',
          'error_class': e.runtimeType.toString(),
        });
      }
    }

    // A consumed one-time prekey must stay consumed across a restart.
    if (prekeysConsumed) await _persistPreKeys();
    if (toAck.isNotEmpty) await _authed(() => relay.acknowledge(toAck));
    await maintainPreKeys();
    if (queued.isNotEmpty) _changes.add(null);
    return accepted;
  }

  // --- verification -------------------------------------------------------

  Future<String> safetyNumberFor(String peerDeviceId) async {
    final Conversation? c = conversations[peerDeviceId];
    if (c == null) {
      throw const UnknownSessionError('no session with this peer');
    }
    return safetyNumber(identity.public, c.session.remoteIdentity);
  }

  Future<String> verificationQrFor(String peerDeviceId) async {
    final Conversation? c = conversations[peerDeviceId];
    if (c == null) {
      throw const UnknownSessionError('no session with this peer');
    }
    return qrPayload(identity.public, c.session.remoteIdentity);
  }

  Future<void> markVerified(String peerDeviceId) async {
    final Conversation? c = conversations[peerDeviceId];
    if (c == null) {
      throw const UnknownSessionError('no session with this peer');
    }
    c.session.markVerified();
    await _persist(c);
    _changes.add(null);
  }

  // --- persistence --------------------------------------------------------

  Future<String?> _getString(String key) async {
    final Uint8List? value = await storage.get(key);
    return value == null ? null : utf8.decode(value);
  }

  Future<void> _putString(String key, String? value) => value == null
      ? storage.delete(key)
      : storage.put(key, Uint8List.fromList(utf8.encode(value)));

  Future<void> _persistTokens() async {
    await _putString(StorageKeys.accessToken, relay.accountToken);
    await _putString(StorageKeys.deviceToken, relay.deviceToken);
    await _putString(StorageKeys.refreshToken, relay.refreshToken);
  }

  Future<void> _persistPreKeys() => storage.put(
        StorageKeys.preKeyState,
        Uint8List.fromList(utf8.encode(jsonEncode(prekeys.toStorageJson()))),
      );

  /// Save one conversation: sealed ratchet state, sealed history, and the
  /// index entry that maps the peer to its session.
  Future<void> _persist(Conversation conversation) async {
    final Uint8List? key = _stateKey;
    if (key == null) return;
    final String sid = conversation.session.sessionId;
    await storage.put(
        StorageKeys.session(sid), await conversation.session.save(key));

    final List<ChatMessage> all = conversation.messages;
    final List<ChatMessage> kept = all.length > maxStoredMessagesPerConversation
        ? all.sublist(all.length - maxStoredMessagesPerConversation)
        : all;
    final Uint8List history = Uint8List.fromList(utf8
        .encode(jsonEncode(kept.map((ChatMessage m) => m.toJson()).toList())));
    await storage.put(StorageKeys.history(sid), await _seal(sid, history));
    await _persistIndex();
  }

  Future<void> _persistIndex() => _putString(
        StorageKeys.conversationIndex,
        jsonEncode(conversations.values
            .map((Conversation c) => <String, Object?>{
                  'peer': c.peerDeviceId,
                  'session_id': c.session.sessionId,
                  'warning': c.warning.name,
                })
            .toList()),
      );

  Future<void> _loadConversations() async {
    final Uint8List? key = _stateKey;
    final String? index = await _getString(StorageKeys.conversationIndex);
    if (key == null || index == null) return;

    final Object? entries = jsonDecode(index);
    if (entries is! List<Object?>) return;
    for (final Object? raw in entries) {
      if (raw is! Map<String, dynamic>) continue;
      final Object? peer = raw['peer'];
      final Object? sid = raw['session_id'];
      if (peer is! String || sid is! String) continue;
      final Uint8List? blob = await storage.get(StorageKeys.session(sid));
      if (blob == null) continue;
      try {
        final Session session = await Session.load(blob, key, sid);
        final Conversation c =
            Conversation(peerDeviceId: peer, session: session)
              ..warning = ConversationWarning.fromName(raw['warning']);
        final Uint8List? sealed = await storage.get(StorageKeys.history(sid));
        if (sealed != null) {
          final Object? list =
              jsonDecode(utf8.decode(await _open(sid, sealed)));
          if (list is List<Object?>) {
            c.messages.addAll(list.whereType<Map<String, dynamic>>().map(
                (Map<String, dynamic> m) => ChatMessage.fromJson(peer, m)));
          }
        }
        conversations[peer] = c;
      } on HeloError catch (e) {
        // Corrupt or tampered state fails closed: the session is not loaded,
        // and a fresh one must be established. It is never "repaired".
        logger.security('session_state_rejected', <String, Object?>{
          'outcome': 'dropped',
          'error_class': e.runtimeType.toString(),
        });
      }
    }
  }

  /// History is plaintext, so it is sealed under a key derived from the
  /// session-state key, bound to its session id. The label is local storage
  /// domain separation, distinct from every protocol KDF string.
  Future<Uint8List> _historyKey(String sessionId) => hkdf(
        ikm: _stateKey!,
        salt: <int>[],
        info: utf8.encode('Helo_History_v1|$sessionId'),
        length: aes256KeyLen,
      );

  Future<Uint8List> _seal(String sessionId, Uint8List plaintext) async {
    final Uint8List nonce = defaultRandom.bytes(aesGcmNonceLen);
    final Uint8List sealed = await aes256GcmEncrypt(
      key: await _historyKey(sessionId),
      nonce: nonce,
      plaintext: plaintext,
      associatedData: utf8.encode('Helo_History_v1|$sessionId'),
    );
    return concat(<List<int>>[nonce, sealed]);
  }

  Future<Uint8List> _open(String sessionId, Uint8List blob) async {
    if (blob.length < aesGcmNonceLen + aesGcmTagLen) {
      throw const SessionStateCorruptError('stored history is truncated');
    }
    try {
      return await aes256GcmDecrypt(
        key: await _historyKey(sessionId),
        nonce: blob.sublist(0, aesGcmNonceLen),
        ciphertextAndTag: blob.sublist(aesGcmNonceLen),
        associatedData: utf8.encode('Helo_History_v1|$sessionId'),
      );
    } on HeloError {
      throw const SessionStateCorruptError(
          'stored history failed authentication');
    }
  }

  /// Destroy all key material. Peers will see an identity change and must
  /// re-verify — that warning is the correct outcome, not a bug.
  Future<void> resetEverything() async {
    conversations.clear();
    _identity = null;
    _prekeys = null;
    _stateKey = null;
    await storage.wipeAll();
    await relay.logout();
    _changes.add(null);
    onReset?.call();
  }

  /// The RelayClient is owned by the app, not by this manager: a reset hands
  /// the same client to the onboarding screen, so it must not be closed here.
  void dispose() {
    unawaited(_changes.close());
  }
}
