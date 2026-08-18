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

import '../crypto/envelope.dart';
import '../crypto/errors.dart';
import '../crypto/identity.dart';
import '../crypto/prekeys.dart';
import '../crypto/primitives.dart';
import '../crypto/session.dart';
import '../data/relay_client.dart';
import '../security/secure_log.dart';
import '../storage/crypto_storage.dart';

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
}

/// Why a conversation is showing a warning, if it is.
enum ConversationWarning {
  none,

  /// The peer's one-time prekeys were exhausted, so this session used the
  /// weaker three-DH handshake. An attacker can force this by draining prekeys,
  /// so it is surfaced rather than silently accepted.
  weakenedHandshake,

  /// The peer presented a different identity key. Never dismiss this silently.
  identityChanged,
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
  });

  final CryptoStorage storage;
  final RelayClient relay;
  final String deviceId;

  IdentityKeyPair? _identity;
  PreKeyStore? _prekeys;
  Uint8List? _stateKey;

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
      _prekeys = PreKeyStore(_identity!);
      await _loadStateKey();
      logger.info('identity_loaded');
      return false;
    }

    final IdentityKeyPair fresh = await IdentityKeyPair.generate();
    await storage.put(StorageKeys.identitySigSeed, fresh.sigSeed);
    await storage.put(StorageKeys.identityDhPriv, fresh.dhPriv);
    _identity = fresh;
    _prekeys = PreKeyStore(fresh);
    await _loadStateKey();
    logger.info('identity_created');
    return true;
  }

  Future<void> _loadStateKey() async {
    Uint8List? key = await storage.get(StorageKeys.sessionStateKey);
    if (key == null) {
      key = defaultRandom.bytes(aes256KeyLen);
      await storage.put(StorageKeys.sessionStateKey, key);
    }
    _stateKey = key;
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

    final String? account = relay.accountToken;
    final String? device = relay.deviceToken;
    if (account != null) {
      await storage.put(
          StorageKeys.accessToken, Uint8List.fromList(utf8.encode(account)));
    }
    if (device != null) {
      await storage.put(
          StorageKeys.deviceId, Uint8List.fromList(utf8.encode(device)));
    }
    logger.info('device_registered');
  }

  Future<int> publishPreKeys({int count = 100}) async {
    if (prekeys.needsSignedPreKeyRotation) {
      await prekeys.rotateSignedPreKey();
    }
    final List<OneTimePreKeyPublic> batch =
        await prekeys.generateOneTimePreKeys(count);
    final int available = await relay.publishPreKeys(
      deviceId: deviceId,
      signedPreKey: prekeys.currentSignedPreKey,
      oneTimePreKeys: batch,
    );
    logger.info('prekeys_published', <String, Object?>{
      'prekey_count': available,
    });
    return available;
  }

  /// Replenish prekeys if the local store is running low.
  Future<void> replenishPreKeysIfNeeded() async {
    if (prekeys.needsOneTimeReplenishment) await publishPreKeys();
  }

  // --- conversations ------------------------------------------------------

  Future<Conversation> startConversation(String peerDeviceId) async {
    final Conversation? existing = conversations[peerDeviceId];
    if (existing != null) return existing;

    final FetchedBundle fetched = await relay.fetchBundle(peerDeviceId);

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
    await relay.sendEnvelope(
        recipientDeviceId: peerDeviceId, envelope: envelope);

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
    final List<QueuedMessage> queued = await relay.fetchMessages();
    final List<String> toAck = <String>[];
    int accepted = 0;

    for (final QueuedMessage item in queued) {
      toAck.add(item.messageId);
      try {
        Conversation? conversation = conversations[item.senderDeviceId];

        if (conversation == null) {
          if (item.envelope.x3dh == null) {
            logger.warning('unknown_session', <String, Object?>{
              'outcome': 'dropped',
              'message_type': item.envelope.messageType,
            });
            continue;
          }
          final Session session = await startAsResponder(
            identity: identity,
            localDeviceId: deviceId,
            prekeys: prekeys,
            envelope: item.envelope,
          );
          conversation = Conversation(
              peerDeviceId: item.senderDeviceId, session: session);
          conversations[item.senderDeviceId] = conversation;
        }

        final Uint8List plaintext =
            await conversation.session.decryptMessage(item.envelope);
        conversation.messages.add(ChatMessage(
          peerDeviceId: item.senderDeviceId,
          body: utf8.decode(plaintext),
          outgoing: false,
          timestamp:
              DateTime.fromMillisecondsSinceEpoch(item.queuedAt * 1000),
        ));
        accepted += 1;
        await _persist(conversation);
      } on IdentityChangedError {
        final Conversation? c = conversations[item.senderDeviceId];
        if (c != null) c.warning = ConversationWarning.identityChanged;
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

    await relay.acknowledge(toAck);
    await replenishPreKeysIfNeeded();
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

  Future<void> _persist(Conversation conversation) async {
    final Uint8List? key = _stateKey;
    if (key == null) return;
    final Uint8List blob = await conversation.session.save(key);
    await storage.put('session.${conversation.session.sessionId}', blob);
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
  }

  void dispose() {
    unawaited(_changes.close());
    relay.close();
  }
}
