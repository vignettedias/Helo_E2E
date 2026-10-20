/// Messenger — the boundary where plaintext becomes ciphertext.
///
/// This is the ONLY class that holds both. The UI above it sees plaintext;
/// RelayClient below it sees envelopes and encrypted attachment blobs. A
/// reviewer can audit this one file to confirm no plaintext reaches the
/// network layer.
///
/// Invariants enforced here (each has a test in test/messenger_test.dart):
///  * Ratchet state is persisted BEFORE its ciphertext leaves the device, and
///    a retry re-sends the SAME envelope — never a re-encryption — so a
///    message key and its derived nonce are never used twice.
///  * Every ratchet operation runs under one lock (see async_lock.dart).
///  * A sender is the relay-authenticated account of the sending DEVICE,
///    bound on first contact to that device's pinned identity key. Nothing in
///    a payload can claim to be from someone else.
///  * Sessions are hybrid PQXDH unless the user explicitly allowed classical
///    contacts; a missing PQ prekey is never silently downgraded.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:flutter/foundation.dart';

import '../crypto/attachment.dart';
import '../crypto/encoding.dart';
import '../crypto/envelope.dart';
import '../crypto/errors.dart';
import '../crypto/identity.dart';
import '../crypto/padding.dart';
import '../crypto/pqxdh.dart';
import '../crypto/prekeys.dart';
import '../crypto/primitives.dart';
import '../crypto/session.dart';
import '../crypto/x3dh.dart';
import '../data/relay_client.dart';
import '../protocol/payload.dart';
import '../security/secure_log.dart';
import '../storage/crypto_storage.dart';
import 'async_lock.dart';
import 'directory.dart';
import 'groups.dart';
import 'local_store.dart';
import 'models.dart';

enum ConnectionStatus { connecting, online, offline, signedOut }

class MessengerException implements Exception {
  const MessengerException(this.message);
  final String message;
  @override
  String toString() => message;
}

/// A safety number for one of a contact's devices.
/// Result of [Messenger.verifyByScannedCode]: the verdict, and the device it
/// concerns when the code's owner key is one of the contact's devices.
class QrScanOutcome {
  const QrScanOutcome(this.check, this.device);

  final QrCheck check;
  final DevicePin? device;
}

class DeviceSafety {
  const DeviceSafety(this.pin, this.safetyNumber, this.qrPayload);
  final DevicePin pin;
  final String safetyNumber;
  final String qrPayload;
}

class SearchHit {
  const SearchHit(this.conversation, this.message);
  final Conversation conversation;
  final ChatMessage message;
}

/// An incoming message the UI may want to notify about.
class IncomingNotice {
  const IncomingNotice(this.conversation, this.message);
  final Conversation conversation;
  final ChatMessage message;
}

class _OutboxItem {
  _OutboxItem(this.payloadId, this.convId, this.envelopes, {this.attempts = 0});
  final String payloadId;
  final String convId;

  /// recipient device id -> envelope JSON. Ciphertext only.
  final Map<String, Map<String, dynamic>> envelopes;
  int attempts;
  int accepted = 0;

  Map<String, Object?> toJson() => <String, Object?>{
        'id': payloadId, 'conv': convId, 'env': envelopes, 'attempts': attempts,
        'accepted': accepted,
      };

  static _OutboxItem fromJson(Map<String, dynamic> m) => _OutboxItem(
        m['id']! as String,
        m['conv']! as String,
        (m['env']! as Map<String, dynamic>).map((String k, dynamic v) =>
            MapEntry<String, Map<String, dynamic>>(k, v as Map<String, dynamic>)),
        attempts: m['attempts'] as int? ?? 0,
      )..accepted = m['accepted'] as int? ?? 0;
}

const int _maxArchivedSessions = 3;
const int _maxHistory = 1000;
const Duration _editWindow = Duration(minutes: 15);
const Duration _deleteWindow = Duration(hours: 48);
const Duration _typingLifetime = Duration(seconds: 6);

class Messenger {
  Messenger._({
    required this.storage,
    required this.relay,
    required this.username,
    required this.deviceId,
  })  : store = LocalStore(storage),
        directory = Directory(relay);

  final CryptoStorage storage;
  final RelayClient relay;
  final LocalStore store;
  final Directory directory;
  final String username;
  final String deviceId;

  late IdentityKeyPair identity;
  late PreKeyStore prekeys;

  /// remote device id -> sessions, current first (older ones are kept briefly
  /// so that simultaneous initiation converges instead of diverging).
  final Map<String, List<Session>> _sessions = <String, List<Session>>{};
  final Map<String, Conversation> conversations = <String, Conversation>{};
  final Map<String, Contact> contacts = <String, Contact>{};
  AppSettings settings = AppSettings();
  MyProfile profile = MyProfile();
  final List<_OutboxItem> _outbox = <_OutboxItem>[];
  final Set<String> _profileShared = <String>{};
  final Map<String, Uint8List> _attachmentCache = <String, Uint8List>{};
  final Set<String> _seenPayloads = <String>{};

  final AsyncLock _lock = AsyncLock();
  final StreamController<void> _changes = StreamController<void>.broadcast();
  final StreamController<IncomingNotice> _incoming =
      StreamController<IncomingNotice>.broadcast();
  final ValueNotifier<ConnectionStatus> connection =
      ValueNotifier<ConnectionStatus>(ConnectionStatus.connecting);

  Stream<void> get changes => _changes.stream;
  Stream<IncomingNotice> get incoming => _incoming.stream;

  /// Called after the account is reset or deleted, so the app can return to
  /// onboarding.
  void Function()? onReset;

  /// The conversation currently on screen: incoming messages there are read
  /// immediately rather than counted as unread.
  String? activeConversationId;

  bool _running = false;

  /// One in-flight prekey-bundle fetch per device: concurrent sends (typing,
  /// profile, message) must not each consume one of the peer's one-time keys.
  final Map<String, Future<FetchedBundle>> _bundleFetches = <String, Future<FetchedBundle>>{};
  Future<void>? _reauth;
  Timer? _saveTimer;
  final Set<String> _dirtyHistory = <String>{};
  final Map<String, DateTime> _typingSentAt = <String, DateTime>{};

  PaddingPolicy get _padding =>
      paddingPolicies[settings.padding] ?? defaultPaddingPolicy;

  // =====================================================================
  // Construction
  // =====================================================================

  /// Create (or sign in to) an account on this device: a fresh identity, a
  /// fresh device id, prekeys published. Nothing secret leaves the device.
  static Future<Messenger> register({
    required CryptoStorage storage,
    required RelayClient relay,
    required String username,
    required String password,
    bool createAccount = true,
  }) async {
    final String user = username.trim().toLowerCase();
    if (createAccount) await relay.register(user, password);
    await relay.login(user, password);

    final Messenger m = Messenger._(
      storage: storage,
      relay: relay,
      username: user,
      deviceId: 'device-${_hex(defaultRandom.bytes(6))}',
    );
    await m.store.open();
    m.identity = await IdentityKeyPair.generate();
    await storage.put(StorageKeys.identitySigSeed, m.identity.sigSeed);
    await storage.put(StorageKeys.identityDhPriv, m.identity.dhPriv);
    m.prekeys = PreKeyStore(m.identity);
    m.profile = MyProfile(displayName: user);

    await relay.registerDevice(deviceId: m.deviceId, identityPublic: m.identity.public.toJson());
    await m._publishPreKeys(initial: true);
    await m._putString(StorageKeys.username, user);
    await m._persistTokens();
    await m.store.put('profile', m.profile.toJson());
    await m.store.put('settings', m.settings.toJson());
    // Written LAST: its presence marks the device as registered, so a failure
    // anywhere above leaves the app on onboarding.
    await m._putString(StorageKeys.deviceId, m.deviceId);
    logger.info('device_registered');
    return m;
  }

  /// Restore a registered device after a restart, or null if none exists.
  static Future<Messenger?> restore({
    required CryptoStorage storage,
    required RelayClient relay,
  }) async {
    final Uint8List? device = await storage.get(StorageKeys.deviceId);
    final Uint8List? user = await storage.get(StorageKeys.username);
    final Uint8List? sigSeed = await storage.get(StorageKeys.identitySigSeed);
    final Uint8List? dhPriv = await storage.get(StorageKeys.identityDhPriv);
    if (device == null || user == null || sigSeed == null || dhPriv == null) return null;

    final Messenger m = Messenger._(
      storage: storage,
      relay: relay,
      username: utf8.decode(user),
      deviceId: utf8.decode(device),
    );
    await m.store.open();
    final KeyPairBytes sig = await ed25519FromSeed(sigSeed);
    final KeyPairBytes dh = await x25519FromPrivate(dhPriv);
    m.identity = IdentityKeyPair(
      sigSeed: sig.privateKey,
      sigPub: sig.publicKey,
      dhPriv: dh.privateKey,
      dhPub: dh.publicKey,
      bindingSig: await ed25519Sign(
          sig.privateKey, concat(<List<int>>[identityBindingContext, dh.publicKey])),
    );
    final Uint8List? pk = await storage.get(StorageKeys.preKeyState);
    m.prekeys = pk == null
        ? PreKeyStore(m.identity)
        : PreKeyStore.fromStorageJson(
            m.identity, jsonDecode(utf8.decode(pk)) as Map<String, dynamic>);
    relay.restoreTokens(
      account: await m._getString(StorageKeys.accessToken),
      device: await m._getString(StorageKeys.deviceToken),
      refresh: await m._getString(StorageKeys.refreshToken),
    );
    await m._loadState();
    return m;
  }

  Future<void> _loadState() async {
    final Object? settingsJson = await store.get('settings');
    if (settingsJson is Map<String, dynamic>) settings = AppSettings.fromJson(settingsJson);
    final Object? profileJson = await store.get('profile');
    if (profileJson is Map<String, dynamic>) profile = MyProfile.fromJson(profileJson);
    directory.load(await store.get('directory'));

    final Object? contactsJson = await store.get('contacts');
    if (contactsJson is List<Object?>) {
      for (final Map<String, dynamic> c in contactsJson.whereType<Map<String, dynamic>>()) {
        final Contact contact = Contact.fromJson(c);
        contacts[contact.username] = contact;
      }
    }
    final Object? shared = await store.get('profile_shared');
    if (shared is List<Object?>) _profileShared.addAll(shared.whereType<String>());

    final Object? sessionIndex = await store.get('devsessions');
    if (sessionIndex is Map<String, dynamic>) {
      for (final MapEntry<String, dynamic> e in sessionIndex.entries) {
        final List<Session> list = <Session>[];
        for (final String sid in (e.value as List<Object?>).whereType<String>()) {
          final Uint8List? blob = await storage.get(StorageKeys.session(sid));
          if (blob == null) continue;
          try {
            list.add(await Session.load(blob, store.stateKey, sid));
          } on HeloError {
            // Corrupt or tampered session state fails closed: dropped, and a
            // fresh session is established on next contact. Never "repaired".
            logger.security('session_state_rejected', <String, Object?>{'outcome': 'dropped'});
          }
        }
        if (list.isNotEmpty) _sessions[e.key] = list;
      }
    }

    final Object? convs = await store.get('conversations');
    if (convs is List<Object?>) {
      for (final Map<String, dynamic> raw in convs.whereType<Map<String, dynamic>>()) {
        final Conversation c = Conversation.fromMetaJson(raw);
        final Object? history = await store.get('history.${c.id}');
        if (history is List<Object?>) {
          c.messages.addAll(history.whereType<Map<String, dynamic>>().map(ChatMessage.fromJson));
        }
        conversations[c.id] = c;
      }
    }
    final Object? outbox = await store.get('outbox');
    if (outbox is List<Object?>) {
      _outbox.addAll(outbox.whereType<Map<String, dynamic>>().map(_OutboxItem.fromJson));
    }
    _sweepExpired();
  }

  // =====================================================================
  // Lifecycle: the delivery loop
  // =====================================================================

  /// Start the long-poll delivery loop. Idempotent.
  void start() {
    if (_running) return;
    _running = true;
    unawaited(_loop());
  }

  void stop() => _running = false;

  Future<void> _loop() async {
    int backoff = 1;
    while (_running) {
      try {
        // After (re)connecting, the first pass does not wait, so the status
        // turns "online" as soon as the relay answers rather than up to a
        // long-poll later.
        await _receiveOnce(
            waitSeconds: connection.value == ConnectionStatus.online ? 25 : 0);
        if (!_running) break;
        await _afterReceive();
        connection.value = ConnectionStatus.online;
        backoff = 1;
      } on RelayException catch (e) {
        if (e.isAuthFailure) {
          connection.value = ConnectionStatus.signedOut;
          await Future<void>.delayed(const Duration(seconds: 30));
        } else {
          connection.value = ConnectionStatus.offline;
          await Future<void>.delayed(Duration(seconds: backoff));
          backoff = min(backoff * 2, 30);
        }
      } on Object {
        connection.value = ConnectionStatus.offline;
        await Future<void>.delayed(Duration(seconds: backoff));
        backoff = min(backoff * 2, 30);
      }
    }
  }

  /// One full synchronisation pass without waiting (used by tests, pull-to-
  /// refresh, and after reconnecting).
  Future<void> sync() async {
    await _receiveOnce(waitSeconds: 0);
    await _afterReceive();
  }

  Future<void> _afterReceive() async {
    await retryOutbox();
    _sweepExpired();
    await _maintainPreKeys();
  }

  Future<void> dispose() async {
    _running = false;
    await flush();
    _saveTimer?.cancel();
    await _changes.close();
    await _incoming.close();
  }

  // =====================================================================
  // Relay authentication
  // =====================================================================

  /// Run a relay call, renewing tokens once if the relay says they expired.
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
    // device id with the same identity issues a new one (the relay refuses a
    // different identity under an existing id).
    await relay.registerDevice(deviceId: deviceId, identityPublic: identity.public.toJson());
    await _persistTokens();
    logger.info('relay_session_renewed');
  }

  // =====================================================================
  // Prekeys
  // =====================================================================

  Future<void> _publishPreKeys({bool initial = false}) async {
    final (SignedPreKeyPublic, List<OneTimePreKeyPublic>, PqPreKeyPublic?, List<PqPreKeyPublic>)
        batch = await _lock.run(() async {
      if (initial || prekeys.needsSignedPreKeyRotation) {
        await prekeys.rotateSignedPreKey();
        await prekeys.rotatePqLastResort();
      }
      prekeys.pruneExpiredSignedPreKeys();
      final List<OneTimePreKeyPublic> ec = initial || prekeys.needsOneTimeReplenishment
          ? await prekeys.generateOneTimePreKeys(oneTimePreKeyBatch)
          : <OneTimePreKeyPublic>[];
      final List<PqPreKeyPublic> pq = initial || prekeys.needsPqReplenishment
          ? await prekeys.generatePqOneTimePreKeys(pqOneTimePreKeyBatch)
          : <PqPreKeyPublic>[];
      // Persist BEFORE publishing: the relay must never hold a public prekey
      // whose private half a crash could lose.
      await _persistPreKeys();
      return (prekeys.currentSignedPreKey, ec, prekeys.currentPqLastResort, pq);
    });
    await _authed(() => relay.publishPreKeys(
          deviceId: deviceId,
          signedPreKey: batch.$1,
          oneTimePreKeys: batch.$2,
          pqLastResort: batch.$3,
          pqOneTimePreKeys: batch.$4,
        ));
  }

  Future<void> _maintainPreKeys() async {
    if (prekeys.needsSignedPreKeyRotation ||
        prekeys.needsOneTimeReplenishment ||
        prekeys.needsPqReplenishment ||
        !prekeys.hasPqLastResort) {
      await _publishPreKeys();
    }
  }

  // =====================================================================
  // Sending
  // =====================================================================

  String _newId() => newId(defaultRandom.bytes);

  Conversation _conv(String convId) {
    final Conversation? c = conversations[convId];
    if (c == null) throw const MessengerException('Conversation not found.');
    return c;
  }

  /// Open (or return) the direct conversation with [peer]. Verifies the user
  /// exists and has devices; does not send anything.
  Future<Conversation> openDirect(String peer) async {
    final String user = peer.trim().toLowerCase();
    if (user == username) {
      throw const MessengerException('That is you — pick someone else.');
    }
    final String id = Conversation.directId(user);
    final Conversation? existing = conversations[id];
    if (existing != null) return existing;
    final DirectoryLookup found;
    try {
      found = await _authed(() => directory.lookup(user, refresh: true));
    } on RelayException catch (e) {
      if (e.statusCode == 404) throw const MessengerException('No user with that name.');
      rethrow;
    }
    if (found.devices.isEmpty) {
      throw const MessengerException('That user has no active devices.');
    }
    final Conversation c = Conversation.direct(user)
      ..disappearingSeconds = settings.defaultDisappearingSeconds;
    conversations[id] = c;
    contacts.putIfAbsent(user, () => Contact(user));
    _markDirty(c);
    await _persistDirectory();
    _emit();
    return c;
  }

  /// Send a text message (optionally replying to [replyToId]).
  Future<ChatMessage> sendText(String convId, String text, {String? replyToId}) async {
    final String body = text.trim();
    if (body.isEmpty) throw const MessengerException('Nothing to send.');
    if (body.length > maxBodyChars) throw const MessengerException('Message is too long.');
    return _sendMessage(convId, body: body, replyToId: replyToId);
  }

  Future<ChatMessage> _sendMessage(
    String convId, {
    String body = '',
    String? replyToId,
    List<AttachmentRef> attachments = const <AttachmentRef>[],
    bool forwarded = false,
  }) async {
    final Conversation c = _conv(convId);
    _requireCanSend(c);
    ReplyRef? reply;
    if (replyToId != null) {
      final ChatMessage? target = c.byId(replyToId);
      if (target != null && !target.deleted) {
        reply = ReplyRef(
          id: target.id,
          author: target.author,
          snippet: target.body.length > 120 ? '${target.body.substring(0, 120)}…' : target.body,
        );
      }
    }
    final DateTime now = DateTime.now();
    final AppPayload payload = AppPayload(
      id: _newId(),
      timestampMs: now.millisecondsSinceEpoch,
      kind: PayloadKind.msg,
      conv: c.isGroup ? ConvRef.group(c.group!.gid) : const ConvRef.direct(),
      body: body,
      reply: reply,
      attachments: attachments,
      forwarded: forwarded,
      expireSeconds: c.disappearingSeconds > 0 ? c.disappearingSeconds : null,
    );
    final ChatMessage message = ChatMessage(
      id: payload.id,
      convId: c.id,
      author: username,
      outgoing: true,
      sentAt: now,
      body: body,
      reply: reply,
      attachments: attachments,
      forwarded: forwarded,
      status: MessageStatus.pending,
      expiresAt: c.disappearingSeconds > 0 ? now.add(Duration(seconds: c.disappearingSeconds)) : null,
    );
    _addMessage(c, message);
    _emit();
    await _shareProfileIfNeeded(c);
    await _send(c, payload, message: message);
    return message;
  }

  void _requireCanSend(Conversation c) {
    if (c.isGroup && c.group!.removed) {
      throw const MessengerException('You are no longer a member of this group.');
    }
    if (!c.isGroup && (contacts[c.peer]?.blocked ?? false)) {
      throw const MessengerException('Unblock this contact to send messages.');
    }
  }

  /// Encrypt [payload] for every active device of the conversation's other
  /// members and hand the envelopes to the relay.
  ///
  /// [transient] payloads (typing) are best-effort: not queued for retry.
  Future<void> _send(
    Conversation c,
    AppPayload payload, {
    ChatMessage? message,
    bool transient = false,
    List<String>? users,
  }) async {
    final List<String> targets = users ?? c.recipients(username);
    final List<DevicePin> devices = <DevicePin>[];
    final List<String> problems = <String>[];
    final Map<String, FetchedBundle> bundles = <String, FetchedBundle>{};
    try {
      for (final String u in targets) {
        try {
          final DirectoryLookup found = await _authed(() => directory.lookup(u));
          devices.addAll(found.devices);
          if (found.added.isNotEmpty) {
            _systemNotice(c, '${_label(u)} added a new device. It is not verified.');
            await _persistDirectory();
          }
          if (found.conflicts.isNotEmpty) {
            // A device's key never changes legitimately (a reset registers a
            // NEW device id), so a changed key means the relay is misbehaving:
            // the device stays blocked; there is no "accept" path to abuse.
            _systemNotice(c, 'The relay reported a different key for one of ${_label(u)}\'s '
                'devices. Keys never change for a device, so nothing more will be sent to it. '
                'Compare safety numbers with ${_label(u)} in person.');
            await _persistDirectory();
          }
        } on RelayException catch (e) {
          if (!e.isPermanent) rethrow;
          problems.add('${_label(u)} is not reachable.');
        }
      }
      // Fetch prekey bundles for devices with no session yet — network, so
      // OUTSIDE the lock.
      for (final DevicePin d in devices) {
        if (_sessions[d.deviceId]?.isNotEmpty ?? false) continue;
        try {
          bundles[d.deviceId] = await _bundleFetches.putIfAbsent(
              d.deviceId,
              // Block body on purpose: `=> remove(..)` would return this very
              // future to whenComplete, which then waits on itself forever.
              () => _authed(() => relay.fetchBundle(d.deviceId)).whenComplete(() {
                    _bundleFetches.remove(d.deviceId);
                  }));
        } on RelayException catch (e) {
          if (!e.isPermanent) rethrow;
        }
      }
    } on Object {
      // Nothing was encrypted yet, so nothing can be reused: the message is
      // marked failed and can be retried, which encrypts it afresh.
      if (message != null) {
        message
          ..status = MessageStatus.failed
          ..failureReason = 'Could not reach the relay.';
        _markDirty(c);
        _emit();
      }
      return;
    }

    final Uint8List plaintext = payload.encode(_padding);
    final Map<String, Map<String, dynamic>> envelopes =
        await _lock.run(() => _encryptFor(devices, bundles, plaintext, c, problems));

    if (envelopes.isEmpty) {
      if (message != null) {
        message
          ..status = MessageStatus.failed
          ..failureReason = problems.isEmpty
              ? 'No device could receive this message.'
              : problems.join(' ');
        _markDirty(c);
        _emit();
      }
      return;
    }
    final _OutboxItem item = _OutboxItem(payload.id, c.id, envelopes);
    if (!transient) {
      _outbox.add(item);
      await _persistOutbox();
    }
    try {
      await _deliver(item, transient: transient);
    } on Object {
      // Offline: the envelopes stay in the persisted outbox and are re-sent
      // (unchanged) by the delivery loop. The message shows as pending.
    }
  }

  /// Retry a FAILED message. Failed means nothing reached the relay, so it is
  /// encrypted afresh — a new ratchet step, not a reused key.
  Future<void> retryMessage(String convId, String messageId) async {
    final Conversation c = _conv(convId);
    final ChatMessage? m = c.byId(messageId);
    if (m == null || !m.outgoing || m.status != MessageStatus.failed) return;
    if (_outbox.any((_OutboxItem i) => i.payloadId == messageId)) return;
    m
      ..status = MessageStatus.pending
      ..failureReason = null;
    _emit();
    await _send(c, AppPayload(
      id: m.id,
      timestampMs: m.sentAt.millisecondsSinceEpoch,
      kind: PayloadKind.msg,
      conv: c.isGroup ? ConvRef.group(c.group!.gid) : const ConvRef.direct(),
      body: m.body,
      reply: m.reply,
      attachments: m.attachments,
      forwarded: m.forwarded,
      expireSeconds: c.disappearingSeconds > 0 ? c.disappearingSeconds : null,
    ), message: m);
  }

  /// Under the lock: create missing sessions, encrypt once per device, and
  /// persist every advanced session BEFORE returning the ciphertexts.
  Future<Map<String, Map<String, dynamic>>> _encryptFor(
    List<DevicePin> devices,
    Map<String, FetchedBundle> bundles,
    Uint8List plaintext,
    Conversation c,
    List<String> problems,
  ) async {
    final Map<String, Map<String, dynamic>> out = <String, Map<String, dynamic>>{};
    final List<Session> touched = <Session>[];
    for (final DevicePin d in devices) {
      Session? session = _sessions[d.deviceId]?.first;
      if (session == null) {
        final FetchedBundle? fetched = bundles[d.deviceId];
        if (fetched == null) continue;
        // The bundle's identity must be the identity the directory pinned for
        // this device; a relay that serves a different key gets nothing.
        if (!directory.matchesPin(d.deviceId, fetched.bundle.identity)) {
          problems.add('A device of ${_label(d.username)} presented an unexpected key.');
          continue;
        }
        final bool pq = fetched.bundle.pqPreKey != null;
        if (!pq && !settings.allowClassical) {
          problems.add('${_label(d.username)}\'s app does not offer post-quantum keys; '
              'classical sessions are disabled in Settings.');
          continue;
        }
        try {
          session = await startAsInitiator(
            identity: identity,
            localDeviceId: deviceId,
            bundle: fetched.bundle,
            kex: pq ? const Pqxdh() : const ClassicalX3dh(),
          );
        } on HeloError catch (e) {
          problems.add('Could not establish a secure session with a device of '
              '${_label(d.username)} (${e.runtimeType}).');
          continue;
        }
        if (!pq) {
          _systemNotice(c, 'Session with ${_label(d.username)} uses CLASSICAL X3DH '
              '(no post-quantum protection), because you allowed classical contacts.');
        }
        _sessions[d.deviceId] = <Session>[session];
      }
      final Envelope env = await session.encryptMessage(plaintext);
      out[d.deviceId] = env.toJson();
      touched.add(session);
    }
    // The advanced ratchets hit storage before any ciphertext leaves.
    for (final Session s in touched) {
      await _persistSessionState(s);
    }
    if (touched.isNotEmpty) await _persistSessionIndex();
    return out;
  }

  /// Hand an outbox item to the relay. Accepted and permanently refused
  /// envelopes leave the outbox; transient failures stay for retry.
  Future<void> _deliver(_OutboxItem item, {bool transient = false}) async {
    item.attempts += 1;
    final List<(String, Envelope)> batch = item.envelopes.entries
        .map((MapEntry<String, Map<String, dynamic>> e) =>
            (e.key, Envelope.fromJson(e.value)))
        .toList();
    try {
      for (int i = 0; i < batch.length; i += 100) {
        final List<SendResult> results = await _authed(
            () => relay.sendBatch(batch.sublist(i, min(i + 100, batch.length))));
        for (final SendResult r in results) {
          if (r.accepted) item.accepted += 1;
          if (r.accepted || r.permanentFailure) item.envelopes.remove(r.recipientDeviceId);
        }
      }
    } on Object catch (_) {
      if (transient) return;
      _updateStatusFromOutbox(item);
      await _persistOutbox();
      rethrow;
    }
    if (transient) return;
    if (item.envelopes.isEmpty) _outbox.remove(item);
    _updateStatusFromOutbox(item);
    await _persistOutbox();
  }

  void _updateStatusFromOutbox(_OutboxItem item) {
    final ChatMessage? m = conversations[item.convId]?.byId(item.payloadId);
    if (m == null || !m.outgoing) return;
    if (item.envelopes.isNotEmpty) {
      m.status = MessageStatus.pending;
    } else if (item.accepted == 0) {
      m
        ..status = MessageStatus.failed
        ..failureReason ??= 'The relay refused this message for every recipient device.';
    } else if (m.status == MessageStatus.pending || m.status == MessageStatus.failed) {
      m.status = MessageStatus.sent;
      _recomputeStatus(conversations[item.convId]!, m);
    }
    _markDirty(conversations[item.convId]!);
    _emit();
  }

  /// Re-send queued envelopes (the SAME ciphertext — never re-encrypted).
  Future<void> retryOutbox() async {
    for (final _OutboxItem item in List<_OutboxItem>.of(_outbox)) {
      try {
        await _deliver(item);
      } on Object {
        return; // still offline; try again on the next pass
      }
    }
  }

  // =====================================================================
  // Receiving
  // =====================================================================

  Future<void> _receiveOnce({required int waitSeconds}) async {
    final List<QueuedMessage> items =
        await _authed(() => relay.fetchMessages(waitSeconds: waitSeconds));
    if (items.isEmpty) return;
    final List<String> ack = <String>[];
    final Map<String, Map<String, List<String>>> delivered =
        <String, Map<String, List<String>>>{};

    for (final QueuedMessage item in items) {
      if (item.messageId.isNotEmpty) ack.add(item.messageId);
      final Envelope? env = item.envelope;
      final String? sender = item.senderUsername;
      if (env == null || sender == null) continue;
      try {
        final AppPayload? payload =
            await _lock.run(() => _open(item.senderDeviceId, sender, env));
        if (payload == null) continue;
        await _dispatch(sender, payload, delivered);
      } on HeloError catch (e) {
        logger.security('message_rejected', <String, Object?>{
          'outcome': 'rejected',
          'error_class': e.runtimeType.toString(),
        });
      } on MessengerException {
        continue;
      }
    }
    // History hits storage before the relay is told to delete the ciphertext.
    await flush();
    await _authed(() => relay.acknowledge(ack));
    await _sendDeliveryReceipts(delivered);
    _emit();
  }

  /// Decrypt one envelope. Returns null if the message must be dropped.
  Future<AppPayload?> _open(String senderDevice, String sender, Envelope env) async {
    if (sender == username) return null; // own-device sync is not implemented
    if (contacts[sender]?.blocked ?? false) return null;

    // Bind the device to its owner and identity. A device the relay
    // attributes to a different user than before is dropped.
    DevicePin? pin = directory.pin(senderDevice);
    if (pin == null) {
      await directory.lookup(sender, refresh: true);
      pin = directory.pin(senderDevice);
      if (pin == null) return null;
      await _persistDirectory();
    }
    if (pin.username != sender || pin.conflict) {
      logger.security('sender_binding_mismatch', <String, Object?>{'outcome': 'dropped'});
      return null;
    }

    final List<Session> sessions = _sessions[senderDevice] ?? <Session>[];
    Object? lastError;
    for (int i = 0; i < sessions.length; i++) {
      try {
        final Uint8List pt = await sessions[i].decryptMessage(env);
        if (i > 0) sessions.insert(0, sessions.removeAt(i)); // promote
        await _persistSessionState(sessions.first);
        if (i > 0) await _persistSessionIndex();
        return AppPayload.decode(pt);
      } on AuthenticationError catch (e) {
        lastError = e;
      } on IdentityChangedError catch (e) {
        lastError = e;
      }
    }

    // A prekey message: a new session (first contact, or the peer
    // re-initiated, e.g. both sides started at once).
    final InitialMessageHeader? header = env.x3dh;
    if (header == null) {
      if (lastError is HeloError) throw lastError;
      throw const UnknownSessionError('no session with sender');
    }
    if (!directory.matchesPin(senderDevice, header.initiatorIdentity)) {
      logger.security('initiator_identity_mismatch', <String, Object?>{'outcome': 'dropped'});
      return null;
    }
    final Session fresh;
    try {
      fresh = await startAsResponder(
        identity: identity,
        localDeviceId: deviceId,
        prekeys: prekeys,
        envelope: env,
        acceptClassical: settings.allowClassical,
      );
    } finally {
      // Whatever happened, a consumed one-time prekey must stay consumed.
      await _persistPreKeys();
    }
    final Uint8List pt = await fresh.decryptMessage(env);
    // Adopted only after the first message authenticates.
    sessions.insert(0, fresh);
    while (sessions.length > _maxArchivedSessions) {
      final Session dropped = sessions.removeLast();
      await storage.delete(StorageKeys.session(dropped.sessionId));
    }
    _sessions[senderDevice] = sessions;
    await _persistSessionState(fresh);
    await _persistSessionIndex();
    return AppPayload.decode(pt);
  }

  Future<void> _dispatch(
    String sender,
    AppPayload p,
    Map<String, Map<String, List<String>>> delivered,
  ) async {
    if (p.kind == PayloadKind.profile) {
      final Contact c = contacts.putIfAbsent(sender, () => Contact(sender));
      c.displayName = p.displayName;
      c.avatar = p.avatar;
      await _persistContacts();
      return;
    }
    if (p.kind == PayloadKind.group) {
      await _applyGroup(sender, p);
      return;
    }

    final Conversation? c = _conversationFor(sender, p.conv!, create: p.kind == PayloadKind.msg);
    if (c == null) return;
    if (c.isGroup && (c.group!.removed || !c.group!.members.contains(sender))) {
      return; // not a member: ignore everything they send to this group
    }

    switch (p.kind) {
      case PayloadKind.msg:
        if (_seenPayloads.contains(p.id) || c.byId(p.id) != null) return; // duplicate
        _seenPayloads.add(p.id);
        final DateTime now = DateTime.now();
        final ChatMessage m = ChatMessage(
          id: p.id,
          convId: c.id,
          author: sender,
          outgoing: false,
          sentAt: DateTime.fromMillisecondsSinceEpoch(p.timestampMs),
          body: p.body ?? '',
          reply: p.reply,
          attachments: p.attachments,
          forwarded: p.forwarded,
          expiresAt: p.expireSeconds == null ? null : now.add(Duration(seconds: p.expireSeconds!)),
        );
        _addMessage(c, m);
        c.typing.remove(sender);
        if (activeConversationId != c.id) c.unread += 1;
        delivered.putIfAbsent(sender, () => <String, List<String>>{})
            .putIfAbsent(c.id, () => <String>[]).add(p.id);
        if (!c.muted) _incoming.add(IncomingNotice(c, m));
        if (activeConversationId == c.id) unawaited(markRead(c.id));
      case PayloadKind.react:
        final ChatMessage? t = c.byId(p.target!);
        if (t == null || t.deleted) return;
        if (p.emoji!.isEmpty) {
          t.reactions.remove(sender);
        } else {
          t.reactions[sender] = p.emoji!;
        }
        _markDirty(c);
      case PayloadKind.edit:
        final ChatMessage? t = c.byId(p.target!);
        // Only the AUTHOR may edit — checked against the authenticated sender.
        if (t == null || t.deleted || t.author != sender || t.system) return;
        t
          ..body = p.body!
          ..edited = true;
        _markDirty(c);
      case PayloadKind.del:
        final ChatMessage? t = c.byId(p.target!);
        if (t == null || t.author != sender || t.system) return;
        _tombstone(t);
        _markDirty(c);
      case PayloadKind.rcpt:
        for (final String id in p.targets) {
          final ChatMessage? t = c.byId(id);
          if (t == null || !t.outgoing) continue;
          t.deliveredTo.add(sender);
          if (p.receiptKind == ReceiptKind.read) t.readBy.add(sender);
          _recomputeStatus(c, t);
        }
        _markDirty(c);
      case PayloadKind.typing:
        if (p.typingOn ?? false) {
          c.typing[sender] = DateTime.now().add(_typingLifetime);
        } else {
          c.typing.remove(sender);
        }
      case PayloadKind.timer:
        c.disappearingSeconds = p.timerSeconds!;
        _systemNotice(c, '${_label(sender)} ${_timerText(p.timerSeconds!)}');
        _markDirty(c);
      case PayloadKind.profile:
      case PayloadKind.group:
        break; // handled above
    }
  }

  Conversation? _conversationFor(String sender, ConvRef ref, {required bool create}) {
    if (ref.isGroup) return conversations[Conversation.groupId(ref.gid!)];
    final String id = Conversation.directId(sender);
    Conversation? c = conversations[id];
    if (c == null && create) {
      c = Conversation.direct(sender);
      conversations[id] = c;
      contacts.putIfAbsent(sender, () => Contact(sender));
      unawaited(_persistContacts());
    }
    return c;
  }

  void _recomputeStatus(Conversation c, ChatMessage m) {
    if (m.status == MessageStatus.pending || m.status == MessageStatus.failed) return;
    final List<String> audience = c.recipients(username);
    if (audience.isEmpty) return;
    if (audience.every(m.readBy.contains)) {
      m.status = MessageStatus.read;
    } else if (audience.every(m.deliveredTo.contains)) {
      m.status = MessageStatus.delivered;
    } else {
      m.status = MessageStatus.sent;
    }
  }

  // =====================================================================
  // Receipts and typing
  // =====================================================================

  /// "Delivered" means a recipient DEVICE decrypted the message — sent back
  /// end to end encrypted, so the relay cannot fake or read it.
  Future<void> _sendDeliveryReceipts(Map<String, Map<String, List<String>>> delivered) async {
    for (final MapEntry<String, Map<String, List<String>>> byUser in delivered.entries) {
      for (final MapEntry<String, List<String>> byConv in byUser.value.entries) {
        final Conversation? c = conversations[byConv.key];
        if (c == null) continue;
        await _sendReceipt(c, byUser.key, ReceiptKind.delivered, byConv.value);
      }
    }
  }

  Future<void> _sendReceipt(
      Conversation c, String toUser, ReceiptKind kind, List<String> ids) async {
    if (ids.isEmpty) return;
    for (int i = 0; i < ids.length; i += maxReceiptTargets) {
      final AppPayload p = AppPayload(
        id: _newId(),
        timestampMs: DateTime.now().millisecondsSinceEpoch,
        kind: PayloadKind.rcpt,
        conv: c.isGroup ? ConvRef.group(c.group!.gid) : const ConvRef.direct(),
        receiptKind: kind,
        targets: ids.sublist(i, min(i + maxReceiptTargets, ids.length)),
      );
      try {
        await _send(c, p, transient: true, users: <String>[toUser]);
      } on Object {
        // Receipts are best-effort; the message itself is already stored.
      }
    }
  }

  /// Mark a conversation read. Sends read receipts only if the setting is on.
  Future<void> markRead(String convId) async {
    final Conversation? c = conversations[convId];
    if (c == null) return;
    final Map<String, List<String>> unreadByAuthor = <String, List<String>>{};
    for (final ChatMessage m in c.messages) {
      if (m.outgoing || m.system || m.deleted || m.readBy.contains(username)) continue;
      m.readBy.add(username);
      unreadByAuthor.putIfAbsent(m.author, () => <String>[]).add(m.id);
    }
    c.unread = 0;
    _markDirty(c);
    _emit();
    if (!settings.readReceipts) return;
    for (final MapEntry<String, List<String>> e in unreadByAuthor.entries) {
      await _sendReceipt(c, e.key, ReceiptKind.read, e.value);
    }
  }

  /// Report local typing activity. Throttled; sends nothing if the user
  /// turned typing indicators off.
  Future<void> setTyping(String convId, bool on) async {
    if (!settings.typingIndicators) return;
    final Conversation? c = conversations[convId];
    if (c == null || (c.isGroup && c.group!.removed)) return;
    final DateTime now = DateTime.now();
    final DateTime? last = _typingSentAt[convId];
    if (on && last != null && now.difference(last) < const Duration(seconds: 4)) return;
    if (!on && last == null) return;
    if (on) {
      _typingSentAt[convId] = now;
    } else {
      _typingSentAt.remove(convId);
    }
    final AppPayload p = AppPayload(
      id: _newId(),
      timestampMs: now.millisecondsSinceEpoch,
      kind: PayloadKind.typing,
      conv: c.isGroup ? ConvRef.group(c.group!.gid) : const ConvRef.direct(),
      typingOn: on,
    );
    try {
      await _send(c, p, transient: true);
    } on Object {
      // Typing indicators are best-effort.
    }
  }

  /// Usernames currently typing in [convId] (expired entries are dropped).
  List<String> typingIn(String convId) {
    final Conversation? c = conversations[convId];
    if (c == null) return const <String>[];
    final DateTime now = DateTime.now();
    c.typing.removeWhere((String _, DateTime until) => until.isBefore(now));
    return c.typing.keys.toList();
  }

  // =====================================================================
  // Reactions, edits, deletes, forwards
  // =====================================================================

  Future<void> react(String convId, String messageId, String emoji) async {
    final Conversation c = _conv(convId);
    final ChatMessage? t = c.byId(messageId);
    if (t == null || t.deleted || t.system) return;
    final bool remove = t.reactions[username] == emoji;
    if (remove) {
      t.reactions.remove(username);
    } else {
      t.reactions[username] = emoji;
    }
    _markDirty(c);
    _emit();
    await _send(c, AppPayload(
      id: _newId(),
      timestampMs: DateTime.now().millisecondsSinceEpoch,
      kind: PayloadKind.react,
      conv: c.isGroup ? ConvRef.group(c.group!.gid) : const ConvRef.direct(),
      target: messageId,
      emoji: remove ? '' : emoji,
    ));
  }

  bool canEdit(ChatMessage m) =>
      m.outgoing && !m.deleted && !m.system && m.attachments.isEmpty &&
      DateTime.now().difference(m.sentAt) < _editWindow;

  bool canDeleteForEveryone(ChatMessage m) =>
      m.outgoing && !m.deleted && !m.system && DateTime.now().difference(m.sentAt) < _deleteWindow;

  Future<void> edit(String convId, String messageId, String newBody) async {
    final Conversation c = _conv(convId);
    final ChatMessage? t = c.byId(messageId);
    final String body = newBody.trim();
    if (t == null || !canEdit(t)) throw const MessengerException('This message can no longer be edited.');
    if (body.isEmpty || body.length > maxBodyChars) throw const MessengerException('Invalid message.');
    t
      ..body = body
      ..edited = true;
    _markDirty(c);
    _emit();
    await _send(c, AppPayload(
      id: _newId(),
      timestampMs: DateTime.now().millisecondsSinceEpoch,
      kind: PayloadKind.edit,
      conv: c.isGroup ? ConvRef.group(c.group!.gid) : const ConvRef.direct(),
      target: messageId,
      body: body,
    ));
  }

  Future<void> deleteForEveryone(String convId, String messageId) async {
    final Conversation c = _conv(convId);
    final ChatMessage? t = c.byId(messageId);
    if (t == null || !canDeleteForEveryone(t)) {
      throw const MessengerException('This message can no longer be deleted for everyone.');
    }
    _tombstone(t);
    _markDirty(c);
    _emit();
    await _send(c, AppPayload(
      id: _newId(),
      timestampMs: DateTime.now().millisecondsSinceEpoch,
      kind: PayloadKind.del,
      conv: c.isGroup ? ConvRef.group(c.group!.gid) : const ConvRef.direct(),
      target: messageId,
    ));
  }

  /// Remove from this device only. Recipients keep their copies.
  void deleteForMe(String convId, String messageId) {
    final Conversation c = _conv(convId);
    c.messages.removeWhere((ChatMessage m) => m.id == messageId);
    _markDirty(c);
    _emit();
  }

  void _tombstone(ChatMessage m) {
    for (final AttachmentRef a in m.attachments) {
      _attachmentCache.remove(a.id);
    }
    m
      ..deleted = true
      ..body = ''
      ..attachments = const <AttachmentRef>[]
      ..reactions.clear();
  }

  /// Forward a message's text and attachments into another conversation.
  /// Attachments are re-uploaded for the new recipients (the relay only
  /// serves a blob to the devices it was uploaded for).
  Future<void> forward(String fromConvId, String messageId, String toConvId) async {
    final ChatMessage? m = _conv(fromConvId).byId(messageId);
    if (m == null || m.deleted || m.system) return;
    final List<AttachmentRef> refs = <AttachmentRef>[];
    for (final AttachmentRef a in m.attachments) {
      final Uint8List bytes = await loadAttachment(a);
      refs.add(await _uploadAttachment(_conv(toConvId), bytes, a.name, a.mime,
          voice: a.voice, durationMs: a.durationMs));
    }
    await _sendMessage(toConvId, body: m.body, attachments: refs, forwarded: true);
  }

  // =====================================================================
  // Attachments
  // =====================================================================

  Future<ChatMessage> sendAttachment(
    String convId,
    Uint8List bytes, {
    required String name,
    required String mime,
    String caption = '',
    bool voice = false,
    int? durationMs,
  }) async {
    if (bytes.length > maxAttachmentBytes) {
      throw const MessengerException('File is too large (24 MB maximum).');
    }
    if (voice && !mime.startsWith('audio/')) {
      throw const MessengerException('A voice message must be audio.');
    }
    final Conversation c = _conv(convId);
    _requireCanSend(c);
    final AttachmentRef ref = await _uploadAttachment(c, bytes, name, mime,
        voice: voice, durationMs: durationMs);
    return _sendMessage(convId, body: caption.trim(), attachments: <AttachmentRef>[ref]);
  }

  /// Encrypt locally under a fresh key, upload ciphertext only. The key goes
  /// into the end-to-end encrypted message, never to the relay.
  Future<AttachmentRef> _uploadAttachment(
      Conversation c, Uint8List bytes, String name, String mime,
      {bool voice = false, int? durationMs}) async {
    final List<String> recipients = <String>[deviceId];
    for (final String u in c.recipients(username)) {
      final DirectoryLookup found = await _authed(() => directory.lookup(u));
      recipients.addAll(found.devices.map((DevicePin d) => d.deviceId));
    }
    final Uint8List key = generateAttachmentKey();
    final Uint8List ct = await encryptAttachment(key, bytes);
    final String id = await _authed(() => relay.uploadAttachment(ct, recipients));
    _attachmentCache[id] = bytes;
    return AttachmentRef(
      id: id,
      key: key,
      digest: await attachmentDigest(ct),
      size: bytes.length,
      mime: mime.isEmpty ? 'application/octet-stream' : mime,
      name: name.isEmpty ? 'file' : name,
      chunkSize: attachmentChunkSize,
      voice: voice,
      durationMs: durationMs,
    );
  }

  Uint8List? cachedAttachment(String id) => _attachmentCache[id];

  /// Download, verify the digest, decrypt and authenticate every chunk.
  Future<Uint8List> loadAttachment(AttachmentRef ref) async {
    final Uint8List? cached = _attachmentCache[ref.id];
    if (cached != null) return cached;
    final Uint8List ct = await _authed(() => relay.downloadAttachment(ref.id));
    await verifyAttachmentDigest(ct, ref.digest);
    final Uint8List plain = await decryptAttachment(ref.key, ct, ref.chunkSize);
    if (plain.length != ref.size) {
      throw const AuthenticationError('attachment size does not match the message');
    }
    _attachmentCache[ref.id] = plain;
    return plain;
  }

  // =====================================================================
  // Groups
  // =====================================================================

  Future<Conversation> createGroup(String name, List<String> members, {Uint8List? avatar}) async {
    final String title = name.trim();
    if (title.isEmpty || title.length > maxNameChars) {
      throw const MessengerException('Group name must be 1–64 characters.');
    }
    final List<String> others = members
        .map((String u) => u.trim().toLowerCase())
        .where((String u) => u.isNotEmpty && u != username)
        .toSet()
        .toList();
    if (others.isEmpty) throw const MessengerException('Add at least one member.');
    for (final String u in others) {
      final DirectoryLookup found = await _authed(() => directory.lookup(u, refresh: true));
      if (found.devices.isEmpty) throw MessengerException('$u has no active devices.');
    }
    final GroupState state = GroupState(
      gid: _newId(),
      version: 1,
      name: title,
      members: <String>[username, ...others],
      admins: <String>[username],
      avatar: avatar,
    );
    final Conversation c = Conversation.group(state);
    conversations[c.id] = c;
    _systemNotice(c, 'You created the group "$title".');
    _markDirty(c);
    _emit();
    await _sendGroup(c, GroupOp.create, state.toSnapshot(), to: others);
    return c;
  }

  void _requireAdmin(Conversation c) {
    if (!c.isGroup || c.group!.removed || !c.group!.admins.contains(username)) {
      throw const MessengerException('Only group admins can do that.');
    }
  }

  Future<void> _changeGroup(Conversation c, GroupSnapshot next, {List<String> alsoNotify = const <String>[]}) async {
    final GroupState current = c.group!;
    final List<String> audience = <String>{
      ...current.members,
      ...next.members,
      ...alsoNotify,
    }.where((String u) => u != username).toList();
    final GroupChange change =
        applyGroupChange(current: current, op: GroupOp.update, proposed: next, sender: username, me: username);
    if (!change.accepted) throw MessengerException(change.reason ?? 'Group change refused.');
    _applyLocalGroup(c, change, username);
    await _sendGroup(c, GroupOp.update, next, to: audience);
  }

  GroupSnapshot _next(GroupState g, {String? name, List<String>? members, List<String>? admins, Uint8List? avatar, bool clearAvatar = false}) =>
      GroupSnapshot(
        gid: g.gid,
        version: g.version + 1,
        name: name ?? g.name,
        members: members ?? List<String>.of(g.members),
        admins: admins ?? List<String>.of(g.admins),
        avatar: clearAvatar ? null : (avatar ?? g.avatar),
      );

  Future<void> addMembers(String convId, List<String> users) async {
    final Conversation c = _conv(convId);
    _requireAdmin(c);
    final List<String> add = users
        .map((String u) => u.trim().toLowerCase())
        .where((String u) => u.isNotEmpty && !c.group!.members.contains(u))
        .toSet()
        .toList();
    for (final String u in add) {
      final DirectoryLookup found = await _authed(() => directory.lookup(u, refresh: true));
      if (found.devices.isEmpty) throw MessengerException('$u has no active devices.');
    }
    if (add.isEmpty) return;
    await _changeGroup(c, _next(c.group!, members: <String>[...c.group!.members, ...add]));
  }

  Future<void> removeMember(String convId, String user) async {
    final Conversation c = _conv(convId);
    _requireAdmin(c);
    if (user == username) throw const MessengerException('Use "Leave group" instead.');
    final GroupState g = c.group!;
    await _changeGroup(
      c,
      _next(g,
          members: g.members.where((String u) => u != user).toList(),
          admins: g.admins.where((String u) => u != user).toList()),
      // The removed member is told (so their client stops sending), and is
      // then never encrypted to again.
      alsoNotify: <String>[user],
    );
  }

  Future<void> setAdmin(String convId, String user, bool admin) async {
    final Conversation c = _conv(convId);
    _requireAdmin(c);
    final GroupState g = c.group!;
    if (!g.members.contains(user)) return;
    final List<String> admins = admin
        ? <String>{...g.admins, user}.toList()
        : g.admins.where((String u) => u != user).toList();
    if (admins.isEmpty) throw const MessengerException('A group needs at least one admin.');
    await _changeGroup(c, _next(g, admins: admins));
  }

  Future<void> renameGroup(String convId, String name) async {
    final Conversation c = _conv(convId);
    _requireAdmin(c);
    final String title = name.trim();
    if (title.isEmpty || title.length > maxNameChars) {
      throw const MessengerException('Group name must be 1–64 characters.');
    }
    await _changeGroup(c, _next(c.group!, name: title));
  }

  Future<void> setGroupAvatar(String convId, Uint8List? avatar) async {
    final Conversation c = _conv(convId);
    _requireAdmin(c);
    if (avatar != null && avatar.length > maxInlineImageBytes) {
      throw const MessengerException('Image is too large.');
    }
    await _changeGroup(c, _next(c.group!, avatar: avatar, clearAvatar: avatar == null));
  }

  Future<void> leaveGroup(String convId) async {
    final Conversation c = _conv(convId);
    if (!c.isGroup || c.group!.removed) return;
    final GroupSnapshot next = leaveSnapshot(c.group!, username);
    final List<String> audience = c.group!.members.where((String u) => u != username).toList();
    c.group!
      ..version = next.version
      ..members = next.members
      ..admins = next.admins
      ..removed = true;
    _systemNotice(c, 'You left the group.');
    _markDirty(c);
    _emit();
    await _sendGroup(c, GroupOp.leave, next, to: audience);
  }

  Future<void> _sendGroup(Conversation c, GroupOp op, GroupSnapshot snapshot,
      {required List<String> to}) async {
    if (to.isEmpty) return;
    await _send(c, AppPayload(
      id: _newId(),
      timestampMs: DateTime.now().millisecondsSinceEpoch,
      kind: PayloadKind.group,
      conv: ConvRef.group(snapshot.gid),
      groupOp: op,
      group: snapshot,
    ), users: to);
  }

  Future<void> _applyGroup(String sender, AppPayload p) async {
    final String id = Conversation.groupId(p.group!.gid);
    final Conversation? existing = conversations[id];
    final GroupChange change = applyGroupChange(
      current: existing?.group,
      op: p.groupOp!,
      proposed: p.group!,
      sender: sender,
      me: username,
    );
    if (!change.accepted) {
      logger.security('group_change_rejected', <String, Object?>{
        'outcome': change.decision.name,
      });
      return;
    }
    Conversation c;
    if (existing == null) {
      c = Conversation.group(change.state!);
      conversations[id] = c;
      _systemNotice(c, '${_label(sender)} added you to "${change.state!.name}".');
    } else {
      c = existing;
      _applyLocalGroup(c, change, sender);
    }
    _markDirty(c);
  }

  void _applyLocalGroup(Conversation c, GroupChange change, String by) {
    final GroupState g = c.group!;
    final GroupState next = change.state!;
    final String who = by == username ? 'You' : _label(by);
    if (next.name != g.name) _systemNotice(c, '$who renamed the group to "${next.name}".');
    for (final String u in change.added) {
      _systemNotice(c, '$who added ${_label(u)}.');
    }
    for (final String u in change.removed) {
      _systemNotice(c, u == by ? '${_label(u)} left.' : '$who removed ${_label(u)}.');
    }
    for (final String u in next.admins.where((String u) => !g.admins.contains(u))) {
      if (!change.added.contains(u)) _systemNotice(c, '${_label(u)} is now an admin.');
    }
    if (change.selfRemoved && by != username) _systemNotice(c, '$who removed you from the group.');
    g
      ..version = next.version
      ..name = next.name
      ..members = next.members
      ..admins = next.admins
      ..avatar = next.avatar
      ..removed = change.selfRemoved || (by == username && g.removed);
    _emit();
  }

  // =====================================================================
  // Disappearing messages
  // =====================================================================

  Future<void> setDisappearing(String convId, int seconds) async {
    final Conversation c = _conv(convId);
    _requireCanSend(c);
    c.disappearingSeconds = seconds;
    _systemNotice(c, 'You ${_timerText(seconds)}');
    _markDirty(c);
    _emit();
    await _send(c, AppPayload(
      id: _newId(),
      timestampMs: DateTime.now().millisecondsSinceEpoch,
      kind: PayloadKind.timer,
      conv: c.isGroup ? ConvRef.group(c.group!.gid) : const ConvRef.direct(),
      timerSeconds: seconds,
    ));
  }

  static String _timerText(int seconds) => seconds == 0
      ? 'turned off disappearing messages.'
      : 'set messages to disappear after ${_duration(seconds)}.';

  static String _duration(int s) {
    if (s % 86400 == 0) return '${s ~/ 86400} day${s == 86400 ? '' : 's'}';
    if (s % 3600 == 0) return '${s ~/ 3600} hour${s == 3600 ? '' : 's'}';
    if (s % 60 == 0) return '${s ~/ 60} minute${s == 60 ? '' : 's'}';
    return '$s seconds';
  }

  /// Delete expired messages from memory and storage. This removes them from
  /// THIS device; it cannot reach screenshots or copies.
  void _sweepExpired() {
    final DateTime now = DateTime.now();
    for (final Conversation c in conversations.values) {
      final int before = c.messages.length;
      c.messages.removeWhere((ChatMessage m) => m.expiresAt != null && m.expiresAt!.isBefore(now));
      if (c.messages.length != before) {
        _markDirty(c);
        _emit();
      }
    }
  }

  // =====================================================================
  // Conversation management, contacts, profile, settings
  // =====================================================================

  List<Conversation> sortedConversations({bool archived = false}) {
    final List<Conversation> list = conversations.values
        .where((Conversation c) => c.archived == archived)
        .toList()
      ..sort((Conversation a, Conversation b) {
        if (a.pinned != b.pinned) return a.pinned ? -1 : 1;
        return b.lastActivity.compareTo(a.lastActivity);
      });
    return list;
  }

  void setPinned(String convId, bool v) => _flag(convId, (Conversation c) => c.pinned = v);
  void setArchived(String convId, bool v) => _flag(convId, (Conversation c) => c.archived = v);
  void setMuted(String convId, bool v) => _flag(convId, (Conversation c) => c.muted = v);

  void _flag(String convId, void Function(Conversation) set) {
    final Conversation c = _conv(convId);
    set(c);
    _markDirty(c);
    _emit();
  }

  /// Remove a conversation and its history from this device.
  Future<void> deleteConversation(String convId) async {
    conversations.remove(convId);
    await store.delete('history.$convId');
    _scheduleSave();
    _emit();
  }

  String titleOf(Conversation c) => c.isGroup ? c.group!.name : _label(c.peer!);
  String labelOf(String user) => _label(user);
  String _label(String user) => user == username ? 'You' : (contacts[user]?.label ?? user);

  List<SearchHit> search(String query) {
    final String q = query.trim().toLowerCase();
    if (q.isEmpty) return const <SearchHit>[];
    final List<SearchHit> hits = <SearchHit>[];
    for (final Conversation c in conversations.values) {
      for (final ChatMessage m in c.messages.reversed) {
        if (!m.deleted && !m.system && m.body.toLowerCase().contains(q)) hits.add(SearchHit(c, m));
      }
    }
    hits.sort((SearchHit a, SearchHit b) => b.message.sentAt.compareTo(a.message.sentAt));
    return hits;
  }

  Future<void> updateProfile({String? displayName, Uint8List? avatar, bool clearAvatar = false}) async {
    if (displayName != null) profile.displayName = displayName.trim();
    if (clearAvatar) {
      profile.avatar = null;
    } else if (avatar != null) {
      if (avatar.length > maxInlineImageBytes) throw const MessengerException('Image is too large.');
      profile.avatar = avatar;
    }
    await store.put('profile', profile.toJson());
    _profileShared.clear();
    await store.put('profile_shared', <String>[]);
    _emit();
    for (final Conversation c in conversations.values.where((Conversation c) => !c.isGroup)) {
      try {
        await _shareProfileIfNeeded(c);
      } on Object {
        // Shared on the next message instead.
      }
    }
  }

  /// Profiles travel end to end, never via the relay: each contact receives
  /// ours once (and again after it changes).
  Future<void> _shareProfileIfNeeded(Conversation c) async {
    final List<String> users = c.recipients(username)
        .where((String u) => !_profileShared.contains(u))
        .toList();
    if (users.isEmpty) return;
    final AppPayload p = AppPayload(
      id: _newId(),
      timestampMs: DateTime.now().millisecondsSinceEpoch,
      kind: PayloadKind.profile,
      displayName: profile.displayName,
      avatar: profile.avatar,
    );
    await _send(c, p, users: users);
    _profileShared.addAll(users);
    await store.put('profile_shared', _profileShared.toList());
  }

  Future<void> updateSettings(void Function(AppSettings) change) async {
    final bool online = settings.showOnline;
    final bool lastSeen = settings.showLastSeen;
    change(settings);
    await store.put('settings', settings.toJson());
    if (online != settings.showOnline || lastSeen != settings.showLastSeen) {
      await _authed(() => relay.putPrivacy(
          showOnline: settings.showOnline, showLastSeen: settings.showLastSeen));
    }
    _emit();
  }

  Future<Presence?> presenceOf(String user) async {
    try {
      return await _authed(() => relay.presence(user));
    } on Object {
      return null;
    }
  }

  Future<void> block(String user) async {
    await _authed(() => relay.block(user));
    contacts.putIfAbsent(user, () => Contact(user)).blocked = true;
    await _persistContacts();
    _emit();
  }

  Future<void> unblock(String user) async {
    await _authed(() => relay.unblock(user));
    contacts[user]?.blocked = false;
    await _persistContacts();
    _emit();
  }

  Future<void> report(String user, String reason, {String? note}) =>
      _authed(() => relay.report(user, reason, note: note));

  // =====================================================================
  // Verification
  // =====================================================================

  /// Safety numbers for each of [user]'s devices, to compare out of band.
  Future<List<DeviceSafety>> safetyNumbersFor(String user) async {
    try {
      await _authed(() => directory.lookup(user));
    } on Object {
      // Offline: show what is pinned.
    }
    final List<DeviceSafety> out = <DeviceSafety>[];
    for (final DevicePin p in directory.allDevicesOf(user).where((DevicePin p) => p.active)) {
      out.add(DeviceSafety(
        p,
        await safetyNumber(identity.public, p.identity),
        qrPayload(identity.public, p.identity),
      ));
    }
    return out;
  }

  Future<void> setDeviceVerified(String deviceIdOfPeer, bool verified) async {
    final DevicePin? p = directory.pin(deviceIdOfPeer);
    if (p == null) return;
    if (verified && p.conflict) {
      throw const MessengerException('This device presented a changed key; it cannot be marked verified.');
    }
    p.verified = verified;
    await _persistDirectory();
    _emit();
  }

  /// Judge a scanned verification code against [user]'s devices.
  ///
  /// The code names exactly one device (by its key). Only a full two-way
  /// [QrCheck.match] marks that device verified; nothing in the code is ever
  /// imported. An own-key mismatch outranks the others: it means the peer holds
  /// a different key for US, which is the man-in-the-middle signal.
  Future<QrScanOutcome> verifyByScannedCode(String user, String scanned) async {
    try {
      await _authed(() => directory.lookup(user));
    } on Object {
      // Offline: judge against what is pinned.
    }
    QrCheck best = QrCheck.notHelo;
    for (final DevicePin p in directory.allDevicesOf(user).where((DevicePin p) => p.active)) {
      final QrCheck r = checkQrPayload(scanned, me: identity.public, peer: p.identity);
      if (r == QrCheck.match) {
        if (p.conflict) return QrScanOutcome(QrCheck.peerKeyMismatch, p);
        await setDeviceVerified(p.deviceId, true);
        logger.info('device_verified_by_qr');
        return QrScanOutcome(QrCheck.match, p);
      }
      if (r == QrCheck.ownKeyMismatch) return QrScanOutcome(r, p);
      if (r == QrCheck.peerKeyMismatch) best = r;
    }
    return QrScanOutcome(best, null);
  }

  /// Verified only if EVERY active device of every other member is verified.
  bool isVerified(Conversation c) {
    final List<DevicePin> devices =
        c.recipients(username).expand(directory.devicesOf).toList();
    return devices.isNotEmpty && devices.every((DevicePin p) => p.verified);
  }

  bool hasConflict(Conversation c) =>
      c.recipients(username).expand(directory.allDevicesOf).any((DevicePin p) => p.conflict);

  /// Which handshake protects the current session(s) with a conversation.
  Set<String> keyEstablishmentOf(Conversation c) => c.recipients(username)
      .expand(directory.devicesOf)
      .map((DevicePin p) => _sessions[p.deviceId]?.first.kex)
      .whereType<String>()
      .toSet();

  // =====================================================================
  // Account
  // =====================================================================

  Future<List<OwnDevice>> devices() => _authed(relay.listDevices);
  Future<List<SecurityEvent>> securityEvents() => _authed(relay.securityEvents);

  Future<void> revokeDevice(String id) async {
    await _authed(() => relay.revokeDevice(id));
    if (id == deviceId) await _wipe();
  }

  /// The relay revokes every other session; this device logs in again with
  /// the new password and re-registers its (unchanged) identity.
  Future<void> changePassword(String current, String next) async {
    await _authed(() => relay.changePassword(current, next));
    await relay.login(username, next);
    await relay.registerDevice(deviceId: deviceId, identityPublic: identity.public.toJson());
    await _persistTokens();
  }

  Future<void> logoutEverywhere() async {
    await _authed(relay.logoutAll);
    await _wipe();
  }

  Future<void> deleteAccount(String password) async {
    await _authed(() => relay.deleteAccount(password));
    await _wipe();
  }

  /// Destroy all key material on this device. Contacts will see this
  /// account's next device as new and unverified — the correct outcome.
  Future<void> resetEverything() async {
    await relay.logout();
    await _wipe();
  }

  Future<void> _wipe() async {
    _running = false;
    conversations.clear();
    contacts.clear();
    _sessions.clear();
    _outbox.clear();
    _saveTimer?.cancel();
    _dirtyHistory.clear();
    relay.clearTokens();
    await storage.wipeAll();
    _emit();
    onReset?.call();
  }

  // =====================================================================
  // Persistence
  // =====================================================================

  void _addMessage(Conversation c, ChatMessage m) {
    c.messages.add(m);
    if (c.messages.length > _maxHistory) c.messages.removeRange(0, c.messages.length - _maxHistory);
    _markDirty(c);
  }

  void _systemNotice(Conversation c, String text) {
    _addMessage(c, ChatMessage(
      id: _newId(),
      convId: c.id,
      author: username,
      outgoing: false,
      sentAt: DateTime.now(),
      body: text,
      system: true,
    ));
  }

  void _markDirty(Conversation c) {
    _dirtyHistory.add(c.id);
    _scheduleSave();
  }

  void _scheduleSave() {
    _saveTimer?.cancel();
    _saveTimer = Timer(const Duration(milliseconds: 250), () => unawaited(flush()));
  }

  /// Write conversations, dirty histories and contacts now.
  Future<void> flush() async {
    _saveTimer?.cancel();
    final List<String> dirty = _dirtyHistory.toList();
    _dirtyHistory.clear();
    for (final String id in dirty) {
      final Conversation? c = conversations[id];
      if (c == null) continue;
      await store.put('history.$id',
          c.messages.map((ChatMessage m) => m.toJson()).toList());
    }
    await store.put('conversations',
        conversations.values.map((Conversation c) => c.metaJson()).toList());
    await _persistContacts();
  }

  Future<void> _persistContacts() =>
      store.put('contacts', contacts.values.map((Contact c) => c.toJson()).toList());

  Future<void> _persistDirectory() => store.put('directory', directory.toJson());

  Future<void> _persistOutbox() =>
      store.put('outbox', _outbox.map((_OutboxItem i) => i.toJson()).toList());

  Future<void> _persistSessionState(Session s) async =>
      storage.put(StorageKeys.session(s.sessionId), await s.save(store.stateKey));

  Future<void> _persistSessionIndex() => store.put('devsessions', _sessions.map(
      (String device, List<Session> list) => MapEntry<String, Object?>(
          device, list.map((Session s) => s.sessionId).toList())));

  Future<void> _persistPreKeys() => storage.put(StorageKeys.preKeyState,
      Uint8List.fromList(utf8.encode(jsonEncode(prekeys.toStorageJson()))));

  Future<void> _persistTokens() async {
    await _putString(StorageKeys.accessToken, relay.accountToken);
    await _putString(StorageKeys.deviceToken, relay.deviceToken);
    await _putString(StorageKeys.refreshToken, relay.refreshToken);
  }

  Future<String?> _getString(String key) async {
    final Uint8List? v = await storage.get(key);
    return v == null ? null : utf8.decode(v);
  }

  Future<void> _putString(String key, String? value) => value == null
      ? storage.delete(key)
      : storage.put(key, Uint8List.fromList(utf8.encode(value)));

  void _emit() {
    if (!_changes.isClosed) _changes.add(null);
  }

  static String _hex(List<int> bytes) =>
      bytes.map((int b) => b.toRadixString(16).padLeft(2, '0')).join();

  // ------------------------------------------------------- test seams

  /// Send an arbitrary, possibly unauthorised payload, bypassing this
  /// client's own checks. Tests use it to play a MALICIOUS peer and confirm
  /// the RECEIVING client enforces the rules (author-only edits, admin-only
  /// group changes) rather than trusting the sender's UI to.
  @visibleForTesting
  Future<void> sendRawPayload(String convId, AppPayload payload, {List<String>? users}) =>
      _send(_conv(convId), payload, users: users);

  @visibleForTesting
  String freshId() => _newId();

  /// Number of envelopes waiting for the relay (for tests and diagnostics).
  int get pendingEnvelopes =>
      _outbox.fold(0, (int n, _OutboxItem i) => n + i.envelopes.length);

  /// The current session with a remote device, if any (diagnostics).
  Session? sessionWith(String remoteDeviceId) => _sessions[remoteDeviceId]?.first;
}
