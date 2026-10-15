// SessionManager behaviour across restarts, token expiry and hostile input.
//
// The real RelayClient and SessionManager run against an in-memory relay
// double (FakeRelay) behind http's MockClient, so every byte still crosses the
// JSON wire format. A "restart" is a brand-new SessionManager and RelayClient
// over the SAME storage, which is exactly what relaunching the app does.

import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:helo/crypto/encoding.dart';
import 'package:helo/data/relay_client.dart';
import 'package:helo/domain/session_manager.dart';
import 'package:helo/storage/crypto_storage.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

const String password = 'correct-horse-battery-staple';

/// Minimal model of the relay's HTTP contract. Mirrors backend/src/server.js
/// closely enough to exercise the client, including the property that the
/// relay keeps the FIRST public key it sees for a given prekey id.
class FakeRelay {
  final Map<String, String> _accounts = <String, String>{};
  final Map<String, (String, String?)> _access = <String, (String, String?)>{};
  final Map<String, String> _refresh = <String, String>{};
  final Map<String, Map<String, dynamic>> _identities =
      <String, Map<String, dynamic>>{};
  final Map<String, Map<String, dynamic>> _signed =
      <String, Map<String, dynamic>>{};
  final Map<String, Map<int, Map<String, dynamic>>> _oneTime =
      <String, Map<int, Map<String, dynamic>>>{};
  final Map<String, Set<int>> _seenOneTimeIds = <String, Set<int>>{};
  final Map<String, List<Map<String, dynamic>>> _queues =
      <String, List<Map<String, dynamic>>>{};

  /// Every envelope ever submitted, including ones the relay then refused.
  final List<Map<String, dynamic>> submitted = <Map<String, dynamic>>[];
  int failNextSends = 0;
  int _counter = 0;

  String _token() => 'tok-${_counter++}-abcdefghijklmnop';

  /// Simulate the passage of an hour: every access and device token expires.
  void expireAccessTokens() => _access.clear();

  /// Act as a malicious relay: flip one bit of every queued ciphertext.
  void tamperQueuedCiphertexts() {
    for (final List<Map<String, dynamic>> queue in _queues.values) {
      for (final Map<String, dynamic> item in queue) {
        final Map<String, dynamic> env =
            item['envelope']! as Map<String, dynamic>;
        final Uint8List ct = b64d(env['ciphertext']! as String);
        ct[0] ^= 0x01;
        env['ciphertext'] = b64e(ct);
      }
    }
  }

  RelayClient client() =>
      RelayClient(baseUrl: 'http://relay.test', client: MockClient(_handle));

  http.Response _json(int status, Object body) =>
      http.Response(jsonEncode(body), status,
          headers: <String, String>{'content-type': 'application/json'});

  Future<http.Response> _handle(http.Request req) async {
    final String path = req.url.path;
    final Map<String, dynamic> body = req.body.isEmpty
        ? <String, dynamic>{}
        : jsonDecode(req.body) as Map<String, dynamic>;
    final String? bearer =
        req.headers['Authorization']?.replaceFirst('Bearer ', '');
    final (String, String?)? auth = bearer == null ? null : _access[bearer];

    http.Response unauthorised() =>
        _json(401, <String, String>{'error': 'invalid_token'});

    switch ((req.method, path)) {
      case ('POST', '/auth/register'):
        final String user = body['username']! as String;
        if (_accounts.containsKey(user)) {
          return _json(409, <String, String>{'error': 'username_taken'});
        }
        _accounts[user] = body['password']! as String;
        return _json(201, <String, String>{'account_id': user});

      case ('POST', '/auth/login'):
        final String user = body['username']! as String;
        if (_accounts[user] != body['password']) {
          return _json(401, <String, String>{'error': 'invalid_credentials'});
        }
        final String access = _token();
        final String refresh = _token();
        _access[access] = (user, null);
        _refresh[refresh] = user;
        return _json(200, <String, Object>{
          'access_token': access,
          'refresh_token': refresh,
          'expires_in': 3600,
        });

      case ('POST', '/auth/refresh'):
        final String? user = _refresh[body['refresh_token']];
        if (user == null) return unauthorised();
        final String access = _token();
        _access[access] = (user, null);
        return _json(
            200, <String, Object>{'access_token': access, 'expires_in': 3600});

      case ('POST', '/devices'):
        if (auth == null) return unauthorised();
        final String deviceId = body['device_id']! as String;
        _identities[deviceId] = body['identity']! as Map<String, dynamic>;
        final String token = _token();
        _access[token] = (auth.$1, deviceId);
        return _json(201,
            <String, String>{'device_id': deviceId, 'device_token': token});

      case ('POST', '/prekeys'):
        if (auth == null) return unauthorised();
        final String deviceId = body['device_id']! as String;
        _signed[deviceId] = body['signed_prekey']! as Map<String, dynamic>;
        final Map<int, Map<String, dynamic>> pool =
            _oneTime.putIfAbsent(deviceId, () => <int, Map<String, dynamic>>{});
        final Set<int> seen =
            _seenOneTimeIds.putIfAbsent(deviceId, () => <int>{});
        for (final Object? raw in body['one_time_prekeys']! as List<Object?>) {
          final Map<String, dynamic> otp = raw! as Map<String, dynamic>;
          // ON CONFLICT DO NOTHING: an id the relay has seen is never replaced.
          if (seen.add(otp['key_id']! as int)) {
            pool[otp['key_id']! as int] = otp;
          }
        }
        return _json(
            200, <String, int>{'available_one_time_prekeys': pool.length});

      case ('POST', '/messages'):
        if (auth == null) return unauthorised();
        final Map<String, dynamic> env =
            body['envelope']! as Map<String, dynamic>;
        submitted.add(env);
        if (failNextSends > 0) {
          failNextSends -= 1;
          return _json(500, <String, String>{'error': 'internal_error'});
        }
        final String id = 'msg-${_counter++}';
        _queues
            .putIfAbsent(body['recipient_device_id']! as String,
                () => <Map<String, dynamic>>[])
            .add(<String, dynamic>{
          'message_id': id,
          'sender_device_id': env['sender_device_id'],
          'queued_at': DateTime.now().millisecondsSinceEpoch ~/ 1000,
          'envelope': env,
        });
        return _json(202, <String, String>{'message_id': id});

      case ('GET', '/messages'):
        if (auth == null || auth.$2 == null) return unauthorised();
        return _json(200, <String, Object>{
          'messages': _queues[auth.$2] ?? <Map<String, dynamic>>[],
        });

      case ('POST', '/delivery/ack'):
        if (auth == null || auth.$2 == null) return unauthorised();
        final Set<Object?> ids =
            (body['message_ids']! as List<Object?>).toSet();
        final List<Map<String, dynamic>> queue =
            _queues[auth.$2] ?? <Map<String, dynamic>>[];
        final int before = queue.length;
        queue.removeWhere(
            (Map<String, dynamic> m) => ids.contains(m['message_id']));
        return _json(200, <String, int>{'acknowledged': before - queue.length});
    }

    if (req.method == 'GET' && path.startsWith('/prekeys/')) {
      if (auth == null) return unauthorised();
      final String deviceId = path.substring('/prekeys/'.length);
      final Map<String, dynamic>? identity = _identities[deviceId];
      if (identity == null) {
        return _json(404, <String, String>{'error': 'device_not_found'});
      }
      final Map<int, Map<String, dynamic>> pool =
          _oneTime[deviceId] ?? <int, Map<String, dynamic>>{};
      final List<int> ids = pool.keys.toList()..sort();
      final Map<String, dynamic>? claimed =
          ids.isEmpty ? null : pool.remove(ids.first);
      return _json(200, <String, Object?>{
        'device_id': deviceId,
        'identity': identity,
        'signed_prekey': _signed[deviceId],
        'one_time_prekey': claimed,
        'one_time_prekey_available': claimed != null,
        'remaining_one_time_prekeys': pool.length,
      });
    }
    return _json(404, <String, String>{'error': 'not_found'});
  }
}

Future<SessionManager> register(
    FakeRelay relay, CryptoStorage storage, String name) async {
  final SessionManager m = SessionManager(
    storage: storage,
    relay: relay.client(),
    deviceId: '$name-device',
  );
  await m.loadOrCreateIdentity();
  await m.registerWithRelay(
      username: name, password: password, createAccount: true);
  return m;
}

/// What relaunching the app does: fresh objects, same storage.
Future<SessionManager> restart(FakeRelay relay, CryptoStorage storage) async {
  final Uint8List? id = await storage.get(StorageKeys.deviceId);
  expect(id, isNotNull, reason: 'a registered device must be restorable');
  final SessionManager m = SessionManager(
    storage: storage,
    relay: relay.client(),
    deviceId: utf8.decode(id!),
  );
  expect(await m.restore(), isTrue);
  return m;
}

void main() {
  late FakeRelay relay;
  late CryptoStorage aliceStore;
  late CryptoStorage bobStore;

  setUp(() {
    relay = FakeRelay();
    aliceStore = InMemoryCryptoStorageForTestsOnly();
    bobStore = InMemoryCryptoStorageForTestsOnly();
  });

  test('the stored device id is the device id, not a bearer token', () async {
    await register(relay, aliceStore, 'alice');
    expect(utf8.decode((await aliceStore.get(StorageKeys.deviceId))!),
        equals('alice-device'));
    expect(await aliceStore.containsKey(StorageKeys.deviceToken), isTrue);
  });

  test('identity, sessions, prekeys and history survive restarts on both sides',
      () async {
    final SessionManager alice0 = await register(relay, aliceStore, 'alice');
    final SessionManager bob0 = await register(relay, bobStore, 'bob');

    // Alice opens a session but restarts before sending anything: the pending
    // X3DH header must survive, or Bob can never establish his side.
    await alice0.startConversation('bob-device');
    final SessionManager alice1 = await restart(relay, aliceStore);
    expect(alice1.identity.public.encode(),
        equals(alice0.identity.public.encode()));
    await alice1.send('bob-device', 'hello after a restart');

    // Bob restarts before receiving: the one-time prekey Alice consumed must
    // still be on his device, or the session cannot be built.
    final SessionManager bob1 = await restart(relay, bobStore);
    expect(await bob1.receive(), equals(1));
    await bob1.send('alice-device', 'got it');
    expect(await alice1.receive(), equals(1));

    final SessionManager alice2 = await restart(relay, aliceStore);
    final SessionManager bob2 = await restart(relay, bobStore);
    expect(
      alice2.conversations['bob-device']!.messages
          .map((ChatMessage m) => m.body),
      equals(<String>['hello after a restart', 'got it']),
    );
    expect(bob2.conversations['alice-device']!.messages.first.body,
        equals('hello after a restart'));

    // The restored sessions keep ratcheting.
    await alice2.send('bob-device', 'still working');
    expect(await bob2.receive(), equals(1));
    expect(await alice2.safetyNumberFor('bob-device'),
        equals(await bob2.safetyNumberFor('alice-device')));
    expect(bob0.deviceId, equals('bob-device'));
  });

  test('expired relay tokens are renewed instead of silently failing',
      () async {
    final SessionManager alice = await register(relay, aliceStore, 'alice');
    final SessionManager bob = await register(relay, bobStore, 'bob');
    final Uint8List before = (await bobStore.get(StorageKeys.deviceToken))!;

    relay.expireAccessTokens(); // an hour passes

    await alice.send('bob-device', 'sent after expiry');
    expect(await bob.receive(), equals(1));
    expect(
        (await bobStore.get(StorageKeys.deviceToken))!, isNot(equals(before)),
        reason: 'the renewed device token must be persisted');
  });

  test('ratchet state is saved before a ciphertext leaves the device',
      () async {
    final SessionManager alice0 = await register(relay, aliceStore, 'alice');
    await register(relay, bobStore, 'bob');

    relay.failNextSends = 1;
    await expectLater(alice0.send('bob-device', 'lost in transit'),
        throwsA(isA<RelayException>()));
    final SessionManager alice1 = await restart(relay, aliceStore);
    await alice1.send('bob-device', 'retry after restart');

    // If the advanced ratchet were not persisted before sending, the restart
    // would reuse the failed message's key -- and its derived AES-GCM nonce --
    // for a different plaintext.
    final List<String> headers = relay.submitted
        .map((Map<String, dynamic> e) => e['header']! as String)
        .toList();
    expect(headers, hasLength(2));
    expect(headers.toSet(), hasLength(2),
        reason: 'two ciphertexts were produced under the same message key');

    final SessionManager bob = await restart(relay, bobStore);
    expect(await bob.receive(), equals(1));
    expect(bob.conversations['alice-device']!.messages.single.body,
        equals('retry after restart'));
  });

  test('a tampered first message does not plant a conversation', () async {
    final SessionManager alice = await register(relay, aliceStore, 'alice');
    final SessionManager bob = await register(relay, bobStore, 'bob');

    await alice.send('bob-device', 'hello');
    relay.tamperQueuedCiphertexts();

    expect(await bob.receive(), equals(0));
    expect(bob.conversations, isEmpty,
        reason:
            'a session is adopted only after its first message authenticates');
    expect(await bob.receive(), equals(0),
        reason: 'the rejected message is acknowledged, not retried forever');
  });

  test('reset destroys local state and notifies the app', () async {
    final SessionManager alice = await register(relay, aliceStore, 'alice');
    bool notified = false;
    alice.onReset = () => notified = true;
    await alice.resetEverything();
    expect(notified, isTrue);
    expect(await aliceStore.containsKey(StorageKeys.identitySigSeed), isFalse);
    expect(await aliceStore.containsKey(StorageKeys.deviceId), isFalse);
  });
}
