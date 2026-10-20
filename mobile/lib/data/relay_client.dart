/// HTTP client for the untrusted relay.
///
/// DESIGN RULE: this layer moves opaque envelopes and encrypted attachment
/// blobs. It never sees a plaintext message and holds no key. Encryption
/// happens strictly above it, in the Messenger. If a plaintext message string
/// ever appears in this file, that is a bug of the most serious kind.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import '../crypto/envelope.dart';
import '../crypto/errors.dart';
import '../crypto/prekeys.dart';

class RelayException implements Exception {
  const RelayException(this.statusCode, this.code, [this.retryAfter]);
  final int statusCode;
  final String code;
  final int? retryAfter;

  bool get isAuthFailure => statusCode == 401;
  bool get isRateLimited => statusCode == 429;

  /// The relay will never accept this request as sent (as opposed to a
  /// transient failure worth retrying).
  bool get isPermanent =>
      statusCode >= 400 && statusCode < 500 && statusCode != 401 && statusCode != 429;

  @override
  String toString() => 'RelayException($statusCode, $code)';
}

class QueuedMessage {
  const QueuedMessage({
    required this.messageId,
    required this.senderDeviceId,
    required this.senderUsername,
    required this.queuedAt,
    required this.envelope,
  });
  final String messageId;
  final String senderDeviceId;

  /// Asserted by the RELAY from the authenticated sending device.
  final String? senderUsername;
  final int queuedAt;

  /// Null when the relay delivered something that is not a valid envelope.
  /// It is still acknowledged by id, so it cannot wedge the queue.
  final Envelope? envelope;
}

class FetchedBundle {
  const FetchedBundle(this.bundle, this.username, this.oneTimePreKeyAvailable);
  final PreKeyBundle bundle;
  final String? username;

  /// False when the peer's EC one-time prekeys are exhausted, so the session
  /// falls back to three-DH. Surfaced so the UI can say so.
  final bool oneTimePreKeyAvailable;
}

class DirectoryDevice {
  const DirectoryDevice(this.deviceId, this.identity);
  final String deviceId;
  final Map<String, dynamic> identity;
}

class DirectoryEntry {
  const DirectoryEntry(this.username, this.devices);
  final String username;
  final List<DirectoryDevice> devices;
}

class Presence {
  const Presence({this.online, this.lastSeen});

  /// Null when hidden by the user's (or the viewer's) privacy settings.
  final bool? online;
  final DateTime? lastSeen;
}

class SendResult {
  const SendResult(this.recipientDeviceId, this.status, {this.messageId, this.error});
  final String recipientDeviceId;
  final int status;
  final String? messageId;
  final String? error;
  bool get accepted => status == 202;
  bool get permanentFailure => status >= 400 && status < 500 && status != 429;
}

class OwnDevice {
  const OwnDevice(this.deviceId, this.registeredAt, this.lastSeenAt, this.revoked, this.current);
  final String deviceId;
  final DateTime registeredAt;
  final DateTime? lastSeenAt;
  final bool revoked;
  final bool current;
}

class SecurityEvent {
  const SecurityEvent(this.kind, this.deviceId, this.at);
  final String kind;
  final String? deviceId;
  final DateTime at;
}

DateTime _secs(int s) => DateTime.fromMillisecondsSinceEpoch(s * 1000);

class RelayClient {
  RelayClient({required this.baseUrl, http.Client? client})
      : _client = client ?? http.Client();

  final String baseUrl;
  final http.Client _client;

  String? _accountToken;
  String? _deviceToken;
  String? _refreshToken;

  bool get isAuthenticated => _accountToken != null;
  String? get accountToken => _accountToken;
  String? get deviceToken => _deviceToken;
  String? get refreshToken => _refreshToken;

  void restoreTokens({String? account, String? device, String? refresh}) {
    _accountToken = account;
    _deviceToken = device;
    _refreshToken = refresh;
  }

  Never _fail(http.BaseResponse response, String body) {
    Map<String, dynamic> decoded = <String, dynamic>{};
    try {
      final Object? parsed = jsonDecode(body);
      if (parsed is Map<String, dynamic>) decoded = parsed;
    } on FormatException {
      // Non-JSON error body (e.g. from a proxy): keep the status code only.
    }
    final Object? retry = decoded['retry_after'];
    throw RelayException(
      response.statusCode,
      decoded['error'] as String? ?? 'http_${response.statusCode}',
      retry is int ? retry : null,
    );
  }

  Future<Map<String, dynamic>> _request(
    String method,
    String path, {
    Object? body,
    String? token,
  }) async {
    final http.Request req = http.Request(method, Uri.parse('$baseUrl$path'));
    req.headers['Content-Type'] = 'application/json';
    if (token != null) req.headers['Authorization'] = 'Bearer $token';
    if (body != null) req.body = jsonEncode(body);

    final http.Response response = await http.Response.fromStream(await _client.send(req));
    if (response.statusCode >= 400) _fail(response, response.body);
    if (response.body.isEmpty) return <String, dynamic>{};
    final Object? parsed = jsonDecode(response.body);
    return parsed is Map<String, dynamic> ? parsed : <String, dynamic>{};
  }

  // --- auth ---------------------------------------------------------------

  Future<void> register(String username, String password) async {
    await _request('POST', '/auth/register',
        body: <String, Object?>{'username': username, 'password': password});
  }

  Future<void> login(String username, String password) async {
    final Map<String, dynamic> body = await _request('POST', '/auth/login',
        body: <String, Object?>{'username': username, 'password': password});
    _accountToken = body['access_token'] as String?;
    _refreshToken = body['refresh_token'] as String?;
  }

  Future<void> refresh() async {
    final String? token = _refreshToken;
    if (token == null) throw const RelayException(401, 'no_refresh_token');
    final Map<String, dynamic> body = await _request('POST', '/auth/refresh',
        body: <String, Object?>{'refresh_token': token});
    _accountToken = body['access_token'] as String?;
  }

  Future<void> logout() async {
    if (_accountToken != null) {
      try {
        await _request('POST', '/auth/logout', token: _accountToken);
      } on Object {
        // Local logout proceeds regardless: failing to clear local tokens
        // because the network is down is the worse outcome.
      }
    }
    clearTokens();
  }

  void clearTokens() {
    _accountToken = null;
    _deviceToken = null;
    _refreshToken = null;
  }

  Future<void> logoutAll() async {
    await _request('POST', '/auth/logout-all', token: _accountToken);
    clearTokens();
  }

  /// Change the password. The relay revokes every OTHER session; the caller
  /// must re-login to obtain fresh tokens for this device.
  Future<void> changePassword(String current, String next) async {
    await _request('POST', '/auth/password', token: _accountToken,
        body: <String, Object?>{'current_password': current, 'new_password': next});
  }

  // --- account ------------------------------------------------------------

  Future<List<SecurityEvent>> securityEvents() async {
    final Map<String, dynamic> body =
        await _request('GET', '/me/security-events', token: _accountToken);
    return (body['events'] as List<Object?>? ?? <Object?>[])
        .whereType<Map<String, dynamic>>()
        .map((Map<String, dynamic> e) => SecurityEvent(
            e['kind']! as String, e['device_id'] as String?, _secs(e['created_at']! as int)))
        .toList();
  }

  Future<Map<String, bool>> getPrivacy() async {
    final Map<String, dynamic> body = await _request('GET', '/me/settings', token: _accountToken);
    return body.map((String k, dynamic v) => MapEntry<String, bool>(k, v == true));
  }

  Future<void> putPrivacy({bool? showOnline, bool? showLastSeen}) async {
    await _request('PUT', '/me/settings', token: _accountToken, body: <String, Object?>{
      if (showOnline != null) 'show_online': showOnline,
      if (showLastSeen != null) 'show_last_seen': showLastSeen,
    });
  }

  Future<void> deleteAccount(String password) async {
    await _request('DELETE', '/me', token: _accountToken,
        body: <String, Object?>{'password': password});
    clearTokens();
  }

  // --- devices ------------------------------------------------------------

  Future<String> registerDevice({
    required String deviceId,
    required Map<String, dynamic> identityPublic,
  }) async {
    final Map<String, dynamic> body = await _request('POST', '/devices',
        token: _accountToken,
        body: <String, Object?>{'device_id': deviceId, 'identity': identityPublic});
    _deviceToken = body['device_token'] as String?;
    return _deviceToken ?? '';
  }

  Future<List<OwnDevice>> listDevices() async {
    final Map<String, dynamic> body = await _request('GET', '/devices', token: _accountToken);
    return (body['devices'] as List<Object?>? ?? <Object?>[])
        .whereType<Map<String, dynamic>>()
        .map((Map<String, dynamic> d) => OwnDevice(
              d['device_id']! as String,
              _secs(d['registered_at']! as int),
              d['last_seen_at'] == null ? null : _secs(d['last_seen_at']! as int),
              d['revoked'] == true,
              d['current'] == true,
            ))
        .toList();
  }

  Future<void> revokeDevice(String deviceId) async {
    await _request('POST', '/devices/revoke',
        token: _accountToken, body: <String, Object?>{'device_id': deviceId});
  }

  // --- directory & social -------------------------------------------------

  Future<DirectoryEntry> lookupUser(String username) async {
    final Map<String, dynamic> body = await _request(
        'GET', '/users/${Uri.encodeComponent(username)}', token: _accountToken);
    return DirectoryEntry(
      body['username']! as String,
      (body['devices'] as List<Object?>? ?? <Object?>[])
          .whereType<Map<String, dynamic>>()
          .map((Map<String, dynamic> d) => DirectoryDevice(
              d['device_id']! as String, d['identity']! as Map<String, dynamic>))
          .toList(),
    );
  }

  Future<Presence> presence(String username) async {
    final Map<String, dynamic> body = await _request(
        'GET', '/presence/${Uri.encodeComponent(username)}', token: _accountToken);
    final Object? last = body['last_seen'];
    return Presence(
      online: body['online'] as bool?,
      lastSeen: last is int ? _secs(last) : null,
    );
  }

  Future<List<String>> blocked() async {
    final Map<String, dynamic> body = await _request('GET', '/me/blocks', token: _accountToken);
    return (body['blocked'] as List<Object?>? ?? <Object?>[]).cast<String>();
  }

  Future<void> block(String username) async {
    await _request('POST', '/me/blocks',
        token: _accountToken, body: <String, Object?>{'username': username});
  }

  Future<void> unblock(String username) async {
    await _request('DELETE', '/me/blocks/${Uri.encodeComponent(username)}',
        token: _accountToken);
  }

  Future<void> report(String username, String reason, {String? note}) async {
    await _request('POST', '/reports', token: _accountToken, body: <String, Object?>{
      'username': username,
      'reason': reason,
      if (note != null && note.isNotEmpty) 'note': note,
    });
  }

  // --- prekeys ------------------------------------------------------------

  Future<(int, int)> publishPreKeys({
    required String deviceId,
    required SignedPreKeyPublic signedPreKey,
    required List<OneTimePreKeyPublic> oneTimePreKeys,
    PqPreKeyPublic? pqLastResort,
    List<PqPreKeyPublic> pqOneTimePreKeys = const <PqPreKeyPublic>[],
  }) async {
    Map<String, Object?> pq(PqPreKeyPublic k) => <String, Object?>{
          'key_id': k.keyId,
          'public': k.toJson()['public'],
          'signature': k.toJson()['signature'],
        };
    final Map<String, dynamic> body = await _request('POST', '/prekeys',
        token: _accountToken,
        body: <String, Object?>{
          'device_id': deviceId,
          'signed_prekey': signedPreKey.toJson(),
          'one_time_prekeys':
              oneTimePreKeys.map((OneTimePreKeyPublic k) => k.toJson()).toList(),
          if (pqLastResort != null) 'pq_last_resort': pq(pqLastResort),
          if (pqOneTimePreKeys.isNotEmpty)
            'pq_one_time_prekeys': pqOneTimePreKeys.map(pq).toList(),
        });
    return (
      body['available_one_time_prekeys'] as int? ?? 0,
      body['available_pq_one_time_prekeys'] as int? ?? 0,
    );
  }

  Future<FetchedBundle> fetchBundle(String peerDeviceId) async {
    final Map<String, dynamic> body = await _request(
        'GET', '/prekeys/${Uri.encodeComponent(peerDeviceId)}', token: _accountToken);
    final PreKeyBundle bundle = PreKeyBundle.fromJson(<String, dynamic>{
      'device_id': body['device_id'],
      'identity': body['identity'],
      'signed_prekey': body['signed_prekey'],
      'one_time_prekey': body['one_time_prekey'],
      'pq_prekey': body['pq_prekey'],
    });
    return FetchedBundle(bundle, body['username'] as String?,
        body['one_time_prekey_available'] as bool? ?? false);
  }

  // --- messages -----------------------------------------------------------

  /// One envelope per recipient device, in one request. Each item succeeds or
  /// fails on its own.
  Future<List<SendResult>> sendBatch(List<(String, Envelope)> items) async {
    final Map<String, dynamic> body = await _request('POST', '/messages/batch',
        token: _deviceToken,
        body: <String, Object?>{
          'messages': items
              .map(((String, Envelope) i) => <String, Object?>{
                    'recipient_device_id': i.$1,
                    'envelope': i.$2.toJson(),
                  })
              .toList(),
        });
    return (body['results'] as List<Object?>? ?? <Object?>[])
        .whereType<Map<String, dynamic>>()
        .map((Map<String, dynamic> r) => SendResult(
              r['recipient_device_id'] as String? ?? '',
              r['status'] as int? ?? 0,
              messageId: r['message_id'] as String?,
              error: r['error'] as String?,
            ))
        .toList();
  }

  /// Fetch this device's queue; with [waitSeconds] > 0, long-poll.
  Future<List<QueuedMessage>> fetchMessages({int waitSeconds = 0}) async {
    final Map<String, dynamic> body = await _request(
        'GET', waitSeconds > 0 ? '/messages?wait=$waitSeconds' : '/messages',
        token: _deviceToken);
    final Object? messages = body['messages'];
    if (messages is! List<Object?>) return <QueuedMessage>[];

    final List<QueuedMessage> out = <QueuedMessage>[];
    for (final Object? item in messages) {
      if (item is! Map<String, dynamic>) continue;
      final Object? env = item['envelope'];
      if (env is! Map<String, dynamic>) continue;
      try {
        out.add(QueuedMessage(
          messageId: item['message_id']! as String,
          senderDeviceId: item['sender_device_id']! as String,
          senderUsername: item['sender_username'] as String?,
          queuedAt: item['queued_at']! as int,
          envelope: Envelope.fromJson(env),
        ));
      } on HeloError {
        // A malformed envelope from an untrusted relay is expected input. It
        // is skipped (and later acknowledged by id) rather than aborting the
        // fetch, which would let one bad message block the whole queue.
        out.add(QueuedMessage(
          messageId: item['message_id'] as String? ?? '',
          senderDeviceId: '',
          senderUsername: null,
          queuedAt: 0,
          envelope: null,
        ));
      }
    }
    return out;
  }

  Future<int> acknowledge(List<String> messageIds) async {
    if (messageIds.isEmpty) return 0;
    final Map<String, dynamic> body = await _request('POST', '/delivery/ack',
        token: _deviceToken, body: <String, Object?>{'message_ids': messageIds});
    return body['acknowledged'] as int? ?? 0;
  }

  // --- attachments --------------------------------------------------------

  Future<String> uploadAttachment(Uint8List ciphertext, List<String> recipientDevices) async {
    final http.Request req =
        http.Request('POST', Uri.parse('$baseUrl/attachments'))
          ..headers['Content-Type'] = 'application/octet-stream'
          ..headers['Authorization'] = 'Bearer $_deviceToken'
          ..headers['X-Helo-Recipients'] = recipientDevices.join(',')
          ..bodyBytes = ciphertext;
    final http.Response response = await http.Response.fromStream(await _client.send(req));
    if (response.statusCode >= 400) _fail(response, response.body);
    return (jsonDecode(response.body) as Map<String, dynamic>)['attachment_id']! as String;
  }

  Future<Uint8List> downloadAttachment(String attachmentId) async {
    final http.Request req = http.Request(
        'GET', Uri.parse('$baseUrl/attachments/${Uri.encodeComponent(attachmentId)}'))
      ..headers['Authorization'] = 'Bearer $_deviceToken';
    final http.Response response = await http.Response.fromStream(await _client.send(req));
    if (response.statusCode >= 400) _fail(response, response.body);
    return response.bodyBytes;
  }

  void close() => _client.close();
}
