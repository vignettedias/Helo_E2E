/// HTTP client for the untrusted relay.
///
/// DESIGN RULE: this layer moves opaque envelopes. It never sees a plaintext
/// message and holds no key. Encryption happens strictly above it, in
/// SessionManager. If a plaintext message string ever appears in this file,
/// that is a bug of the most serious kind.
library;

import 'dart:convert';

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

  @override
  String toString() => 'RelayException($statusCode, $code)';
}

class QueuedMessage {
  const QueuedMessage({
    required this.messageId,
    required this.senderDeviceId,
    required this.queuedAt,
    required this.envelope,
  });
  final String messageId;
  final String senderDeviceId;
  final int queuedAt;
  final Envelope envelope;
}

class FetchedBundle {
  const FetchedBundle(this.bundle, this.oneTimePreKeyAvailable);
  final PreKeyBundle bundle;

  /// False when the peer's one-time prekeys are exhausted, meaning this session
  /// falls back to three-DH. The UI MUST surface this rather than silently
  /// accepting a weaker handshake — an attacker can force it by draining the
  /// victim's prekeys.
  final bool oneTimePreKeyAvailable;
}

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

  Future<Map<String, dynamic>> _request(
    String method,
    String path, {
    Map<String, Object?>? body,
    String? token,
  }) async {
    final Uri uri = Uri.parse('$baseUrl$path');
    final Map<String, String> headers = <String, String>{
      'Content-Type': 'application/json',
    };
    if (token != null) headers['Authorization'] = 'Bearer $token';

    final http.Response response = switch (method) {
      'GET' => await _client.get(uri, headers: headers),
      'POST' => await _client.post(uri,
          headers: headers, body: body == null ? null : jsonEncode(body)),
      _ => throw ArgumentError('unsupported method $method'),
    };

    Map<String, dynamic> decoded = <String, dynamic>{};
    if (response.body.isNotEmpty) {
      final Object? parsed = jsonDecode(response.body);
      if (parsed is Map<String, dynamic>) decoded = parsed;
    }

    if (response.statusCode >= 400) {
      final Object? retry = decoded['retry_after'];
      throw RelayException(
        response.statusCode,
        decoded['error'] as String? ?? 'unknown_error',
        retry is int ? retry : null,
      );
    }
    return decoded;
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
      } on RelayException {
        // Local logout proceeds regardless. The user asked to log out; failing
        // to clear local tokens because the network is down is the worse
        // outcome.
      }
    }
    _accountToken = null;
    _deviceToken = null;
    _refreshToken = null;
  }

  // --- devices ------------------------------------------------------------

  Future<String> registerDevice({
    required String deviceId,
    required Map<String, dynamic> identityPublic,
  }) async {
    final Map<String, dynamic> body = await _request('POST', '/devices',
        token: _accountToken,
        body: <String, Object?>{
          'device_id': deviceId,
          'identity': identityPublic,
        });
    _deviceToken = body['device_token'] as String?;
    return _deviceToken ?? '';
  }

  Future<List<Map<String, dynamic>>> listDevices() async {
    final Map<String, dynamic> body =
        await _request('GET', '/devices', token: _accountToken);
    final Object? devices = body['devices'];
    if (devices is! List<Object?>) return <Map<String, dynamic>>[];
    return devices.whereType<Map<String, dynamic>>().toList();
  }

  Future<void> revokeDevice(String deviceId) async {
    await _request('POST', '/devices/revoke',
        token: _accountToken, body: <String, Object?>{'device_id': deviceId});
  }

  // --- prekeys ------------------------------------------------------------

  Future<int> publishPreKeys({
    required String deviceId,
    required SignedPreKeyPublic signedPreKey,
    required List<OneTimePreKeyPublic> oneTimePreKeys,
  }) async {
    final Map<String, dynamic> body = await _request('POST', '/prekeys',
        token: _accountToken,
        body: <String, Object?>{
          'device_id': deviceId,
          'signed_prekey': signedPreKey.toJson(),
          'one_time_prekeys': oneTimePreKeys
              .map((OneTimePreKeyPublic k) => k.toJson())
              .toList(),
        });
    return body['available_one_time_prekeys'] as int? ?? 0;
  }

  Future<FetchedBundle> fetchBundle(String peerDeviceId) async {
    final Map<String, dynamic> body =
        await _request('GET', '/prekeys/$peerDeviceId', token: _accountToken);

    final PreKeyBundle bundle = PreKeyBundle.fromJson(<String, dynamic>{
      'device_id': body['device_id'],
      'identity': body['identity'],
      'signed_prekey': body['signed_prekey'],
      'one_time_prekey': body['one_time_prekey'],
    });
    return FetchedBundle(
        bundle, body['one_time_prekey_available'] as bool? ?? false);
  }

  // --- messages -----------------------------------------------------------

  Future<String> sendEnvelope({
    required String recipientDeviceId,
    required Envelope envelope,
  }) async {
    final Map<String, dynamic> body = await _request('POST', '/messages',
        token: _accountToken,
        body: <String, Object?>{
          'recipient_device_id': recipientDeviceId,
          'envelope': envelope.toJson(),
        });
    return body['message_id'] as String? ?? '';
  }

  Future<List<QueuedMessage>> fetchMessages() async {
    final Map<String, dynamic> body =
        await _request('GET', '/messages', token: _deviceToken);
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
          queuedAt: item['queued_at']! as int,
          envelope: Envelope.fromJson(env),
        ));
      } on HeloError {
        // A malformed envelope from an untrusted relay is expected input, not
        // an exceptional condition. Skip it rather than aborting the whole
        // fetch, which would let one bad message block the entire queue —
        // a trivial denial of service for a malicious relay.
        continue;
      }
    }
    return out;
  }

  Future<int> acknowledge(List<String> messageIds) async {
    if (messageIds.isEmpty) return 0;
    final Map<String, dynamic> body = await _request('POST', '/delivery/ack',
        token: _deviceToken,
        body: <String, Object?>{'message_ids': messageIds});
    return body['acknowledged'] as int? ?? 0;
  }

  void close() => _client.close();
}
