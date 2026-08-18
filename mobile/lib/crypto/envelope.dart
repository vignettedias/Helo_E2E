/// The wire envelope — exactly what the untrusted relay sees.
///
/// Data classification:
///   version, type       PUBLIC
///   session_id          SENSITIVE METADATA — links two devices' traffic
///   sender_device_id    SENSITIVE METADATA — routing
///   x3dh                CRYPTOGRAPHIC MATERIAL (public halves only)
///   header              CRYPTOGRAPHIC MATERIAL, authenticated but NOT encrypted
///   ciphertext          CIPHERTEXT (includes the 16-byte GCM tag)
///
/// The relay can therefore learn who talks to whom, when, how often, how long
/// each message is, and the delivery state. It cannot learn content. That is
/// stated plainly rather than described as "zero knowledge".
///
/// There is no `nonce` field: the nonce is derived from the message key.
library;

import 'dart:typed_data';

import 'encoding.dart';
import 'errors.dart';
import 'primitives.dart';
import 'x3dh.dart';

const String messageTypePrekey = 'prekey';
const String messageTypeNormal = 'normal';
const int maxCiphertextBytes = 64 * 1024;

class Envelope {
  const Envelope({
    required this.sessionId,
    required this.senderDeviceId,
    required this.header,
    required this.ciphertext,
    this.x3dh,
    this.version = protocolVersion,
  });

  final String sessionId;
  final String senderDeviceId;
  final RatchetHeader header;
  final Uint8List ciphertext;
  final InitialMessageHeader? x3dh;
  final int version;

  String get messageType =>
      x3dh != null ? messageTypePrekey : messageTypeNormal;

  Map<String, dynamic> toJson() {
    final Map<String, dynamic> obj = <String, dynamic>{
      'v': version,
      'type': messageType,
      'session_id': sessionId,
      'sender_device_id': senderDeviceId,
      'header': b64e(header.encode()),
      'ciphertext': b64e(ciphertext),
    };
    if (x3dh != null) obj['x3dh'] = x3dh!.toJson();
    return obj;
  }

  /// Parse and validate. Every bound is checked before any crypto runs.
  static Envelope fromJson(Map<String, dynamic> obj) {
    final Object? version = obj['v'];
    if (version is! int || version != protocolVersion) {
      throw const InvalidEncodingError('unsupported envelope version');
    }
    final Object? type = obj['type'];
    if (type is! String ||
        (type != messageTypePrekey && type != messageTypeNormal)) {
      throw const InvalidEncodingError('unknown message type');
    }
    final Object? sessionId = obj['session_id'];
    final Object? sender = obj['sender_device_id'];
    final Object? headerB64 = obj['header'];
    final Object? ctB64 = obj['ciphertext'];
    if (sessionId is! String ||
        sender is! String ||
        headerB64 is! String ||
        ctB64 is! String) {
      throw const InvalidEncodingError('envelope is missing a field');
    }

    final Uint8List ciphertext = b64d(ctB64);
    if (ciphertext.length < aesGcmTagLen) {
      throw const InvalidEncodingError('ciphertext shorter than the tag');
    }
    if (ciphertext.length > maxCiphertextBytes) {
      throw const InvalidEncodingError('ciphertext exceeds maximum size');
    }

    final Object? x3dhObj = obj['x3dh'];
    if (type == messageTypePrekey && x3dhObj is! Map<String, dynamic>) {
      throw const InvalidEncodingError('prekey message missing x3dh header');
    }
    if (type == messageTypeNormal && x3dhObj != null) {
      throw const InvalidEncodingError('normal message must not carry x3dh');
    }

    return Envelope(
      version: version,
      sessionId: sessionId,
      senderDeviceId: sender,
      header: RatchetHeader.decode(b64d(headerB64, expectLen: headerLen)),
      ciphertext: ciphertext,
      x3dh: x3dhObj is Map<String, dynamic>
          ? InitialMessageHeader.fromJson(x3dhObj)
          : null,
    );
  }

  /// Bytes of overhead this envelope adds over the raw plaintext.
  int ciphertextExpansion(int plaintextLen) =>
      ciphertext.length - plaintextLen + headerLen;
}
