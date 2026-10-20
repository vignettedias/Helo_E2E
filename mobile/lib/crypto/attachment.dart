/// End-to-end encrypted attachments — port of `helo_ref/attachment.py`.
///
/// STREAM over AES-256-GCM (Hoang, Reyhanitabar, Rogaway, Vizár 2015):
///
///     nonce_i = 0x00×7 ‖ u32(i) ‖ u8(is_final)      AD = "Helo_Attachment_v1"
///
/// The key is fresh per attachment and travels only inside an E2EE message.
/// Reordering, dropping, truncating or extending chunks all fail
/// authentication; no partial plaintext is ever returned.
library;

import 'dart:typed_data';

import 'encoding.dart';
import 'errors.dart';
import 'primitives.dart';

final Uint8List attachmentAd =
    Uint8List.fromList('Helo_Attachment_v1'.codeUnits);
const int attachmentChunkSize = 64 * 1024;
const int maxAttachmentBytes = 24 * 1024 * 1024;

Uint8List generateAttachmentKey([RandomSource? rng]) =>
    (rng ?? defaultRandom).bytes(aes256KeyLen);

Uint8List _nonce(int index, bool isFinal) => concat(<List<int>>[
      Uint8List(7),
      u32(index),
      u8(isFinal ? 1 : 0),
    ]);

int attachmentCiphertextLength(int plaintextLen,
    [int chunkSize = attachmentChunkSize]) {
  final int chunks =
      plaintextLen == 0 ? 1 : (plaintextLen + chunkSize - 1) ~/ chunkSize;
  return plaintextLen + chunks * aesGcmTagLen;
}

Future<Uint8List> encryptAttachment(
  List<int> key,
  Uint8List plaintext, [
  int chunkSize = attachmentChunkSize,
]) async {
  if (plaintext.length > maxAttachmentBytes) {
    throw const InvalidEncodingError('attachment exceeds the maximum size');
  }
  final int count =
      plaintext.isEmpty ? 1 : (plaintext.length + chunkSize - 1) ~/ chunkSize;
  final BytesBuilder out = BytesBuilder(copy: false);
  for (int i = 0; i < count; i++) {
    final int start = i * chunkSize;
    final int end = start + chunkSize < plaintext.length
        ? start + chunkSize
        : plaintext.length;
    out.add(await aes256GcmEncrypt(
      key: key,
      nonce: _nonce(i, i == count - 1),
      plaintext: Uint8List.sublistView(plaintext, start, end),
      associatedData: attachmentAd,
    ));
  }
  return out.takeBytes();
}

Future<Uint8List> decryptAttachment(
  List<int> key,
  Uint8List ciphertext, [
  int chunkSize = attachmentChunkSize,
]) async {
  final int segment = chunkSize + aesGcmTagLen;
  if (ciphertext.length < aesGcmTagLen) {
    throw const AuthenticationError('attachment ciphertext is truncated');
  }
  final int count = (ciphertext.length + segment - 1) ~/ segment;
  if (ciphertext.length - (count - 1) * segment < aesGcmTagLen) {
    throw const AuthenticationError(
        'attachment ciphertext has a malformed final chunk');
  }
  final BytesBuilder out = BytesBuilder(copy: false);
  for (int i = 0; i < count; i++) {
    final int start = i * segment;
    final int end =
        start + segment < ciphertext.length ? start + segment : ciphertext.length;
    out.add(await aes256GcmDecrypt(
      key: key,
      nonce: _nonce(i, i == count - 1),
      ciphertextAndTag: Uint8List.sublistView(ciphertext, start, end),
      associatedData: attachmentAd,
    ));
  }
  return out.takeBytes();
}

Future<Uint8List> attachmentDigest(List<int> ciphertext) => sha256Hash(ciphertext);

/// Reject a substituted blob before attempting any decryption.
Future<void> verifyAttachmentDigest(List<int> ciphertext, List<int> expected) async {
  if (!constantTimeEquals(await attachmentDigest(ciphertext), expected)) {
    throw const AuthenticationError('attachment ciphertext does not match its digest');
  }
}
