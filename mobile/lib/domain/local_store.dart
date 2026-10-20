/// Sealed local persistence for everything that is not a ratchet session.
///
/// Conversations, message history, contacts, the outbox and settings are
/// serialised to JSON and sealed with AES-256-GCM under a key derived from the
/// session-state key, which itself lives in the platform keystore
/// (CryptoStorage). Each record's name is bound as associated data and into
/// its key derivation, so a sealed record cannot be swapped for another.
///
/// The label `Helo_LocalStore_v1|` is local-storage domain separation; it is
/// distinct from every protocol KDF string.
library;

import 'dart:convert';
import 'dart:typed_data';

import '../crypto/encoding.dart';
import '../crypto/errors.dart';
import '../crypto/primitives.dart';
import '../storage/crypto_storage.dart';

class LocalStore {
  LocalStore(this.storage);

  final CryptoStorage storage;
  Uint8List? _stateKey;

  Uint8List get stateKey {
    final Uint8List? k = _stateKey;
    if (k == null) throw const InvalidStateTransitionError('local store not opened');
    return k;
  }

  /// Load the state key, creating it on first use.
  Future<void> open() async {
    Uint8List? key = await storage.get(StorageKeys.sessionStateKey);
    if (key == null) {
      key = defaultRandom.bytes(aes256KeyLen);
      await storage.put(StorageKeys.sessionStateKey, key);
    }
    _stateKey = key;
  }

  static String _storageKey(String name) => 'store.$name';

  Future<Uint8List> _keyFor(String name) => hkdf(
        ikm: stateKey,
        salt: <int>[],
        info: utf8.encode('Helo_LocalStore_v1|$name'),
        length: aes256KeyLen,
      );

  Future<void> put(String name, Object? json) async {
    final Uint8List nonce = defaultRandom.bytes(aesGcmNonceLen);
    final Uint8List sealed = await aes256GcmEncrypt(
      key: await _keyFor(name),
      nonce: nonce,
      plaintext: utf8.encode(jsonEncode(json)),
      associatedData: utf8.encode('Helo_LocalStore_v1|$name'),
    );
    await storage.put(_storageKey(name), concat(<List<int>>[nonce, sealed]));
  }

  /// Returns null if absent. Throws [SessionStateCorruptError] if the record
  /// fails authentication — tampered or corrupt state is never "repaired".
  Future<Object?> get(String name) async {
    final Uint8List? blob = await storage.get(_storageKey(name));
    if (blob == null) return null;
    if (blob.length < aesGcmNonceLen + aesGcmTagLen) {
      throw SessionStateCorruptError('stored record $name is truncated');
    }
    try {
      final Uint8List plain = await aes256GcmDecrypt(
        key: await _keyFor(name),
        nonce: blob.sublist(0, aesGcmNonceLen),
        ciphertextAndTag: blob.sublist(aesGcmNonceLen),
        associatedData: utf8.encode('Helo_LocalStore_v1|$name'),
      );
      return jsonDecode(utf8.decode(plain));
    } on HeloError {
      throw SessionStateCorruptError('stored record $name failed authentication');
    } on FormatException {
      throw SessionStateCorruptError('stored record $name is malformed');
    }
  }

  Future<void> delete(String name) => storage.delete(_storageKey(name));
}
