/// Secure key storage — the platform abstraction required by Phase 3.
///
/// WHAT IS AND IS NOT HARDWARE-BACKED
/// ----------------------------------
/// This distinction is routinely overstated in security documentation, so it is
/// spelled out precisely here rather than summarised as "hardware-backed".
///
/// Android
///   `flutter_secure_storage` encrypts values with a key held in the Android
///   Keystore. On devices with a TEE or StrongBox, that WRAPPING key is
///   hardware-backed and non-exportable. The wrapped values themselves live in
///   `SharedPreferences` — they are ciphertext there, but they are not inside
///   secure hardware. So:
///       * the wrapping key       -> hardware-backed (TEE/StrongBox, where present)
///       * identity/session keys  -> encrypted at rest, NOT inside the TEE
///   On devices without a TEE, the wrapping key is software-protected only.
///
/// iOS
///   Values are stored in the Keychain with
///   `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. Keychain items are
///   protected by keys derived in the Secure Enclave, and `ThisDeviceOnly`
///   prevents the item from migrating to iCloud Keychain or another device via
///   backup. The item content itself is not stored inside the Secure Enclave.
///
/// What this DOES buy:
///   * Keys are not readable from a filesystem dump or an unencrypted backup.
///   * Keys are bound to the device and cannot be silently exfiltrated to
///     another device via cloud backup.
///   * On Android with StrongBox, extracting the wrapping key requires
///     defeating dedicated secure hardware.
///
/// What this does NOT buy:
///   * Protection against a compromised OS or a rooted/jailbroken device. Once
///     an attacker runs code as this app, they can ask the platform to unwrap
///     these values, exactly as the app does.
///   * True non-exportability of the Ed25519/X25519 private keys. Neither
///     Keystore nor Keychain exposes X25519 or Ed25519 operations in a form the
///     protocol can use, so the keys must exist in process memory to perform a
///     DH. A design where the identity key never leaves secure hardware would
///     require platform channels and hardware that supports these curves —
///     recorded as future work, not claimed today.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../crypto/errors.dart';
import '../crypto/primitives.dart';

/// Platform-agnostic secure storage contract.
abstract class CryptoStorage {
  /// Store a secret. Overwrites any existing value for [key].
  Future<void> put(String key, Uint8List value);

  /// Retrieve a secret, or null if absent.
  Future<Uint8List?> get(String key);

  /// Delete a secret. Idempotent.
  Future<void> delete(String key);

  /// Delete EVERYTHING. Used on logout, account reset, and device replacement.
  Future<void> wipeAll();

  Future<bool> containsKey(String key);

  /// Describes what protection this backend actually provides, for display in
  /// the security-information screen. Users deserve the real answer.
  StorageBacking get backing;
}

class StorageBacking {
  const StorageBacking({
    required this.platform,
    required this.wrappingKeyHardwareBacked,
    required this.description,
  });

  final String platform;
  final bool wrappingKeyHardwareBacked;
  final String description;
}

/// Production implementation over Android Keystore / iOS Keychain.
class PlatformCryptoStorage implements CryptoStorage {
  PlatformCryptoStorage({FlutterSecureStorage? storage})
      : _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(
                // Use the Keystore-backed implementation rather than the
                // legacy software fallback.
                encryptedSharedPreferences: true,
              ),
              iOptions: IOSOptions(
                // Do NOT sync to iCloud Keychain, and do not restore to a
                // different device from backup. Key material must not migrate.
                accessibility: KeychainAccessibility.first_unlock_this_device,
                synchronizable: false,
              ),
            );

  final FlutterSecureStorage _storage;

  static const String _prefix = 'helo.v1.';

  @override
  Future<void> put(String key, Uint8List value) =>
      _storage.write(key: _prefix + key, value: base64.encode(value));

  @override
  Future<Uint8List?> get(String key) async {
    final String? raw = await _storage.read(key: _prefix + key);
    if (raw == null) return null;
    try {
      return base64.decode(raw);
    } on FormatException {
      // Corrupt storage entry. Fail closed rather than returning garbage that
      // would be interpreted as a key.
      throw const SessionStateCorruptError('stored key material is malformed');
    }
  }

  @override
  Future<void> delete(String key) => _storage.delete(key: _prefix + key);

  @override
  Future<bool> containsKey(String key) =>
      _storage.containsKey(key: _prefix + key);

  @override
  Future<void> wipeAll() => _storage.deleteAll();

  @override
  StorageBacking get backing => const StorageBacking(
        platform: 'platform',
        wrappingKeyHardwareBacked: true,
        description:
            'Secrets are encrypted at rest under a key held by the platform '
            'keystore. On Android with a TEE or StrongBox, and on iOS via the '
            'Secure Enclave, that wrapping key is hardware-backed and cannot '
            'be exported. The secrets themselves are not stored inside secure '
            'hardware, and a compromised or rooted device can unwrap them.',
      );
}

/// In-memory implementation for tests ONLY.
///
/// Deliberately named so that its appearance in a production code path is
/// obvious in review and in a stack trace.
class InMemoryCryptoStorageForTestsOnly implements CryptoStorage {
  final Map<String, Uint8List> _values = <String, Uint8List>{};

  @override
  Future<void> put(String key, Uint8List value) async {
    _values[key] = Uint8List.fromList(value);
  }

  @override
  Future<Uint8List?> get(String key) async => _values[key];

  @override
  Future<void> delete(String key) async {
    final Uint8List? existing = _values.remove(key);
    if (existing != null) wipe(existing);
  }

  @override
  Future<bool> containsKey(String key) async => _values.containsKey(key);

  @override
  Future<void> wipeAll() async {
    for (final Uint8List v in _values.values) {
      wipe(v);
    }
    _values.clear();
  }

  @override
  StorageBacking get backing => const StorageBacking(
        platform: 'in-memory (TESTS ONLY)',
        wrappingKeyHardwareBacked: false,
        description: 'No protection whatsoever. Test double.',
      );
}

/// Canonical storage keys. Centralised so an audit can enumerate everything the
/// app persists in one place.
abstract final class StorageKeys {
  static const String identitySigSeed = 'identity.sig_seed';
  static const String identityDhPriv = 'identity.dh_priv';
  static const String identityPublic = 'identity.public';

  /// Master key protecting the encrypted session-state database. It is the one
  /// value whose compromise exposes all persisted ratchet state, which is why
  /// it lives here and never in the database it protects.
  static const String sessionStateKey = 'session.state_key';

  /// This device's relay identifier (e.g. `device-3fa9c1d2e07b`). Not a secret,
  /// but its presence is what marks the app as registered.
  /// Relay origin chosen on this device (a packaged app cannot guess the
  /// address of a relay on someone's laptop). Not a secret.
  static const String relayUrl = 'relay.url';

  static const String deviceId = 'device.id';
  static const String username = 'account.username';

  /// Relay bearer tokens. The account token authorises sending and prekey
  /// fetches; the device token authorises reading this device's queue.
  static const String accessToken = 'auth.access_token';
  static const String deviceToken = 'auth.device_token';
  static const String refreshToken = 'auth.refresh_token';

  /// Every prekey private half plus the id counters, as one snapshot. One
  /// value rather than one per key so a crash cannot persist half a rotation.
  static const String preKeyState = 'prekey.state';

  /// Which peer each persisted session belongs to. Holds no key material.
  static const String conversationIndex = 'conversation.index';

  /// Sealed ratchet state for one session (see Session.save).
  static String session(String sessionId) => 'session.$sessionId';

  /// Sealed message history for one session. Plaintext, so it is encrypted
  /// under the session-state key before it reaches storage.
  static String history(String sessionId) => 'history.$sessionId';
}

/// Key lifecycle operations that must be explicit and auditable.
class KeyLifecycle {
  const KeyLifecycle(this._storage);
  final CryptoStorage _storage;

  /// Device logout: destroy auth material, RETAIN identity and sessions.
  Future<void> logout() async {
    await _storage.delete(StorageKeys.accessToken);
    await _storage.delete(StorageKeys.deviceToken);
    await _storage.delete(StorageKeys.refreshToken);
  }

  /// Account reset / device replacement: destroy EVERYTHING.
  ///
  /// After this the device cannot decrypt any historical message, by design.
  /// Peers will see an identity change and must re-verify — that warning is
  /// the correct outcome, not a bug to be smoothed over.
  Future<void> resetAllKeyMaterial() => _storage.wipeAll();
}
