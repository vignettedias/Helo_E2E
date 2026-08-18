/// Security-aware logging — port of `helo_ref/secure_log.py`.
///
/// The threat is mundane and extremely common: a debug line that prints a whole
/// session object, or a crash report that serialises protocol state. Either
/// turns log access into full compromise.
///
/// This logger uses an ALLOWLIST. Fields not explicitly declared safe are
/// replaced with a redaction marker — the default is to redact, not to emit.
/// There is deliberately no `raw` escape hatch: adding a field requires a code
/// change that shows up in review.
library;

import 'dart:convert';
import 'dart:developer' as developer;


const String redacted = '<redacted>';

const Set<String> safeFields = <String>{
  'event', 'level', 'timestamp', 'state', 'verification', 'protocol_version',
  'session_id_hash', 'device_id_hash', 'message_number',
  'previous_chain_length', 'skipped_keys_stored', 'local_ratchet_fingerprint',
  'remote_ratchet_fingerprint', 'remote_identity_fingerprint', 'outcome',
  'error_class', 'duration_ms', 'ciphertext_len', 'prekey_count',
  'used_one_time_prekey', 'message_type',
};

/// Substrings indicating secret material, checked case-insensitively.
const List<String> forbiddenSubstrings = <String>[
  'private', 'priv', 'secret', 'seed', 'root_key', 'chain_key', 'message_key',
  'plaintext', 'password', 'token', 'credential', 'shared', 'skipped',
  'identity_key', 'salt',
];

bool _isSafe(String key) {
  final String lowered = key.toLowerCase();
  for (final String bad in forbiddenSubstrings) {
    if (lowered.contains(bad)) return false;
  }
  return safeFields.contains(key);
}

Map<String, Object?> redact(Map<String, Object?> fields) =>
    fields.map((String k, Object? v) =>
        MapEntry<String, Object?>(k, _isSafe(k) ? v : redacted));

enum LogLevel { info, warning, security }

class SecureLogger {
  const SecureLogger([this.name = 'helo']);
  final String name;

  void event(LogLevel level, String eventName, [Map<String, Object?>? fields]) {
    final Map<String, Object?> payload = redact(<String, Object?>{
      'event': eventName,
      'level': level.name,
      ...?fields,
    });
    developer.log(jsonEncode(payload), name: name);
  }

  void info(String e, [Map<String, Object?>? f]) =>
      event(LogLevel.info, e, f);
  void warning(String e, [Map<String, Object?>? f]) =>
      event(LogLevel.warning, e, f);

  /// A security-relevant event: auth failure, replay, identity change.
  void security(String e, [Map<String, Object?>? f]) =>
      event(LogLevel.security, e, f);
}

const SecureLogger logger = SecureLogger();
