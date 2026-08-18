/// Protocol error taxonomy — a direct port of `helo_ref/errors.py`.
///
/// There is deliberately NO error type that permits degraded operation. The
/// protocol fails closed: no plaintext fallback, no best-effort decryption.
library;

sealed class HeloError implements Exception {
  const HeloError(this.message);
  final String message;
  @override
  String toString() => '$runtimeType: $message';
}

class InvalidEncodingError extends HeloError {
  const InvalidEncodingError(super.message);
}

class InvalidKeyError extends HeloError {
  const InvalidKeyError(super.message);
}

class SignatureVerificationError extends HeloError {
  const SignatureVerificationError(super.message);
}

class IdentityChangedError extends HeloError {
  const IdentityChangedError(super.message);
}

class PreKeyUnavailableError extends HeloError {
  const PreKeyUnavailableError(super.message);
}

class UnknownSessionError extends HeloError {
  const UnknownSessionError(super.message);
}

class InvalidStateTransitionError extends HeloError {
  const InvalidStateTransitionError(super.message);
}

class SessionStateCorruptError extends HeloError {
  const SessionStateCorruptError(super.message);
}

class TooManySkippedMessagesError extends HeloError {
  const TooManySkippedMessagesError(super.message);
}

class AuthenticationError extends HeloError {
  const AuthenticationError(super.message);
}

class ReplayError extends HeloError {
  const ReplayError(super.message);
}
