"""Security-aware logging.

The threat here is mundane and extremely common: a debug line that prints a
whole session object, a crash report that serialises a state dataclass, or an
exception whose repr contains key material. Any of those turns a device with
log access into a full compromise.

This module enforces an allowlist. Fields not explicitly declared safe are
replaced with a redaction marker -- the default is to redact, not to emit.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

REDACTED = "<redacted>"

# Fields that may appear in logs. Everything else is redacted.
SAFE_FIELDS = frozenset({
    "event", "level", "timestamp", "state", "verification", "protocol_version",
    "session_id_hash", "device_id_hash", "message_number", "previous_chain_length",
    "skipped_keys_stored", "local_ratchet_fingerprint", "remote_ratchet_fingerprint",
    "remote_identity_fingerprint", "outcome", "error_class", "duration_ms",
    "ciphertext_len", "prekey_count", "used_one_time_prekey", "message_type",
})

# Substrings that indicate secret material, checked case-insensitively.
FORBIDDEN_SUBSTRINGS = (
    "private", "priv", "secret", "seed", "root_key", "chain_key", "message_key",
    "mk", "plaintext", "password", "token", "credential", "shared", "skipped",
    "identity_key", "salt",
)


def hash_id(value: str | bytes) -> str:
    """Stable, truncated hash for correlating log lines without exposing ids."""
    raw = value.encode() if isinstance(value, str) else value
    return hashlib.sha256(b"Helo_LogId_v1" + raw).hexdigest()[:16]


def _is_safe(key: str) -> bool:
    lowered = key.lower()
    if any(bad in lowered for bad in FORBIDDEN_SUBSTRINGS):
        return False
    return key in SAFE_FIELDS


def redact(fields: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of `fields` with everything not explicitly safe removed."""
    return {k: (v if _is_safe(k) else REDACTED) for k, v in fields.items()}


class SecureLogger:
    """Structured logger that cannot emit unredacted fields.

    There is intentionally no `raw` or `unsafe` escape hatch. If a field needs
    to be logged, it must be added to SAFE_FIELDS by a deliberate code change
    that shows up in review.
    """

    def __init__(self, name: str = "helo") -> None:
        self._log = logging.getLogger(name)

    def event(self, level: int, event: str, **fields: Any) -> None:
        payload = redact({"event": event, **fields})
        self._log.log(level, "%s", payload)

    def info(self, event: str, **fields: Any) -> None:
        self.event(logging.INFO, event, **fields)

    def warning(self, event: str, **fields: Any) -> None:
        self.event(logging.WARNING, event, **fields)

    def security(self, event: str, **fields: Any) -> None:
        """A security-relevant event: auth failure, replay, identity change."""
        self.event(logging.WARNING, event, **fields)
