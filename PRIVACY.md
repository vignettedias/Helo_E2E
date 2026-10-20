# Privacy

## What Helo protects

Message **content**, end to end. Nothing else is promised.

## What the relay learns

This is the honest list. It is not minimised by assertion, and the phrase
"zero knowledge" is not used anywhere in this project because it would be false.

**Observable to the relay operator:**
- Which account and device sent to which account and device
- Session identifiers linking a conversation's traffic over time
- Timing and frequency of every message
- **Padded length**: messages are padded before encryption (block-256 by default), so the relay sees a
  size bucket, not the exact length. Expansion after that is a constant 57 bytes. Measured leakage is in
  `research/RESULTS.md` E1. The first message of each session is larger (PQXDH header)
- Ratchet cadence and per-chain message counts
- Delivery and acknowledgement state
- Which one-time prekeys were consumed, and when
- IP address, connection times, client-visible TLS metadata

**Not observable:**
- Message content
- Any session, root, chain, or message key
- Any private key
- Safety numbers or verification state

## The social graph is exposed

Routing metadata reveals who talks to whom and when. For many users this is as
sensitive as content. Helo pads message sizes, but does **not** implement sealed sender, cover
traffic, or mixing. A traffic-analysis adversary is not defended against.

## Media on the device

Voice messages are recorded on the device and encrypted like any attachment before upload. The relay
sees only ciphertext size. Playing audio or video needs the decrypted media in a form the platform player
accepts:
- **web:** an in-memory Blob URL, revoked when the player closes;
- **mobile/desktop:** a temporary plaintext file in the app's temp directory, deleted when the player
  closes, and also deleted after a recording is read back. A crash during playback can leave that file
  until the OS clears its temp directory.

Verification QR codes are decoded on the device by a pure-Dart decoder. Camera frames and images are
never uploaded, and no decoder script is loaded from a CDN.

## Retention

Enforced by `sweep()` in `backend/src/db.js`, not merely documented:

| Data | Retention |
|---|---|
| Acknowledged messages | **Deleted immediately** |
| Undelivered messages | 30 days, then deleted |
| Consumed one-time prekeys | 7 days (consumption record only) |
| Expired auth tokens | 24 hours |
| Account and device records | Until account deletion |

A delivered ciphertext has no further purpose on the relay, and retaining it
only enlarges what a future compromise yields.

## Encrypted storage does not solve metadata privacy

This deserves stating plainly because it is commonly elided: encrypting message
bodies at rest does nothing for the metadata columns beside them. The
`messages` table stores opaque ciphertext, but `recipient_device`,
`sender_device`, `queued_at`, and `size_bytes` are all plainly readable and are
jointly sufficient to reconstruct a communication graph with timing.

## Data classification

Every schema column is classified in `backend/src/db.js` as PUBLIC, METADATA,
CRYPTO, CIPHERTEXT, or SECRET, so an audit can enumerate exposure per field.

## Logging

Both the client and relay loggers use an **allowlist**: a field not explicitly
declared safe is redacted. There is no `raw` escape hatch. Identifiers appear
in logs only as truncated hashes. Access logs deliberately never include request
bodies — a body log would write user ciphertext into log aggregation, where
access control is typically weaker than the database's.

## User-facing honesty requirements

The client must not imply protection it does not provide:
- Encryption status must never be shown as "verified" on the basis of
  encryption alone. Encryption authenticates keys, not people.
- A three-DH downgrade (exhausted one-time prekeys) must be surfaced.
- An identity change must warn, and must not be dismissible by simply marking
  the contact verified.
