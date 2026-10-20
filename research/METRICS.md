# Metrics

## Padding (E1)

Let *n* be a payload length and *p(n)* the padded length a policy produces. Every policy appends the 0x80 marker, so *p(n) ≥ n + 1*.

| Metric | Definition | Better |
|---|---|---|
| mean overhead (B) | mean of *p(n) − n* over the distribution | lower |
| overhead % | Σ(*p(n) − n*) / Σ*n* × 100 | lower |
| max overhead ratio | max *p(n) / n* | lower |
| distinct sizes | number of different *p(n)* values the relay can observe | lower |
| leakage (bits) | Shannon entropy H(*p(n)*) of the observed size under the distribution. Padding is deterministic, so this equals the mutual information I(*n*; *p(n)*): how many bits about the true length one message reveals | lower |
| mean anonymity set | average, over observed sizes, of the number of distinct input lengths that map to that size | higher |

The leakage and anonymity figures depend on the input distribution. They describe the distributions in E1, not real users.

## Handshake (E2)

| Metric | Definition |
|---|---|
| initiator time | wall-clock time for `start_as_initiator` plus the first `encrypt` |
| responder time | wall-clock time for `start_as_responder` plus the first `decrypt` |
| median / p95 | median and 95th percentile over 300 runs, after 3 discarded warm-up runs |
| bundle bytes | compact JSON of the prekey bundle as the relay serves it |
| first envelope bytes | compact JSON of the first message, including the key-agreement header |
| header bytes | compact JSON of the `x3dh` header alone (it carries `pq.ct` for the hybrid protocol) |
| prekey upload bytes | compact JSON of one device's upload: signed prekey plus 100 one-time prekeys, plus a PQ last-resort key and 20 PQ one-time keys for hybrid |

## Metadata (E3)

| Metric | Definition |
|---|---|
| column classes | count of `db.js` columns by their comment tag: CIPHERTEXT, CRYPTO (public keys and signatures), SECRET (hashes, salts, push tokens), METADATA, PUBLIC, or UNCLASSIFIED when untagged |
| observed graph | sender account → recipient account edges recoverable by joining `messages` to `devices` and `accounts` while messages are queued |
| stored sizes | `messages.size_bytes`, the size of the envelope JSON as stored, per message |
| rows after delivery | row count of every table once all recipients have fetched and acknowledged |

## Verification (V)

A suite is **PASS** only if its runner exited 0, at least one test was parsed, and no parsed test failed.
It is **FAIL** otherwise, **NOT RUN** if its tool is missing or it was skipped, and **BLOCKED** if a prerequisite is missing (for example, Node for suites that start the relay).
