# Security

## Reporting a vulnerability

Report privately. Do not open a public issue.

**This is a research and portfolio implementation. It has not been
independently audited and should not be used to protect real communications.**

## Security properties

Every claimed property is mapped to a named passing test in
**[SECURITY_CLAIMS.md](SECURITY_CLAIMS.md)** using the format:

> Claim → Mechanism → Test → Evidence → Limitation

Properties that are architecturally intended but not demonstrated are listed
there under **Not Yet Claimed** rather than in the claims table. The rule is:
*if a property is not backed by a named, passing test, it is not claimed.*

Summary of what is claimed:

| Property | Status |
|---|---|
| Content confidentiality vs. relay | ✅ demonstrated against a running relay |
| Integrity and authentication | ✅ property-tested over every bit position |
| Metadata authentication | ✅ header covered by AEAD associated data |
| Forward secrecy | ✅ with two tested exceptions |
| Post-compromise security | ✅ requires a healing round trip |
| Replay resistance | ✅ three independent layers |
| Out-of-order / offline delivery | ✅ arbitrary permutations |
| Bounded resource consumption | ✅ checked before derivation |
| Fail-closed behaviour | ✅ no plaintext fallback exists |
| Identity verification | 🟡 detectable, but TOFU on first contact |
| Metadata privacy | ❌ not provided — enumerated in PRIVACY.md |
| Post-quantum security | ❌ not implemented, not claimed |

## Running the security tests

```bash
python3 -m pytest tests/adversarial -q     # active attacker
python3 -m pytest tests/property -q        # property-based
python3 scripts/integration_e2e.py         # real relay + DB inspection
python3 scripts/generate_test_vectors.py --check
cd backend && node --test test/
```

## Hardening notes for operators

- Terminate TLS in front of the relay; it speaks plain HTTP by design.
- Run the container read-only with `no-new-privileges` and all capabilities
  dropped (see `docker/docker-compose.yml`).
- The relay must not be on a public network; only the reverse proxy should be.
- Never enable request-body logging. It would write user ciphertext into log
  aggregation.
- Rotate the database volume's backing storage encryption independently; the
  relay's ciphertext is opaque, but its metadata is not.

## What a relay compromise yields

Metadata, not content. See THREAT_MODEL.md §T5 and PRIVACY.md. Treat it as a
serious privacy incident even though no message plaintext is exposed — the
communication graph with timing is recoverable.
