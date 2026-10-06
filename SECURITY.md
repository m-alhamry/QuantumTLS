# Security audit and migration

## Status

QTL2 repairs the concrete issues reproduced in the audit. It remains an experimental custom protocol. Passing tests do not establish production readiness, full TLS compliance, resistance to every attack, or the security of native dependencies. Use a maintained standard TLS implementation for production requirements.

The protocol and Python transport APIs have changed incompatibly. Upgrade both endpoints; the original protocol is deliberately rejected. Old tests were migrated to disposable credentials and the new protocol, with regression tests for the observed vulnerabilities.

## Exposed historical credentials: external action required

Private CA and endpoint keys were committed in earlier Git history. Deleting them from the current tree does not make them secret again. Any CA/leaf based on those keys is compromised even if its certificate has not expired.

The six historical CA public-key SHA-256 SPKI fingerprints are recorded in `src/utils/compromised_ca_keys.json` and rejected during trust-root loading and certificate validation. No private-key material is included in that list. Credential files, logs, and virtual environments are now ignored by Git; generators refuse overwrite and create keys with `0600` permissions.

For every previously deployed copy:

1. Generate a new CA and new endpoint keypairs in a fresh directory; never recertify an exposed private key.
2. Distribute the new CA certificate through an authenticated channel, install the new endpoint identities, and remove the old roots from every trust store.
3. Keep the CA private key offline/with the issuer. Deploy only each endpoint's own identity and public trust root.
4. Coordinate any Git-history cleanup with collaborators and repository administrators. History rewriting cannot revoke keys already copied, and is not a replacement for rotation.

This change has **not** rewritten repository history or rotated external installations. There were no current checked-in credentials to replace. Tests generate and destroy their own credentials; they do not provision deployment identities. There is no general CRL/OCSP service here: the bundled historical-root denylist is a targeted safeguard, and future compromises require explicit trust-store replacement.

## Findings and remediation

| Severity | Finding | Remediation and regression evidence |
| --- | --- | --- |
| Critical | CA and endpoint private keys exposed in history | Historical root denylist, fresh-credential workflow, ignored secrets, exclusive writes and permissions; external rotation still required. |
| High | Shared bidirectional AES keys allowed reflection | Independent directional handshake/application keys and IVs; reflection, replay, ordering, and epoch tests. |
| High | Unauthenticated record type/chunk-final metadata enabled message manipulation | Header and sequence are AEAD associated data; inner type/final marker encrypted; corruption and live TCP-proxy tests. |
| High | Finished was an unkeyed transcript hash; weak key-schedule separation | Transcript-derived role-specific secrets, HMAC Finished, separate QTL2 domain; forgery, role/transcript and key-epoch tests. |
| High | Certificate checks accepted wrong server identity or wrong EKU | Strict direct-CA profile with exact DNS/IP SAN, EKU, KU, BasicConstraints, signatures and validity; active client-certificate impersonation regression. |
| High | Unknown critical extensions/CA constraints were ignored | Reject unsupported critical extensions and unsupported root policy constraints; malformed, constrained and wrong-signer tests. |
| High | Plaintext/premature alerts and EOF confused successful closure | Protected close_notify only in application phase; `None` distinct from empty bytes or `END_SESSION`; truncation and retagging tests. |
| High | Slow/unbounded handshakes and unlimited worker creation | Absolute handshake deadline, worker cap, startup validation, bounded shutdown; live stalled-peer/cap tests. |
| High | Unbounded message accumulation and per-read timeout resets | 8 MiB/4096-chunk/record limits, total operation deadlines, incremental chunks; size/chunk/slow-read tests. |
| Medium | send() could silently perform partial writes | sendall(), exact bounded reads, propagated failures; short-read and broken-send tests. |
| Medium | Nested lengths, duplicates, unsupported fields and trailing bytes unchecked | Bounded Reader and strict hello/certificate/handshake parsers; exhaustive representative hello truncations and malformed-field tests. |
| Medium | Certificate rejection relied on a 100 ms timing guess | Explicit transcript-authenticated server ACK after client Finished; client enters application phase only after acceptance. |
| Medium | Hybrid policy silently fell back to ECC | Server requires configured suite and client explicitly offers allowed suites; mismatch regression. |
| Medium | Native KEM objects, private key references and logging handlers accumulated | Explicit KEM free on success/failure, key reference cleanup, one shared rotating server logger; cleanup and handler-bound tests. |
| Medium | Cipher identifiers/record layout falsely implied TLS interoperability | Explicit QTL2 version/magic, corrected AES-256 identifier, documented breaking format; legacy/TLS records rejected. |
| Medium | Payload snippets logged by default; unbounded files and missing log directory failures | INFO metadata only, directory creation, 2 MiB rotation/three backups; CLI payload absence and logger configuration tests. |
| Medium | Exception constructors performed network I/O and cleanup masked failures | Side-effect-free TLSError; alert emission only at connection boundary; initialized cleanup state and CLI nonzero exits. |
| Medium | Socket lifecycle bugs prevented immediate restart and delayed shutdown | SO_REUSEADDR, active socket interruption, bounded joins; same-port CLI restart with a stalled connection. |
| Medium | File messages read unboundedly; empty messages dropped | Read at most limit+1, bounded chunking, valid empty final chunk; empty/large/exact-echo tests. |
| Medium | Generators ran on import and overwrote keys; expired-cert test replaced real credentials | Main guards, exclusive non-overwriting generation, temporary test fixtures; import/overwrite/permissions and isolated-expiry regressions. |
| Medium | Tests checked log text rather than payloads, “large” payloads were below a chunk, longevity waited after exit | Exact 14-combination handshake matrix, >1-chunk and 1 MiB payloads, repeated live-session traffic, parallel real CLI processes and TCP-proxy tampering. |
| Medium | Missing dependency pins, CI and accurate setup requirements | Pinned Python dependency set, matching native OQS instructions, Python 3.10+ requirement, CI matrix and tracked-private-key check. |
| Informational | PQ claims did not distinguish legacy Kyber from ML-KEM or classical authentication | ML-KEM-768 default; explicit legacy options and disclosure that ECDSA authentication remains classical. |

## Validation scope

Local validation uses Python 3.12, cryptography 50.0.2, liboqs-python 0.16.0.1, and native liboqs 0.16.0 on macOS. Run `python -m unittest discover -s tests -v` for unit, integration and CLI tests. Native OQS must enable all six KEMs for the full matrix. CI configuration targets Linux/Python 3.10 and 3.12; hosted runs are separate from local validation.

Remaining architectural limitations include custom protocol analysis, classical authentication, unencrypted development private keys, no general revocation/path building, no key updates/resumption, no guaranteed Python secret erasure, and bounded but finite resources that an attacker can occupy. Certificate files and dependency libraries are trusted local inputs. This audit did not constitute a formal cryptographic proof, independent penetration test, or deployment/infrastructure assessment.
