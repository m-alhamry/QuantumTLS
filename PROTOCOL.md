# QTL2 protocol revision

This document describes this repository's custom protocol, not TLS. It is a research design without independent cryptographic review or a formal security proof. Old QTL/TLS peers are rejected at the record magic. All integers below are unsigned big-endian; `vecN(x)` is an N-byte length followed by exactly that many bytes. Parsers reject trailing data, malformed lengths, duplicates, unsupported values, and missing fields.

## Records

A header is `"QTL2" || type:u8 || payload_length:u32`. Payload length must be in `1..16416`.

Before traffic keys exist, type is handshake (`0x16`) or fatal alert (`0x15`). An unauthenticated alert can abort negotiation; it never authorizes application traffic. Once traffic keys exist, the outer type must be `0x17`, and payload is:

```
sequence:u64 || AES-256-GCM(key, nonce, inner_type:u8 || body, AAD)
AAD   = complete_record_header || sequence:u64
nonce = directional_base_IV XOR zero_extended_96_bit(sequence)
```

The GCM ciphertext includes its 16-byte tag. The receiver requires the next exact sequence number, authenticates before releasing plaintext, and increments the counter only after success. Independent send/receive keys and 12-byte IVs are derived for each epoch. Counters start at zero and stop before `2**20`; exhaustion requires reconnection. There is no KeyUpdate or resumption.

Protected inner types are handshake, application, or alert. Application body is `final:u8 || chunk`, where `final` is exactly 0 or 1. Chunks have at most 16384 data bytes; an empty chunk is valid only when final. A receiver accumulates at most 8 MiB and 4096 chunks under one absolute message deadline. The final marker and inner type are encrypted/authenticated. An empty message therefore sends one final empty chunk.

Alert bodies contain exactly one supported code. Protected application-phase `close_notify` (code 0) is the only successful end-of-stream indication. APIs return `None` for closure, and `bytes` (including empty bytes) for messages. TCP EOF, closure in a partial message, plaintext close, and premature close are errors. Connections do not support application half-close; after sending close, only peer closure is expected.

## Hellos and suite policy

A handshake message is `handshake_type:u8 || vec3(body)`. There is exactly one message per record. The transcript is the concatenation of complete typed/length-prefixed handshake messages, limited to 65536 bytes.

ClientHello (type 1):

```
version:0002 || random:32 || vec2(suite_codes) || vec2(key_share_entries)
entry = group:u16 || vec2(public_key)
```

ServerHello (type 2):

```
version:0002 || random:32 || selected_suite:u16 || vec2(key_share_entries)
```

ECC uses group `0018` and a 97-byte uncompressed P-384 point, validated on the curve. Suite `1302` denotes ECC-only within QTL2; private codes `ff01..ff06` denote Kyber512/768/1024 and ML-KEM-512/768/1024 respectively. Their private group identifiers are `ff01..ff06`. Client KEM public key sizes are 800/1184/1568 bytes; server ciphertext sizes are 768/1088/1568 bytes for each corresponding family. A hello must contain exactly ECC plus the KEM shares required by its offered/selected suites. The server selects its configured required suite only if explicitly offered. It never silently downgrades.

The client generates only the offered KEM keypairs. The server encapsulates using the client key, then frees the native KEM object. The client decapsulates and frees all its native KEM objects, including unused offers. Shared input is `vec2(ECDH_secret) || vec2(KEM_secret)`; the KEM vector is empty for ECC-only.

## Key schedule and authentication

SHA-384, HMAC-SHA384, and HKDF-SHA384 are used throughout. This schedule follows the structure described in [RFC 8446 section 7.1](https://www.rfc-editor.org/rfc/rfc8446#section-7.1) but uses the distinct `qtl2 ` label domain and QTL2 transcripts/input. It is not a standard TLS hybrid construction.

```
ExpandLabel(secret, label, context, length) = HKDF-Expand(secret,
    length:u16 || vec1("qtl2 " || label) || vec1(context), length)
DeriveSecret(secret, label, transcript) =
    ExpandLabel(secret, label, SHA384(transcript), 48)
zero = 48 zero bytes
EarlySecret = HKDF-Extract(zero, zero)
HandshakeSecret = HKDF-Extract(DeriveSecret(EarlySecret, "derived", ""), shared_input)
client_hs = DeriveSecret(HandshakeSecret, "c hs traffic", through_ServerHello)
server_hs = DeriveSecret(HandshakeSecret, "s hs traffic", through_ServerHello)
finished_key = ExpandLabel(directional_hs, "finished", "", 48)
MasterSecret = HKDF-Extract(DeriveSecret(HandshakeSecret, "derived", ""), zero)
client_app = DeriveSecret(MasterSecret, "c ap traffic", through_server_Finished)
server_app = DeriveSecret(MasterSecret, "s ap traffic", through_server_Finished)
traffic_key = ExpandLabel(directional_traffic_secret, "key", "", 32)
base_IV = ExpandLabel(directional_traffic_secret, "iv", "", 12)
```

Handshake encryption is activated only after both hellos are in the transcript. The protected server flight is empty EncryptedExtensions (8), optional empty CertificateRequest (13), Certificate (11), CertificateVerify (15), and Finished (20). The optional client authentication flight is Certificate and CertificateVerify, followed in all cases by Finished. Client/server mutual-authentication policies must match.

Certificate body is `vec1(empty_context) || vec3(vec3(single_DER_leaf) || vec2(empty_extensions))`. The certificate profile accepts exactly one leaf directly signed by the configured self-signed P-384/SHA384 CA; it is not a general path builder. It validates issuer signature, validity dates, BasicConstraints, KeyUsage, role EKU, and the server's exact DNS/IP SAN. Unknown critical extensions, CA policy/name constraints outside this profile, and known compromised CA keys are rejected. Intermediates, wildcards, CN fallback, OS trust-store discovery, CRL/OCSP, and arbitrary certificate algorithms are unsupported.

CertificateVerify body is algorithm `0503` plus `vec2(signature)`. The ECDSA/SHA384 signature input is 64 ASCII spaces, the role string `QTL2 server CertificateVerify` or `QTL2 client CertificateVerify`, a zero byte, and SHA384 of the transcript preceding this message. Received signatures are verified before appending their message to the transcript.

Finished body is `HMAC(directional_finished_key, SHA384(preceding_transcript))`. After validating and appending client Finished, the server sends protected ACK (254), using its Finished key over that updated transcript. The client verifies and appends ACK before entering application mode. This explicitly confirms client authentication/Finished acceptance. Application keys use the snapshot through server Finished on both peers; the ACK is sent under handshake keys. On application transition, handshake secrets, Finished keys, and ephemeral/certificate private key references are dropped; native KEM storage is explicitly freed. Python reference dropping does not guarantee physical memory erasure.

## Operational bounds

Defaults: 10-second absolute handshake I/O deadline; 30-second complete-message send/receive deadlines; 16 active workers; 5-second total shutdown join budget. Partial reads cannot reset operation deadlines. Native cryptographic calls and local filesystem reads are not preempted by socket timeouts. Install OQS before starting the program. Resource bounds limit this prototype's exposure but do not provide Internet-scale denial-of-service protection.
