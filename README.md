# QuantumTLS / QTL2 research prototype

QuantumTLS demonstrates a custom authenticated channel using P-384 ECDH, optional Kyber or ML-KEM key encapsulation, ECDSA certificates, AES-256-GCM, and SHA-384. **QTL2 is not TLS 1.3 and does not interoperate with TLS/OpenSSL or the original QTL protocol.** It is a research prototype, not a production security library. Authentication remains classical ECDSA even when key establishment is hybrid.

The security audit required a breaking protocol revision: direction-specific traffic keys, authenticated framing, keyed Finished messages, strict peer identity validation, and explicit handshake acceptance. Both endpoints must be upgraded together. See [SECURITY.md](SECURITY.md) for findings, credential migration, and remaining limitations, and [PROTOCOL.md](PROTOCOL.md) for the wire format.

## Setup Instructions

### 1. Prerequisites

Run commands from the repository root. Use Python **3.10 or newer** on macOS or Linux; the local validation used Python 3.12. Git, CMake, and a C compiler are required to build the native OQS dependency. On macOS install the Xcode command-line tools and CMake; on Debian/Ubuntu install `build-essential cmake git libssl-dev`.

### 2. Install Dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
export PYOQS_VERSION=0.16.0
python -c "import oqs; print('Native liboqs:', oqs.oqs_version()); print(oqs.get_enabled_kem_mechanisms())"
python -m pip check
```

The pinned wrapper `liboqs-python==0.16.0.1` needs native **liboqs 0.16.0**. The import above loads an installed native library or downloads/builds the matching release if none is found; finish this installation before running either endpoint. This requires network access and may take several minutes. For a custom native installation, set `OQS_INSTALL_PATH` to its installation prefix. See the [official OQS installation instructions](https://github.com/open-quantum-safe/liboqs-python#installation). A pre-existing native library must provide the requested KEMs; the full test suite exercises all six.

ECC-only operation (`--cipher 1` on both endpoints) does not import OQS or generate KEM keys. The full dependency file and tests include OQS.

### 3. Generate fresh development credentials

**Never reuse any private key from this repository's history.** Six historical CA public keys are denied by QTL2. Generate a new CA and endpoint keys in a new directory:

```bash
python -m src.generate_ca_certs --directory credentials
python -m src.generate_server_certs --directory credentials
python -m src.generate_client_certs --directory credentials
```

Generators refuse to overwrite either member of an existing key/certificate pair. Private keys use owner-only permissions (`0600`); new credential directories use `0700`. Importing generators does nothing. Development keys are unencrypted on disk, so protect the directory. Do not commit it.

The default server certificate has DNS SAN `localhost` and IP SANs `127.0.0.1` and `::1`. To issue a remote server identity, use `--dns service.example --ip 192.0.2.10` (repeat flags for additional SANs). Validation requires an exact DNS/IP SAN; wildcard certificates and CN fallback are unsupported. The listener currently supports IPv4, while the client can resolve IPv4/IPv6 addresses.

## Run

Server, in one terminal:

```bash
python -m src.server.main_server --cert-dir credentials --mutual-auth enable
```

Client, in another:

```bash
python -m src.client.main_client --cert-dir credentials --mutual-auth enable
```

Choose text (`1`), file (`2`), or authenticated closure (`3`). An empty file path selects `src/large_data.json`. Empty messages are valid; `END_SESSION` is ordinary payload. The demonstration server acknowledges each complete message. `--echo` on the server and `--expect-echo` on the client instead verify exact round-trip bytes.

A noninteractive smoke test:

```bash
python -m src.client.main_client --cert-dir credentials --mutual-auth enable \
  --test-mode --message-type 1 --message 'hello'
```

Both endpoints default to suite **6 (P-384 + ML-KEM-768)**, port `65432`, and address `127.0.0.1`. Mutual authentication defaults to disabled; enable it on **both** ends to require client authentication. A policy mismatch fails the handshake. The client validates the server even when mutual authentication is disabled.

| `--cipher` | Key establishment |
| --- | --- |
| 1 | P-384 ECDH only |
| 2 | P-384 + legacy Kyber512 |
| 3 | P-384 + legacy Kyber768 |
| 4 | P-384 + legacy Kyber1024 |
| 5 | P-384 + ML-KEM-512 |
| 6 | P-384 + ML-KEM-768 (default) |
| 7 | P-384 + ML-KEM-1024 |

The server enforces its selected suite. The client offers only its configured suite by default; repeat `--cipher` to explicitly allow several. There is no automatic fallback to ECC. Historical Python suite labels beginning with `TLS_` are retained identifiers, not claims of TLS interoperability. Kyber options remain for experiments; they are distinct from standardized ML-KEM.

Common options: `--ip`, `--port`, `--cert-dir`, `--log-dir`, `--handshake-timeout`, `--message-timeout`, and `--mutual-auth enable|disable`. The client accepts `--server-name` for the expected certificate identity when connecting to an IP. The server accepts `--max-connections` (default 16). Use `--help` for all options. Failures exit nonzero.

For remote use, provision only `ca.crt`, `server.crt`, and `server.key` to the server; provision `ca.crt` plus the client's own `client.crt` and `client.key` to an authenticated client. A server-authentication-only client needs just `ca.crt`. Keep `ca.key` with the issuer, away from both endpoints. Authenticate the initial distribution of the new trust root independently.

## Bounds and logs

- Handshake deadline: 10 seconds, covering all handshake I/O.
- Each complete application message: 30 seconds to send or receive, including partial reads; idle receivers expire at that deadline.
- Message limit: 8 MiB, chunks at most 16 KiB, at most 4096 chunks.
- Maximum 16 active server workers by default; shutdown interrupts their sockets and bounds joins to 5 seconds.
- Reconnect after `2**20` records per direction/key epoch; there is no key-update protocol.
- Logs are created under `logs/`, with a shared server log rather than per-connection handlers. Each log rotates at 2 MiB with three backups. Default INFO logging excludes message payloads, private keys, and traffic secrets.

## Tests

```bash
python -m unittest discover -s tests -v
# Or individual layers:
python -m unittest discover -s tests/unit -v
python -m unittest discover -s tests/integration -v
python -m unittest discover -s tests/e2e -v
```

Tests issue disposable credentials in temporary directories and never replace developer credentials. Integration tests require permission to bind localhost ports. The suite covers all seven suites with both authentication modes, exact chunk-boundary/1 MiB payloads, replay/reflection/tampering, certificate policy, every truncation of representative hello messages, TCP proxy corruption, deadlines/connection caps, parallel CLI clients, nonzero failure exits, and same-port restart. CI runs on Python 3.10 and 3.12; a green local run does not imply that hosted CI has run.

Licensed under [Apache 2.0](LICENSE).
