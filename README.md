# QuantumTLS Prototype

QuantumTLS is a prototype implementation of a TLS 1.3 extension designed to incorporate quantum-resistant cryptography. It integrates the Kyber Key Encapsulation Mechanism (KEM) alongside traditional Elliptic Curve Cryptography (ECC) to create a hybrid cryptographic approach. This prototype aims to demonstrate how quantum-resistant algorithms can enhance the security of existing TLS frameworks, preparing them for potential quantum computing threats while maintaining compatibility with TLS 1.3 standards.

## Features

- **TLS 1.3-like Handshake**: Implements a simplified version of the TLS 1.3 handshake with mutual authentication.

- **Hybrid Cipher Suites**: Supports `TLS_AES_256_GCM_SHA384` and hybrid variants with Kyber (Kyber512, Kyber768, Kyber1024).

- **Post-Quantum Cryptography**: Integrates Kyber key encapsulation mechanism (KEM) using `liboqs-python`.

- **Mutual Authentication**: Uses ECC-based certificates signed by a local CA.

- **Encrypted Communication**: Employs AES-GCM for handshake and application data encryption.

- **Large Data Exchange**: Handles transmission of large payloads, such as JSON files.

- **Logging**: Detailed logging for debugging and performance analysis.

- **Comprehensive Testing**: Includes unit, integration, and end-to-end test suites.

## Prerequisites

To run the QuantumTLS prototype, ensure the following are installed:

### **Python 3.x**

### **Dependencies**:

- `cryptography`: Python library for ECC and AES-GCM cryptographic operations.

- `open-quantum-safe/liboqs-python`: Python bindings for the liboqs library, providing Kyber KEM support.

## Setup Instructions

### 1. Clone the Repository

Begin by cloning the QuantumTLS repository to your local machine:
```bash
    git clone https://github.com/m-alhamry/QuantumTLS.git
    cd QuantumTLS
``` 

### 2. Install Dependencies

1. **Open Quantum Safe (OQS) Library with Python Bindings** 

- Required for Kyber-based post-quantum cryptography. 

- Installation instructions: [https://github.com/open-quantum-safe/liboqs-python](https://github.com/open-quantum-safe/liboqs-python) 

- Follow the guide to install `liboqs-python` on your system.

2. **Cryptography Library**

- Used for ECC and certificate operations.  

- Install via pip:

```bash
    pip3 install cryptography
```

## Certificate Generation

Before running the client and server, generate the necessary certificates using the provided scripts. Run them in the following order:

1. **`generate_ca_certs.py`** 

- Generates the Certificate Authority (CA) certificate (`ca.crt`) and key (`ca.key`).  

2. **`generate_server_certs.py`**  

- Generates the server certificate (`server.crt`) and key (`server.key`), signed by the CA.  

3. **`generate_client_certs.py`** 

- Generates the client certificate (`client.crt`) and key (`client.key`), signed by the CA.  

Example:

```bash
    python3 -m src.generate_ca_certs
    python3 -m src.generate_server_certs
    python3 -m src.generate_client_certs
```
- Ensure the certificates and keys are placed in the specified directories:

* src/ca.crt

* src/ca.key

* src/server/server.crt

* src/server/server.key

* src/client/client.crt

* src/client/client.key

## Setting Arguments for Server and Client

The server and client scripts accept command-line arguments to configure their behavior. Below are examples and explanations:

### Server Arguments

Run the server using *python3 -m src.server.main_server* with the following options:

--ip <IP>: Server IP address (default: 127.0.0.1).

--port <PORT>: Server port (default: 65432).

--mutual-auth <enable|disable>: Enable or disable mutual authentication (default: disable).

--cipher <1-4>: Select cipher suite (default: 2):
1: TLS_AES_256_GCM_SHA384 (ECC only).

2: TLS_AES_256_GCM_SHA384_Kyber512.

3: TLS_AES_256_GCM_SHA384_Kyber768.

4: TLS_AES_256_GCM_SHA384_Kyber1024.

--test-mode: Run in test mode (do not set it, only used for automated testing).

--test-interrupt: Simulate network interruption in test mode (do not set it, only used for automated testing).

Example:

```bash
python3 -m src.server.main_server --mutual-auth enable --cipher 4
```
This starts the server with mutual authentication enabled and uses the TLS_AES_256_GCM_SHA384_Kyber1024 cipher suite.

### Client Arguments

Run the client using python3 -m src.client.main_client with these options:
--ip <IP>: Server IP address (default: 127.0.0.1).

--port <PORT>: Server port (default: 65432).

--mutual-auth <enable|disable>: Enable or disable mutual authentication (default: disable).

--test-mode: Run in test mode (do not set it, only used for automated testing).

--message-type <1-3>: Message type for test mode Run in test mode (do not set it, only used for automated testing):

1: Text message.

2: JSON file.

3: Exit.

--message <CONTENT>: Message content or file path for test mode Run in test mode (do not set it, only used for automated testing).

Example:

```bash
python3 -m src.client.main_client --mutual-auth enable --ip 127.0.0.1 --port 65432
```
This connects the client to the server at 127.0.0.1:65432 with mutual authentication enabled.

## Running the Prototype

### Local Environment Testing

To test the prototype locally on a single machine:

1. **Generate Certificates** 

- Follow the certificate generation steps above.

2. **Run the Server**

- In one terminal:

```bash
    python3 -m src.server.main_server --mutual-auth enable --cipher 4
```

- Press Enter to use the default IP (127.0.0.1) and port (65432), or enter custom values.

3. **Run the Client** 

- In another terminal: 
     
```bash
    python3 -m src.client.main_client --mutual-auth enable
```

- Press Enter to use the default server IP (127.0.0.1) and port (65432), or enter custom values.  

- Choose to send a typed message (1), send a JSON file, then provide the file path, default src/large_data.json (2), or exit (3) to terminate the session.

### Remote Environment Testing

To test between two machines (e.g., a server and a client on different hosts):

1. **Prepare the Server Machine** 

- Copy the project directory to the server machine.  

- Generate certificates as described above.  

- Ensure the server’s IP address is accessible (e.g., update firewall rules).  

- Run the server:

```bash
    python3 -m src.server.main_server --ip <server_ip> --port <port> --mutual-auth enable --cipher 4
```

- Replace <server_ip> with the server's public or network-accessible IP (e.g., 0.0.0.0 to bind to all interfaces) and replace <port> with the desired port (e.g., 65432).

2. **Prepare the Client Machine**

- Copy the project directory to the client machine.  

- Ensure ca.crt, client.crt, and client.key are in the directory.  

- Run the client: 

```bash
    python3 -m src.client.main_client --ip <server_ip> --port <port> --mutual-auth enable
```

- Use the same <server_ip> and <port> as the server.

3. **Network Considerations**

- Ensure both machines can communicate over the specified port.  

- Use tools like ping or nc (netcat) to verify connectivity before testing.

## Cipher Suites

The prototype supports the following cipher suites:

- TLS_AES_256_GCM_SHA384: Standard TLS 1.3 with ECC (cipher code 1).

- TLS_AES_256_GCM_SHA384_Kyber512: Hybrid with ECC and Kyber512 (cipher code 2).

- TLS_AES_256_GCM_SHA384_Kyber768: Hybrid with ECC and Kyber768 (cipher code 3).

- TLS_AES_256_GCM_SHA384_Kyber1024: Hybrid with ECC and Kyber1024 (cipher code 4).

The server selects a cipher suite based on its preference and the client's supported suites.

## Logging

Logs are generated for debugging and performance analysis, stored in the logs directory:

- client.log: Client-side logs.

- server.log: Server-side logs.

- server_client_<port>.log: Per-client connection logs on the server.

Logs include timestamps, log levels (e.g., DEBUG, INFO, ERROR), and detailed messages such as handshake durations and cryptographic operation timings.

## Support for Large Data Exchange

The prototype can send large data files (e.g., JSON):

- Place the file in the src directory or specify its path (e.g., src/large_data.json).

- Run the client, select option 2, and enter the file path when prompted.

- The data is transmitted in chunks (max 16KB per chunk) and reassembled by the receiver.

## Running Test Models

The prototype includes three types of tests in the tests directory:

### Unit Tests:

```bash
python3 -m unittest discover -s tests/unit
```

Tests individual components (e.g., cryptographic functions).

### Integration Tests:

```bash
python3 -m unittest discover -s tests/integration
```

Tests interactions between components (e.g., handshake).

### End-to-End Tests:

```bash
python3 -m unittest discover -s tests/e2e
```

Tests full client-server workflows, including edge cases like expired certificates and network interruptions.

**Run all tests from the root directory to ensure dependencies are resolved.**

## Important Notes

1. **Prototype Limitations**: This is an educational and testing prototype, not intended for production use. It may contain security vulnerabilities and lacks full TLS 1.3 compliance (e.g., no padding, limited extensions).  

2. **Session Timeout**: Connections time out after 30 seconds of inactivity.  

3. **Certificates**: Must be correctly generated and placed in the specified paths; mismatches or expired certificates will cause failures.

4. **Performance**: Logs include timing data for cryptographic operations and handshake completion, useful for analysis.

5. **Kyber Variants**: Offer trade-offs between security and performance:
- Kyber512: Smaller keys, lower security.
- Kyber768: Balanced option.
- Kyber1024: Larger keys, higher security.

## Contributing

Feel free to fork this repository, submit issues, or send pull requests with improvements or bug fixes. Please include tests for new features or bug fixes.

## License

This project is licensed under the MIT License - see the LICENSE file for more details.