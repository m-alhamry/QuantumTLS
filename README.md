# ecc_kyber_hybrid_encryption

This repository contains a prototype implementation of a TLS 1.3-like protocol with support for hybrid ECC+Kyber key exchange. It is designed for testing and educational purposes, demonstrating secure client-server communication with mutual authentication and post-quantum cryptography integration. The implementation includes both client and server components, cryptographic utilities, and certificate generation scripts.


## Features

- **TLS 1.3-like Handshake**: Implements a simplified version of the TLS 1.3 handshake with mutual authentication.

- **Cipher Suites**: Supports `TLS_AES_256_GCM_SHA384` and hybrid variants with Kyber (Kyber512, Kyber768, Kyber1024).

- **Post-Quantum Cryptography**: Integrates Kyber key encapsulation mechanism (KEM) using `liboqs-python`.

- **Mutual Authentication**: Uses ECC-based certificates signed by a local CA.

- **Encrypted Communication**: Employs AES-GCM for handshake and application data encryption.

- **Logging**: Detailed logging for debugging and performance analysis.

## Prerequisites

### **Python 3.x**

### **Dependencies**:

- `cryptography` (for ECC and AES-GCM)

- `open-quantum-safe/liboqs-python` (for Kyber KEM)


## Setup Instructions

### 1. Clone the Repository

```bash
    git clone https://github.com/m-alhamry/QuantumTLS
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

## Setup

### Certificate Generation

Before running the client and server, generate the necessary certificates using the provided scripts. Run them in the following order:

1. **`generate_ca_certs.py`** 

- Generates the Certificate Authority (CA) certificate (`ca.crt`) and key (`ca.key`).  

2. **`generate_server_certs.py`**  

- Generates the server certificate (`server.crt`) and key (`server.key`), signed by the CA.  

3. **`generate_client_certs.py`** 

- Generates the client certificate (`client.crt`) and key (`client.key`), signed by the CA.  

Example:

```bash
    python3 generate_ca_certs.py
    python3 generate_server_certs.py
    python3 generate_client_certs.py
```

## Local Environment Testing

To test the prototype locally on a single machine:

1. **Generate Certificates** 

- Follow the certificate generation steps above.

2. **Run the Server**

- In one terminal:

```bash
    python3 server.py
```

- Press Enter to use the default IP (127.0.0.1) and port (65432), or enter custom values.

3. **Run the Client** 

- In another terminal: 
     
```bash
    python3 client.py
```

- Press Enter to use the default server IP (127.0.0.1) and port (65432), or enter custom values.  

- Select a cipher suite when prompted (see Cipher Suites (#cipher-suites)).  

- Choose to send a typed message (1), load large_data.json (2), or exit (3).

## Remote Environment Testing

To test between two machines (e.g., a server and a client on different hosts):

1. **Prepare the Server Machine** 

- Copy the project directory to the server machine.  

- Generate certificates as described above.  

- Ensure the server’s IP address is accessible (e.g., update firewall rules).  

- Run the server:

```bash
    python3 server.py
```

- Enter the server’s IP address (e.g., 0.0.0.0 to bind to all interfaces) and a port (e.g., 65432).

2. **Prepare the Client Machine**

- Copy the project directory to the client machine.  

- Ensure ca.crt, client.crt, and client.key are in the directory.  

- Run the client: 

```bash
    python3 client.py
```

- Enter the server’s IP address and port when prompted.  

- Follow the prompts to select a cipher suite and send messages.

3. **Network Considerations**

- Ensure both machines can communicate over the specified port.  

- Use tools like ping or nc (netcat) to verify connectivity before testing.

## Running the Prototype

### Server

```bash
    python3 server.py
```

1. **Prompts for IP and port to bind (default: 127.0.0.1:65432).**  

2. **Handles multiple client connections via threading.**  

3. **Gracefully shuts down with Ctrl+C (SIGINT).**

### Client

```bash
    python3 client.py
```

1. **Prompts for server IP and port (default: 127.0.0.1:65432).**  

2. **Prompts for cipher suite selection.**  

3. **Options**:

- Type a message to send.  

- Send the contents of large_data.json.  

- Exit the session.

## Cipher Suites

The prototype supports the following cipher suites, selectable by the client:

1. **TLS_AES_256_GCM_SHA384**  

- Standard TLS 1.3 cipher suite with ECC (SECP384R1).

2. **TLS_AES_256_GCM_SHA384_Kyber512** 

- Hybrid ECC + Kyber512 key exchange.

3. **TLS_AES_256_GCM_SHA384_Kyber768** 

- Hybrid ECC + Kyber768 key exchange.

4. **TLS_AES_256_GCM_SHA384_Kyber1024**  

- Hybrid ECC + Kyber1024 key exchange.

The server negotiates the chosen cipher suite and proceeds with the handshake accordingly.

## Logging

- Logs are stored in the client.log, server.log and logs/ directory.  

- Check logs for debugging, handshake timing, and error details.

## Testing with Large Data

### Use large_data.json to test large data transfers:  

- Select option 2 in the client prompt.

- By default, if you press `enter`, the already saved large_data.json will be uploaded. Alternatively, you can use your costum data file to test.  

### The client sends the file contents, and the server responds with a confirmation message.

## Important Notes

1. **Prototype Limitations**: This is an educational and testing prototype, not intended for production use. It may contain security vulnerabilities and lacks full TLS 1.3 compliance (e.g., no padding, limited extensions).  

2. **Session Timeout**: Connections time out after 30 seconds of inactivity.  

3. **Certificates**: Ensure certificates are generated and present in the working directory (ca.crt, client.crt, client.key, server.crt, server.key).

4. **Performance**: Logs include timing for cryptographic operations and network round-trips.

5. **Kyber Variants**: Choose a cipher suite with Kyber (e.g., `TLS_AES_256_GCM_SHA384_Kyber1024`) to test post-quantum cryptography.

## Contributing

Feel free to fork this repository, submit issues, or send pull requests with improvements or bug fixes.

## License

This project is licensed under the MIT License - see the LICENSE file for details.