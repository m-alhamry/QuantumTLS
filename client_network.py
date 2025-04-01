# Imports modules for OS operations, networking, logging, and timing
import os
import socket
import logging
import time
from typing import Dict, Tuple

# Imports cryptographic and network-related classes and utilities
from client_crypto import ClientCrypto
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_pem_x509_certificate
from utils import (
    ALERT_DESCRIPTIONS, EXTENSION_SUPPORTED_VERSIONS, LEGACY_VERSION, TLS_VERSION_1_3,
    BaseNetwork, ALERT_CLOSE_NOTIFY, KYBER_CT_LENGTHS, receive_exact,
    EXTENSION_SERVER_NAME, EXTENSION_SUPPORTED_GROUPS, EXTENSION_ALPN,
    GROUP_SECP384R1, GROUP_KYBER512, GROUP_KYBER768, GROUP_KYBER1024,
    encode_extension, decode_extensions
)

class ClientNetwork(BaseNetwork):
    """
    Manages client-side network communication for a TLS 1.3-like protocol.

    Attributes:
        ip: Server IP address to connect to.
        port: Server port number.
        ca_cert: CA certificate for server verification.
        crypto: Cryptographic object (set during operations).
        sock: Socket for network communication.
        logger: Logger inherited from BaseNetwork.
    """
    def __init__(self, ip: str, port: int, logger: logging.Logger):
        # Initialize base class and client-specific attributes
        super().__init__(logger)
        self.ip = ip
        self.port = port
        self.ca_cert = None
        self.crypto = None
        self._load_ca_certificate()

    def _load_ca_certificate(self) -> None:
        """Load the CA certificate for server certificate verification."""
        with open("ca.crt", "rb") as f:
            self.ca_cert = load_pem_x509_certificate(f.read())
        self.logger.info("Loaded CA certificate for server verification")

    def connect(self) -> None:
        """
        Establish a connection to the server with retry logic.

        Raises:
            ConnectionRefusedError: If connection fails after 3 attempts.
        """
        for attempt in range(3):
            try:
                # Create a new TCP socket
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # Set receive buffer size to 16KB
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16384)
                # Set a 10-second timeout for connection
                self.sock.settimeout(10.0)
                self.sock.connect((self.ip, self.port))
                # Disable timeout after connection is established
                self.sock.settimeout(None)
                self.logger.info(f"Connected to {self.ip}:{self.port}")
                return
            except ConnectionRefusedError as e:
                if attempt < 2:
                    self.logger.debug(f"Connection attempt {attempt + 1} failed, retrying in 1 second")
                    time.sleep(1)
                else:
                    self.logger.error(f"Failed to connect after 3 attempts: {e}")
                    raise

    def negotiate_cipher_suite(self, chosen_suite: str) -> None:
        """
        Negotiate the cipher suite with the server.

        Args:
            chosen_suite: Cipher suite selected by the client.

        Raises:
            ValueError: If server rejects the chosen suite or message is invalid.
        """
        start = time.perf_counter()
        # Encode the chosen cipher suite
        data = chosen_suite.encode('utf-8')
        # Send handshake message with type, version, length, and data
        self.sock.send(bytes([self.MSG_TYPE_HANDSHAKE]) + LEGACY_VERSION + len(data).to_bytes(4, 'big') + data)
        # Receive server response
        header = receive_exact(self.sock, 1)
        if header[0] != self.MSG_TYPE_HANDSHAKE:
            raise ValueError(f"Expected handshake response, got {header[0]:02x}")
        receive_exact(self.sock, 2)  # Skip version
        length = int.from_bytes(receive_exact(self.sock, 4), 'big')
        server_choice = receive_exact(self.sock, length).decode('utf-8')
        # Verify server agrees with client's choice
        if server_choice != chosen_suite:
            raise ValueError(f"Server rejected {chosen_suite}, chose {server_choice}")
        duration = time.perf_counter() - start
        self.logger.info(f"Negotiated cipher suite: {server_choice} in {duration:.6f} seconds")

    def send_client_hello(self, crypto: ClientCrypto, use_hybrid: bool) -> None:
        """
        Send the ClientHello message to initiate the handshake.

        Args:
            crypto: Provides keys and certificate.
            use_hybrid: True to include Kyber key share.
        """
        start = time.perf_counter()
        # Generate 32-byte random data
        random = os.urandom(32)
        # Combine ECC and optionally Kyber public keys
        key_share = crypto.ecc_public_key_bytes + (crypto.kyber_pk if use_hybrid else b"")
        cert_bytes = crypto.cert.public_bytes(Encoding.PEM)
        
        # Build extensions
        extensions = bytearray()
        # Supported versions extension with TLS 1.3
        extensions.extend(encode_extension(EXTENSION_SUPPORTED_VERSIONS, b"\x02" + TLS_VERSION_1_3))
        # Server Name Indication (SNI) extension
        sni = b"example.com"
        sni_data = b"\x00\x00" + len(sni).to_bytes(2, 'big') + sni
        extensions.extend(encode_extension(EXTENSION_SERVER_NAME, sni_data))
        # Supported groups (curves and Kyber variants)
        groups = [GROUP_SECP384R1]
        if use_hybrid:
            groups.extend([GROUP_KYBER512, GROUP_KYBER768, GROUP_KYBER1024])
        group_data = b"".join(g.to_bytes(2, 'big') for g in groups)
        extensions.extend(encode_extension(EXTENSION_SUPPORTED_GROUPS, group_data))
        # Application-Layer Protocol Negotiation (ALPN) extension
        alpn_protocols = b"\x04http"
        extensions.extend(encode_extension(EXTENSION_ALPN, alpn_protocols))

        # Combine all data with extension length
        ext_length = len(extensions).to_bytes(2, 'big')
        data = random + key_share + len(cert_bytes).to_bytes(4, 'big') + cert_bytes + ext_length + extensions
        message = bytes([self.MSG_TYPE_HANDSHAKE]) + LEGACY_VERSION + len(data).to_bytes(4, 'big') + data
        self.sock.send(message)
        # Update handshake transcript
        crypto.handshake_transcript.extend(data)
        self.logger.info(f"Sent ClientHello in {time.perf_counter() - start:.6f} seconds")

    def receive_server_hello(self, crypto: ClientCrypto, use_hybrid: bool) -> Dict[str, bytes]:
        """
        Receive and process the ServerHello message.

        Args:
            crypto: Updates transcript and verifies certificate.
            use_hybrid: True to expect Kyber ciphertext.

        Returns:
            Dict[str, bytes]: Server's handshake data (random, ecc_pk, kyber_ct, cert).

        Raises:
            ValueError: If message is invalid or certificate verification fails.
        """
        self.crypto = crypto
        start = time.perf_counter()
        header = receive_exact(self.sock, 1)
        if not header:
            raise ValueError("Server closed connection unexpectedly")
        if header[0] == self.ALERT_TYPE:
            alert_type, desc = self.receive_alert()
            raise ValueError(f"Server alert: {desc} ({alert_type:02x})")
        if header[0] != self.MSG_TYPE_HANDSHAKE:
            raise ValueError(f"Expected ServerHello, got {header[0]:02x}")
        version = receive_exact(self.sock, 2)
        if version != LEGACY_VERSION:
            raise ValueError(f"Expected legacy version 0x0303, got {version.hex()}")
        length = int.from_bytes(receive_exact(self.sock, 4), 'big')
        data = receive_exact(self.sock, length)
        crypto.handshake_transcript.extend(data)

        # Parse ServerHello data
        random = data[:32]
        ecc_pk_len = 97
        key_start = 32
        if use_hybrid:
            kyber_ct_len = KYBER_CT_LENGTHS[crypto.cipher_suite]
            ecc_pk = data[key_start:key_start + ecc_pk_len]
            kyber_ct = data[key_start + ecc_pk_len:key_start + ecc_pk_len + kyber_ct_len]
            cert_start = key_start + ecc_pk_len + kyber_ct_len
        else:
            ecc_pk = data[key_start:key_start + ecc_pk_len]
            kyber_ct = b""
            cert_start = key_start + ecc_pk_len
        cert_len = int.from_bytes(data[cert_start:cert_start + 4], 'big')
        cert_bytes = data[cert_start + 4:cert_start + 4 + cert_len]
        
        # Verify server certificate
        server_cert = load_pem_x509_certificate(cert_bytes)
        try:
            ca_public_key = self.ca_cert.public_key()
            ca_public_key.verify(server_cert.signature, server_cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA384()))
            self.logger.info("Verified server certificate against CA")
        except Exception as e:
            self.logger.error(f"Server certificate verification failed: {e}")
            raise ValueError(f"Invalid server certificate: {e}")

        # Parse extensions
        ext_len = int.from_bytes(data[cert_start + 4 + cert_len:cert_start + 6 + cert_len], 'big')
        ext_data = data[cert_start + 6 + cert_len:cert_start + 6 + cert_len + ext_len]
        extensions = decode_extensions(ext_data)
        
        # Check supported versions
        selected_version = None
        for ext_type, ext_value in extensions:
            if ext_type == EXTENSION_SUPPORTED_VERSIONS:
                if len(ext_value) != 2 or ext_value != TLS_VERSION_1_3:
                    raise ValueError(f"Server selected unsupported version: {ext_value.hex()}")
                selected_version = ext_value
        if not selected_version:
            raise ValueError("ServerHello missing supported_versions extension")

        duration = time.perf_counter() - start
        self.logger.info(f"Received ServerHello in {duration:.6f} seconds")
        return {"random": random, "ecc_pk": ecc_pk, "kyber_ct": kyber_ct, "cert": cert_bytes}

    def send_certificate_verify(self, crypto: ClientCrypto) -> None:
        """
        Send the CertificateVerify message to the server.

        Args:
            crypto: Provides the signature.
        """
        start = time.perf_counter()
        signature = crypto.compute_certificate_verify()
        data = len(signature).to_bytes(2, 'big') + signature
        message = bytes([self.MSG_TYPE_HANDSHAKE]) + LEGACY_VERSION + len(data).to_bytes(4, 'big') + data
        self.sock.send(message)
        crypto.handshake_transcript.extend(message)
        self.logger.info(f"Sent CertificateVerify in {time.perf_counter() - start:.6f} seconds")

    def receive_server_certificate_verify(self, crypto: ClientCrypto, server_cert: bytes) -> None:
        """
        Receive and verify the server's CertificateVerify message.

        Args:
            crypto: Verifies the signature.
            server_cert: Server's certificate for verification.

        Raises:
            ValueError: If message is invalid or verification fails.
        """
        start = time.perf_counter()
        header = receive_exact(self.sock, 1)
        if header[0] == self.ALERT_TYPE:
            alert_type, desc = self.receive_alert()
            raise ValueError(f"Server alert: {desc} ({alert_type:02x})")
        if header[0] != self.MSG_TYPE_HANDSHAKE:
            raise ValueError(f"Expected CertificateVerify, got {header[0]:02x}")
        receive_exact(self.sock, 2)
        length = int.from_bytes(receive_exact(self.sock, 4), 'big')
        data = receive_exact(self.sock, length)
        sig_len = int.from_bytes(data[:2], 'big')
        signature = data[2:2 + sig_len]
        
        # Snapshot transcript before updating
        transcript_snapshot = bytes(crypto.handshake_transcript)
        message = header + LEGACY_VERSION + len(data).to_bytes(4, 'big') + data
        crypto.handshake_transcript.extend(message)
        if not crypto.verify_certificate_verify(signature, server_cert, transcript_snapshot):
            raise ValueError("Server CertificateVerify verification failed")
        self.logger.info(f"Verified Server CertificateVerify in {time.perf_counter() - start:.6f} seconds")

    def send_finished(self, crypto: ClientCrypto) -> None:
        """
        Send the encrypted Finished message to the server.

        Args:
            crypto: Provides the Finished message and encryption.
        """
        start = time.perf_counter()
        finished = crypto.compute_finished_message()
        iv, ct = crypto.encrypt_message(finished)
        message = bytes([self.MSG_TYPE_HANDSHAKE]) + LEGACY_VERSION + len(iv + ct).to_bytes(4, 'big') + iv + ct
        self.sock.send(message)
        crypto.handshake_transcript.extend(message)
        self.logger.info(f"Sent Finished message in {time.perf_counter() - start:.6f} seconds")

    def receive_server_finished(self, crypto: ClientCrypto) -> None:
        """
        Receive and verify the server's Finished message.

        Args:
            crypto: Decrypts and verifies the message.

        Raises:
            ValueError: If message is invalid or verification fails.
        """
        start = time.perf_counter()
        header = receive_exact(self.sock, 1)
        if header[0] == self.ALERT_TYPE:
            alert_type, desc = self.receive_alert()
            raise ValueError(f"Server alert: {desc} ({alert_type:02x})")
        if header[0] != self.MSG_TYPE_HANDSHAKE:
            raise ValueError(f"Expected ServerFinished, got {header[0]:02x}")
        receive_exact(self.sock, 2)
        length = int.from_bytes(receive_exact(self.sock, 4), 'big')
        data = receive_exact(self.sock, length)
        iv, ct = data[:12], data[12:]
        decrypted = crypto.decrypt_message(iv, ct)
        if not crypto.verify_finished_message(decrypted):
            raise ValueError("Server Finished verification failed")
        crypto.handshake_transcript.extend(header + LEGACY_VERSION + len(data).to_bytes(4, 'big') + data)
        crypto.is_handshake_phase = False
        self.logger.info(f"Verified Server Finished in {time.perf_counter() - start:.6f} seconds")

    def send_application_data(self, crypto: ClientCrypto, plaintext: bytes) -> None:
        """
        Send encrypted application data to the server.

        Args:
            crypto: Encrypts the data.
            plaintext: Data to send.
        """
        start = time.perf_counter()
        iv, ct = crypto.encrypt_message(plaintext)
        self.sock.send(bytes([self.MSG_TYPE_APPLICATION]) + LEGACY_VERSION + len(iv + ct).to_bytes(4, 'big') + iv + ct)
        self.logger.info(f"Sent application data (length: {len(plaintext)} bytes) in {time.perf_counter() - start:.6f} seconds")

    def receive_application_data(self, crypto: ClientCrypto) -> bytes:
        """
        Receive and decrypt application data from the server.

        Args:
            crypto: Decrypts the data.

        Returns:
            bytes: Decrypted response.

        Raises:
            ValueError: If message is invalid or an alert is received.
        """
        self.crypto = crypto
        start = time.perf_counter()
        header = receive_exact(self.sock, 1)
        if header[0] == self.ALERT_TYPE:
            alert_type, desc = self._receive_alert_with_header(header)
            if alert_type == ALERT_CLOSE_NOTIFY:
                return b"END_SESSION"
            raise ValueError(f"Server alert: {desc} ({alert_type:02x})")
        if header[0] != self.MSG_TYPE_APPLICATION:
            raise ValueError(f"Expected application data, got {header[0]:02x}")
        receive_exact(self.sock, 2)
        length = int.from_bytes(receive_exact(self.sock, 4), 'big')
        data = receive_exact(self.sock, length)
        if data == b"END_SESSION":
            return b"END_SESSION"
        iv, ct = data[:12], data[12:]
        plaintext = crypto.decrypt_message(iv, ct)
        self.logger.info(f"Received application data (length: {len(plaintext)} bytes) in {time.perf_counter() - start:.6f} seconds")
        return plaintext

    def _receive_alert_with_header(self, header: bytes) -> Tuple[int, str]:
        """
        Helper method to receive an alert when the header is already read.

        Args:
            header: Pre-read alert header.

        Returns:
            Tuple[int, str]: Alert type and description.

        Raises:
            ValueError: If alert is malformed.
        """
        try:
            if header[0] != self.ALERT_TYPE:
                raise ValueError(f"Expected alert, got {header[0]:02x}")
            version = receive_exact(self.sock, 2)
            if version != LEGACY_VERSION:
                raise ValueError(f"Invalid alert version: {version.hex()}")
            length = int.from_bytes(receive_exact(self.sock, 4), 'big')
            data = receive_exact(self.sock, length)
            if self.crypto and not self.crypto.is_handshake_phase and length >= 12:
                iv, ct = data[:12], data[12:]
                alert_data = self.crypto.decrypt_message(iv, ct)
            else:
                alert_data = data
            alert_type = alert_data[0]
            description = alert_data[1:].decode('utf-8', errors='ignore')
            self.logger.info(f"Received alert: {ALERT_DESCRIPTIONS.get(alert_type, 'Unknown')} ({alert_type:02x}) - {description}")
            return alert_type, description
        except ConnectionError:
            self.logger.info("Connection closed during alert")
            return ALERT_CLOSE_NOTIFY, "Connection closed"

    def close(self) -> None:
        """Close the client socket connection."""
        if self.sock:
            self.sock.close()
            self.logger.info("Client connection closed")