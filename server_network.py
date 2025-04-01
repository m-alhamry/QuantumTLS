# Imports modules for OS operations, networking, logging, and timing
import os
import socket
import logging
import time
from typing import Dict, Tuple

# Imports cryptographic and network-related classes and utilities
from server_crypto import ServerCrypto
from cryptography.hazmat.primitives.serialization import Encoding
from utils import (
    ALERT_DESCRIPTIONS, EXTENSION_SUPPORTED_VERSIONS, LEGACY_VERSION, TLS_VERSION_1_3,
    BaseNetwork, ALERT_CLOSE_NOTIFY, KYBER_PK_LENGTHS, receive_exact,
    encode_extension, decode_extensions
)

class ServerNetwork(BaseNetwork):
    """
    Manages server-side network communication for a TLS 1.3-like protocol.

    Attributes:
        ip: IP address to bind the server to.
        port: Port number to listen on.
        server_socket: Listening socket for incoming connections.
        conn: Socket for a specific client connection.
        addr: Client address (set during connection).
        cipher_suite: Negotiated cipher suite with the client.
        crypto: Cryptographic object (set during operations).
        logger: Logger inherited from BaseNetwork.
    """
    def __init__(self, ip: str, port: int, logger: logging.Logger):
        # Initialize base class and server-specific attributes
        super().__init__(logger)
        self.ip = ip
        self.port = port
        self.server_socket = None
        self.conn = None
        self.addr = None
        self.cipher_suite = None
        self.crypto = None

    def setup(self) -> None:
        """Set up the server socket to listen for incoming connections."""
        # Create a TCP socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set receive buffer size to 16KB
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16384)
        # Bind and listen
        self.server_socket.bind((self.ip, self.port))
        self.server_socket.listen(5)
        self.logger.info(f"Server listening on {self.ip}:{self.port}")

    def negotiate_cipher_suite(self) -> str:
        """
        Negotiate the cipher suite with the client.

        Returns:
            str: Agreed-upon cipher suite.

        Raises:
            ValueError: If client proposes an unsupported suite or message is invalid.
        """
        start = time.perf_counter()
        header = receive_exact(self.conn, 1)
        if header[0] == self.ALERT_TYPE:
            alert_type, desc = self.receive_alert()
            raise ValueError(f"Client alert: {desc} ({alert_type:02x})")
        if header[0] != self.MSG_TYPE_HANDSHAKE:
            raise ValueError(f"Expected handshake, got {header[0]:02x}")
        receive_exact(self.conn, 2)
        length = int.from_bytes(receive_exact(self.conn, 4), 'big')
        supported = receive_exact(self.conn, length).decode('utf-8')
        # Check if the suite is supported
        supported_suites = list(KYBER_PK_LENGTHS.keys()) + ["TLS_AES_256_GCM_SHA384"]
        if supported not in supported_suites:
            raise ValueError(f"Unsupported cipher suite: {supported}")
        self.cipher_suite = supported
        # Send confirmation back to client
        self.conn.send(bytes([self.MSG_TYPE_HANDSHAKE]) + LEGACY_VERSION + len(supported).to_bytes(4, 'big') + supported.encode('utf-8'))
        self.logger.info(f"Negotiated cipher suite: {supported} in {time.perf_counter() - start:.6f} seconds")
        return supported

    def receive_client_hello(self, use_hybrid: bool) -> Dict[str, bytes]:
        """
        Receive and process the ClientHello message.

        Args:
            use_hybrid: True to expect a Kyber public key.

        Returns:
            Dict[str, bytes]: Client's handshake data (random, ecc_pk, kyber_pk, cert, transcript).

        Raises:
            ValueError: If message is invalid or client does not support TLS 1.3.
        """
        start = time.perf_counter()
        header = receive_exact(self.conn, 1)
        if header[0] == self.ALERT_TYPE:
            alert_type, desc = self.receive_alert()
            raise ValueError(f"Client alert: {desc} ({alert_type:02x})")
        if header[0] != self.MSG_TYPE_HANDSHAKE:
            raise ValueError(f"Expected ClientHello, got {header[0]:02x}")
        version = receive_exact(self.conn, 2)
        if version != LEGACY_VERSION:
            raise ValueError(f"Expected legacy version 0x0303, got {version.hex()}")
        length = int.from_bytes(receive_exact(self.conn, 4), 'big')
        data = receive_exact(self.conn, length)
        transcript = data
        # Parse ClientHello data
        random = data[:32]
        key_start = 32
        ecc_pk_len = 97
        if use_hybrid:
            kyber_pk_len = KYBER_PK_LENGTHS[self.cipher_suite]
            ecc_pk = data[key_start:key_start + ecc_pk_len]
            kyber_pk = data[key_start + ecc_pk_len:key_start + ecc_pk_len + kyber_pk_len]
            cert_start = key_start + ecc_pk_len + kyber_pk_len
        else:
            ecc_pk = data[key_start:key_start + ecc_pk_len]
            kyber_pk = b""
            cert_start = key_start + ecc_pk_len
        cert_len = int.from_bytes(data[cert_start:cert_start + 4], 'big')
        cert_bytes = data[cert_start + 4:cert_start + 4 + cert_len]
        # Parse extensions
        ext_len = int.from_bytes(data[cert_start + 4 + cert_len:cert_start + 6 + cert_len], 'big')
        ext_data = data[cert_start + 6 + cert_len:cert_start + 6 + cert_len + ext_len]
        extensions = decode_extensions(ext_data)
        # Verify TLS 1.3 support
        supports_tls_1_3 = False
        for ext_type, ext_value in extensions:
            if ext_type == EXTENSION_SUPPORTED_VERSIONS:
                versions_len = ext_value[0]
                versions = ext_value[1:1 + versions_len]
                if TLS_VERSION_1_3 in [versions[i:i+2] for i in range(0, len(versions), 2)]:
                    supports_tls_1_3 = True
        if not supports_tls_1_3:
            raise ValueError("Client does not support TLS 1.3")
        self.logger.info(f"Received ClientHello in {time.perf_counter() - start:.6f} seconds")
        return {"random": random, "ecc_pk": ecc_pk, "kyber_pk": kyber_pk, "cert": cert_bytes, "transcript": transcript}

    def send_server_hello(self, crypto: ServerCrypto, client_hello: Dict[str, bytes], use_hybrid: bool, kyber_ct: bytes | None) -> None:
        """
        Send the ServerHello message to the client.

        Args:
            crypto: Provides keys and certificate.
            client_hello: Client's handshake data (unused here but kept for context).
            use_hybrid: True to include Kyber ciphertext.
            kyber_ct: Kyber ciphertext or None if not hybrid.
        """
        start = time.perf_counter()
        random = os.urandom(32)
        key_share = crypto.ecc_public_key_bytes + (kyber_ct if use_hybrid else b"")
        cert_bytes = crypto.cert.public_bytes(Encoding.PEM)
        # Build extensions
        extensions = bytearray()
        extensions.extend(encode_extension(EXTENSION_SUPPORTED_VERSIONS, TLS_VERSION_1_3))
        ext_length = len(extensions).to_bytes(2, 'big')
        data = random + key_share + len(cert_bytes).to_bytes(4, 'big') + cert_bytes + ext_length + extensions
        message = bytes([self.MSG_TYPE_HANDSHAKE]) + LEGACY_VERSION + len(data).to_bytes(4, 'big') + data
        self.conn.send(message)
        crypto.handshake_transcript.extend(data)
        self.logger.info(f"Sent ServerHello in {time.perf_counter() - start:.6f} seconds")

    def send_certificate_verify(self, crypto: ServerCrypto) -> None:
        """
        Send the CertificateVerify message to the client.

        Args:
            crypto: Provides the signature.
        """
        start = time.perf_counter()
        signature = crypto.compute_certificate_verify()
        data = len(signature).to_bytes(2, 'big') + signature
        message = bytes([self.MSG_TYPE_HANDSHAKE]) + LEGACY_VERSION + len(data).to_bytes(4, 'big') + data
        self.conn.send(message)
        crypto.handshake_transcript.extend(message)
        self.logger.info(f"Sent CertificateVerify in {time.perf_counter() - start:.6f} seconds")

    def receive_client_certificate_verify(self, crypto: ServerCrypto, client_cert: bytes) -> None:
        """
        Receive and verify the client's CertificateVerify message.

        Args:
            crypto: Verifies the signature.
            client_cert: Client's certificate for verification.

        Raises:
            ValueError: If message is invalid or verification fails.
        """
        start = time.perf_counter()
        header = receive_exact(self.conn, 1)
        if header[0] == self.ALERT_TYPE:
            alert_type, desc = self.receive_alert()
            raise ValueError(f"Client alert: {desc} ({alert_type:02x})")
        if header[0] != self.MSG_TYPE_HANDSHAKE:
            raise ValueError(f"Expected CertificateVerify, got {header[0]:02x}")
        receive_exact(self.conn, 2)
        length = int.from_bytes(receive_exact(self.conn, 4), 'big')
        data = receive_exact(self.conn, length)
        sig_len = int.from_bytes(data[:2], 'big')
        signature = data[2:2 + sig_len]
        
        # Snapshot transcript before updating
        transcript_snapshot = bytes(crypto.handshake_transcript)
        message = header + LEGACY_VERSION + len(data).to_bytes(4, 'big') + data
        crypto.handshake_transcript.extend(message)
        if not crypto.verify_certificate_verify(signature, client_cert, transcript_snapshot):
            raise ValueError("Client CertificateVerify verification failed")
        self.logger.info(f"Verified Client CertificateVerify in {time.perf_counter() - start:.6f} seconds")

    def receive_client_finished(self, crypto: ServerCrypto) -> None:
        """
        Receive and verify the client's Finished message.

        Args:
            crypto: Decrypts and verifies the message.

        Raises:
            ValueError: If message is invalid or verification fails.
        """
        start = time.perf_counter()
        header = receive_exact(self.conn, 1)
        if header[0] == self.ALERT_TYPE:
            alert_type, desc = self.receive_alert()
            raise ValueError(f"Client alert: {desc} ({alert_type:02x})")
        if header[0] != self.MSG_TYPE_HANDSHAKE:
            raise ValueError(f"Expected ClientFinished, got {header[0]:02x}")
        receive_exact(self.conn, 2)
        length = int.from_bytes(receive_exact(self.conn, 4), 'big')
        data = receive_exact(self.conn, length)
        iv, ct = data[:12], data[12:]
        decrypted = crypto.decrypt_message(iv, ct)
        if not crypto.verify_finished_message(decrypted):
            raise ValueError("Client Finished verification failed")
        crypto.handshake_transcript.extend(header + LEGACY_VERSION + len(data).to_bytes(4, 'big') + data)
        self.logger.info(f"Verified Client Finished in {time.perf_counter() - start:.6f} seconds")

    def send_server_finished(self, crypto: ServerCrypto) -> None:
        """
        Send the encrypted Server Finished message to the client.

        Args:
            crypto: Provides the Finished message and encryption.
        """
        start = time.perf_counter()
        finished = crypto.compute_finished_message()
        iv, ct = crypto.encrypt_message(finished)
        message = bytes([self.MSG_TYPE_HANDSHAKE]) + LEGACY_VERSION + len(iv + ct).to_bytes(4, 'big') + iv + ct
        self.conn.send(message)
        crypto.handshake_transcript.extend(message)
        crypto.is_handshake_phase = False
        self.logger.info(f"Sent Server Finished in {time.perf_counter() - start:.6f} seconds")

    def receive_application_data(self, crypto: ServerCrypto) -> Dict[str, bytes]:
        """
        Receive and decrypt application data from the client.

        Args:
            crypto: Decrypts the data.

        Returns:
            Dict[str, bytes]: Dictionary with 'type' ('application' or 'end_session') and optionally 'data'.

        Raises:
            ValueError: If message is invalid or an alert is received.
            ConnectionError: If connection closes unexpectedly.
        """
        self.crypto = crypto
        start = time.perf_counter()
        header = receive_exact(self.conn, 1)
        if not header:
            raise ConnectionError("Client closed connection unexpectedly")
        if header[0] == self.ALERT_TYPE:
            alert_type, desc = self._receive_alert_with_header(header)
            if alert_type == ALERT_CLOSE_NOTIFY:
                return {"type": "end_session"}
            raise ValueError(f"Client alert: {desc} ({alert_type:02x})")
        if header[0] != self.MSG_TYPE_APPLICATION:
            raise ValueError(f"Expected application data, got {header[0]:02x}")
        receive_exact(self.conn, 2)
        length = int.from_bytes(receive_exact(self.conn, 4), 'big')
        data = receive_exact(self.conn, length)
        if data == b"END_SESSION":
            return {"type": "end_session"}
        iv, ct = data[:12], data[12:]
        plaintext = crypto.decrypt_message(iv, ct)
        self.logger.info(f"Received application data (length: {len(plaintext)} bytes) in {time.perf_counter() - start:.6f} seconds")
        return {"type": "application", "data": plaintext}

    def send_application_data(self, crypto: ServerCrypto, response: bytes) -> None:
        """
        Send encrypted application data to the client.

        Args:
            crypto: Encrypts the data.
            response: Data to send.
        """
        start = time.perf_counter()
        iv, ct = crypto.encrypt_message(response)
        self.conn.send(bytes([self.MSG_TYPE_APPLICATION]) + LEGACY_VERSION + len(iv + ct).to_bytes(4, 'big') + iv + ct)
        self.logger.info(f"Sent application data (length: {len(response)} bytes) in {time.perf_counter() - start:.6f} seconds")

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
            version = receive_exact(self.conn, 2)
            if version != LEGACY_VERSION:
                raise ValueError(f"Invalid alert version: {version.hex()}")
            length = int.from_bytes(receive_exact(self.conn, 4), 'big')
            data = receive_exact(self.conn, length)
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
        """Close the server connection and listening socket."""
        if self.conn:
            self.conn.close()
        if self.server_socket:
            self.server_socket.close()
        self.logger.info("Server connection closed")