import os
import socket
import logging
import struct
import time
from typing import Dict, List, Tuple

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_pem_x509_certificate

from client_crypto import ClientCrypto
from errors import TLSError
from utils import (
    ALERT_ACCESS_DENIED, ALERT_BAD_CERTIFICATE, ALERT_DECODE_ERROR, ALERT_DESCRIPTIONS,
    ALERT_HANDSHAKE_FAILURE, ALERT_ILLEGAL_PARAMETER, ALERT_PROTOCOL_VERSION, ALERT_UNEXPECTED_MESSAGE, ALERT_CLOSE_NOTIFY, ALERT_INTERNAL_ERROR,
    EXTENSION_KEY_SHARE, EXTENSION_SIGNATURE_ALGORITHMS, EXTENSION_SUPPORTED_VERSIONS,
    LEGACY_VERSION, MAX_PLAINTEXT_SIZE, STATE_CLIENT_APPLICATION, STATE_CLIENT_INIT,
    STATE_CLIENT_RECEIVED_SERVER_CERT_VERIFY, STATE_CLIENT_RECEIVED_SERVER_FINISHED,
    STATE_CLIENT_RECEIVED_SERVER_HELLO, STATE_CLIENT_SENT_CERT_VERIFY, STATE_CLIENT_SENT_FINISHED,
    STATE_CLIENT_SENT_HELLO, SUPPORTED_SIGNATURE_ALGORITHMS, TLS_VERSION_1_3, BaseNetwork,
    encode_key_share_client_hello, encode_signature_algorithms, receive_exact,
    EXTENSION_SERVER_NAME, EXTENSION_SUPPORTED_GROUPS, EXTENSION_ALPN, GROUP_SECP384R1,
    GROUP_KYBER512, GROUP_KYBER768, GROUP_KYBER1024, encode_extension, decode_extensions
)

class ClientNetwork(BaseNetwork):
    """
    Manages client-side network communication for a TLS 1.3-like protocol.

    Attributes:
        ip (str): Server IP address.
        port (int): Server port number.
        ca_cert: CA certificate for server verification.
        crypto (ClientCrypto, optional): Cryptographic object (set during operations).
        sock (socket.socket, optional): Socket for network communication.
        logger (logging.Logger): Logger inherited from BaseNetwork.
        handshake_state (int): Current state of the handshake process.
    """
    def __init__(self, ip: str, port: int, logger: logging.Logger, ca_cert):
        super().__init__(logger)
        self.ip = ip
        self.port = port
        self.ca_cert = ca_cert
        self.crypto = None
        self.sock = None
        self.handshake_state = STATE_CLIENT_INIT

    def connect(self) -> None:
        """
        Establish a connection to the server with retry logic.

        Raises:
            TLSError: If connection fails due to socket errors or timeout after retries.
        """
        for attempt in range(3):
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16384)
                self.sock.settimeout(10.0)
                self.sock.connect((self.ip, self.port))
                self.sock.settimeout(None)
                self.logger.info(f"Connected to {self.ip}:{self.port}")
                return
            except socket.gaierror as e:
                raise TLSError(f"Address resolution failed: {e}", ALERT_INTERNAL_ERROR, self.logger, None)
            except socket.timeout as e:
                if attempt < 2:
                    self.logger.debug(f"Connection attempt {attempt + 1} timed out, retrying in 1 second")
                    time.sleep(1)
                else:
                    raise TLSError(f"Connection timed out after 3 attempts: {e}", ALERT_ACCESS_DENIED, self.logger, None)
            except ConnectionRefusedError as e:
                if attempt < 2:
                    self.logger.debug(f"Connection attempt {attempt + 1} refused, retrying in 1 second")
                    time.sleep(1)
                else:
                    raise TLSError(f"Connection refused after 3 attempts: {e}", ALERT_ACCESS_DENIED, self.logger, None)
            except socket.error as e:
                raise TLSError(f"Socket error during connection: {e}", ALERT_INTERNAL_ERROR, self.logger, None)

    def negotiate_cipher_suite(self, supported_suites: List[str]) -> str:
        """
        Negotiate the cipher suite with the server.

        Args:
            supported_suites (List[str]): List of supported cipher suites.

        Returns:
            str: Server's chosen cipher suite.

        Raises:
            TLSError: If negotiation fails due to network or parsing errors.
        """
        start = time.perf_counter()
        suites_str = ",".join(supported_suites)
        data = suites_str.encode('utf-8')
        self.logger.debug(f"Sending supported cipher suites: {supported_suites}")

        try:
            self.sock.send(bytes([self.MSG_TYPE_HANDSHAKE]) + LEGACY_VERSION + len(data).to_bytes(4, 'big') + data)
        except socket.error as e:
            raise TLSError(f"Failed to send cipher suites: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

        try:
            header = receive_exact(self.sock, 1)
            if header[0] != self.MSG_TYPE_HANDSHAKE:
                raise TLSError(f"Expected handshake response, got {header[0]:02x}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
            receive_exact(self.sock, 2)  # Skip version
            length = int.from_bytes(receive_exact(self.sock, 4), 'big')
            server_choice = receive_exact(self.sock, length).decode('utf-8')
            self.logger.debug(f"Server chose cipher suite: {server_choice}")
        except ConnectionError as e:
            raise TLSError(f"Connection closed during cipher suite negotiation: {e}", ALERT_CLOSE_NOTIFY, self.logger, self)
        except socket.error as e:
            raise TLSError(f"Socket error during cipher suite negotiation: {e}", ALERT_INTERNAL_ERROR, self.logger, self)
        except UnicodeDecodeError as e:
            raise TLSError(f"Failed to decode server choice: {e}", ALERT_DECODE_ERROR, self.logger, self)

        if server_choice not in supported_suites:
            raise TLSError(f"Server chose an unsupported suite: {server_choice}", ALERT_ILLEGAL_PARAMETER, self.logger, self)

        self.logger.info(f"Negotiated cipher suite: {server_choice} in {time.perf_counter() - start:.6f} seconds")
        return server_choice

    def send_client_hello(self, crypto: ClientCrypto, use_hybrid: bool) -> None:
        """
        Send the ClientHello message to initiate the handshake.

        Args:
            crypto (ClientCrypto): Provides keys and certificate.
            use_hybrid (bool): True to include Kyber key share.

        Raises:
            TLSError: If state is invalid or sending fails.
        """
        if self.handshake_state != STATE_CLIENT_INIT:
            raise TLSError("Attempted to send ClientHello out of order", ALERT_UNEXPECTED_MESSAGE, self.logger, self)

        self.logger.debug("Sending ClientHello")
        random = os.urandom(32)
        cert_bytes = crypto.cert.public_bytes(Encoding.PEM)

        # Build extensions
        extensions = bytearray()
        try:
            # Supported versions extension
            extensions.extend(encode_extension(EXTENSION_SUPPORTED_VERSIONS, b"\x02" + TLS_VERSION_1_3))
            # Server Name Indication (SNI) extension
            sni = b"example.com"
            sni_data = b"\x00\x00" + len(sni).to_bytes(2, 'big') + sni
            extensions.extend(encode_extension(EXTENSION_SERVER_NAME, sni_data))
            # Supported groups extension
            groups = [GROUP_SECP384R1]
            if use_hybrid:
                groups.extend([GROUP_KYBER512, GROUP_KYBER768, GROUP_KYBER1024])
            group_data = b"".join(g.to_bytes(2, 'big') for g in groups)
            extensions.extend(encode_extension(EXTENSION_SUPPORTED_GROUPS, group_data))
            # ALPN extension
            alpn_protocols = b"\x04http"
            extensions.extend(encode_extension(EXTENSION_ALPN, alpn_protocols))
            # Signature Algorithms extension
            sig_alg_data = encode_signature_algorithms(SUPPORTED_SIGNATURE_ALGORITHMS)
            extensions.extend(encode_extension(EXTENSION_SIGNATURE_ALGORITHMS, sig_alg_data))
            # Key Share extension
            key_shares = [(GROUP_SECP384R1, crypto.ecc_public_key_bytes)]
            if use_hybrid:
                kyber_group = {
                    "TLS_AES_256_GCM_SHA384_Kyber512": GROUP_KYBER512,
                    "TLS_AES_256_GCM_SHA384_Kyber768": GROUP_KYBER768,
                    "TLS_AES_256_GCM_SHA384_Kyber1024": GROUP_KYBER1024,
                }.get(crypto.cipher_suite)
                key_shares.append((kyber_group, crypto.kyber_pk))
            key_share_extension = encode_key_share_client_hello(key_shares)
            extensions.extend(key_share_extension)
        except Exception as e:
            raise TLSError(f"Failed to build ClientHello extensions: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

        # Combine data
        ext_length = len(extensions).to_bytes(2, 'big')
        data = random + len(cert_bytes).to_bytes(4, 'big') + cert_bytes + ext_length + extensions
        message = bytes([self.MSG_TYPE_HANDSHAKE]) + LEGACY_VERSION + len(data).to_bytes(4, 'big') + data
        
        try:
            self.sock.send(message)
        except socket.error as e:
            raise TLSError(f"Failed to send ClientHello: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

        crypto.handshake_transcript.extend(data)
        self.handshake_state = STATE_CLIENT_SENT_HELLO

    def receive_server_hello(self, crypto: ClientCrypto, use_hybrid: bool) -> Dict[str, bytes]:
        """
        Receive and process the ServerHello message.

        Args:
            crypto (ClientCrypto): Updates transcript and verifies certificate.
            use_hybrid (bool): True to expect Kyber ciphertext.

        Returns:
            Dict[str, bytes]: Server's handshake data (random, ecc_pk, kyber_ct, cert).

        Raises:
            TLSError: If message is invalid, state is incorrect, or verification fails.
        """
        if self.handshake_state != STATE_CLIENT_SENT_HELLO:
            raise TLSError("Received ServerHello out of order", ALERT_UNEXPECTED_MESSAGE, self.logger, self)

        self.crypto = crypto
        self.logger.debug("Receiving ServerHello")

        try:
            header = receive_exact(self.sock, 1)
        except ConnectionError as e:
            raise TLSError(f"Server closed connection unexpectedly: {e}", ALERT_CLOSE_NOTIFY, self.logger, self)
        except socket.error as e:
            raise TLSError(f"Socket error receiving ServerHello header: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

        if header[0] == self.ALERT_TYPE:
            alert_type, desc = self._receive_alert_with_header(header)
            raise TLSError(f"Server alert: {desc}", alert_type, self.logger, self)
        if header[0] != self.MSG_TYPE_HANDSHAKE:
            raise TLSError(f"Expected ServerHello, got {header[0]:02x}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)

        try:
            version = receive_exact(self.sock, 2)
            if version != LEGACY_VERSION:
                raise TLSError(f"Expected legacy version 0x0303, got {version.hex()}", ALERT_PROTOCOL_VERSION, self.logger, self)
            length = int.from_bytes(receive_exact(self.sock, 4), 'big')
            data = receive_exact(self.sock, length)
        except ConnectionError as e:
            raise TLSError(f"Connection closed during ServerHello: {e}", ALERT_CLOSE_NOTIFY, self.logger, self)
        except socket.error as e:
            raise TLSError(f"Socket error receiving ServerHello: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

        crypto.handshake_transcript.extend(data)
        
        # Parse ServerHello data
        try:
            random = data[:32]
            pos = 32
            cert_len = int.from_bytes(data[pos:pos + 4], 'big')
            pos += 4
            cert_bytes = data[pos:pos + cert_len]
            pos += cert_len
            ext_len = int.from_bytes(data[pos:pos + 2], 'big')
            pos += 2
            ext_data = data[pos:pos + ext_len]
            extensions = decode_extensions(ext_data)
        except Exception as e:
            raise TLSError(f"Failed to parse ServerHello: {e}", ALERT_DECODE_ERROR, self.logger, self)

        # Extract and validate Key Share extension
        key_shares = []
        for ext_type, ext_value in extensions:
            if ext_type == EXTENSION_KEY_SHARE:
                offset = 0
                while offset < len(ext_value):
                    try:
                        group, key_len = struct.unpack("!HH", ext_value[offset:offset+4])
                        key_exchange = ext_value[offset+4:offset+4+key_len]
                        key_shares.append((group, key_exchange))
                        offset += 4 + key_len
                    except struct.error as e:
                        raise TLSError(f"Failed to unpack Key Share extension: {e}", ALERT_DECODE_ERROR, self.logger, self)
                break
        if not key_shares:
            raise TLSError("ServerHello missing Key Share extension", ALERT_HANDSHAKE_FAILURE, self.logger, self)

        # Process key shares
        ecc_pk = b""
        kyber_ct = b""
        if use_hybrid:
            if len(key_shares) != 2:
                raise TLSError("Expected two key shares for hybrid mode", ALERT_HANDSHAKE_FAILURE, self.logger, self)
            for group, key_exchange in key_shares:
                if group == GROUP_SECP384R1:
                    ecc_pk = key_exchange
                elif group in [GROUP_KYBER512, GROUP_KYBER768, GROUP_KYBER1024]:
                    kyber_ct = key_exchange
            if not ecc_pk or not kyber_ct:
                raise TLSError("Missing ECC or Kyber key share in hybrid mode", ALERT_HANDSHAKE_FAILURE, self.logger, self)
        else:
            if len(key_shares) != 1 or key_shares[0][0] != GROUP_SECP384R1:
                raise TLSError("Expected single ECC key share for non-hybrid mode", ALERT_HANDSHAKE_FAILURE, self.logger, self)
            ecc_pk = key_shares[0][1]

        # Verify server certificate
        server_cert = load_pem_x509_certificate(cert_bytes)
        try:
            ca_public_key = self.ca_cert.public_key()
            ca_public_key.verify(server_cert.signature, server_cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA384()))
            self.logger.info("Verified server certificate against CA")
        except Exception as e:
            raise TLSError(f"Invalid server certificate: {e}", ALERT_BAD_CERTIFICATE, self.logger, self)

        # Check supported versions
        selected_version = None
        for ext_type, ext_value in extensions:
            if ext_type == EXTENSION_SUPPORTED_VERSIONS:
                if len(ext_value) != 2 or ext_value != TLS_VERSION_1_3:
                    raise TLSError(f"Server selected unsupported version: {ext_value.hex()}", ALERT_PROTOCOL_VERSION, self.logger, self)
                selected_version = ext_value
        if not selected_version:
            raise TLSError("ServerHello missing supported_versions extension", ALERT_HANDSHAKE_FAILURE, self.logger, self)

        self.handshake_state = STATE_CLIENT_RECEIVED_SERVER_HELLO
        return {"random": random, "ecc_pk": ecc_pk, "kyber_ct": kyber_ct, "cert": cert_bytes}

    def send_certificate_verify(self, crypto: ClientCrypto) -> None:
        """
        Send the CertificateVerify message to the server.

        Args:
            crypto (ClientCrypto): Provides the signature.

        Raises:
            TLSError: If state is invalid or sending fails.
        """
        if self.handshake_state != STATE_CLIENT_RECEIVED_SERVER_CERT_VERIFY:
            raise TLSError("Attempted to send CertificateVerify out of order", ALERT_UNEXPECTED_MESSAGE, self.logger, self)

        self.logger.debug("Sending CertificateVerify")
        try:
            signature = crypto.compute_certificate_verify()
        except TLSError as e:
            raise  # Propagate TLSError from compute_certificate_verify

        data = len(signature).to_bytes(2, 'big') + signature
        message = bytes([self.MSG_TYPE_HANDSHAKE]) + LEGACY_VERSION + len(data).to_bytes(4, 'big') + data

        try:
            self.sock.send(message)
        except socket.error as e:
            raise TLSError(f"Failed to send CertificateVerify: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

        crypto.handshake_transcript.extend(message)
        self.handshake_state = STATE_CLIENT_SENT_CERT_VERIFY

    def receive_server_certificate_verify(self, crypto: ClientCrypto, server_cert: bytes) -> None:
        """
        Receive and verify the server's CertificateVerify message.

        Args:
            crypto (ClientCrypto): Verifies the signature.
            server_cert (bytes): Server's certificate for verification.

        Raises:
            TLSError: If message is invalid or verification fails.
        """
        if self.handshake_state != STATE_CLIENT_RECEIVED_SERVER_HELLO:
            raise TLSError("Received CertificateVerify out of order", ALERT_UNEXPECTED_MESSAGE, self.logger, self)

        self.logger.debug("Receiving CertificateVerify")
        try:
            header = receive_exact(self.sock, 1)
        except ConnectionError as e:
            raise TLSError(f"Connection closed receiving CertificateVerify: {e}", ALERT_CLOSE_NOTIFY, self.logger, self)
        except socket.error as e:
            raise TLSError(f"Socket error receiving CertificateVerify: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

        if header[0] == self.ALERT_TYPE:
            alert_type, desc = self._receive_alert_with_header(header)
            raise TLSError(f"Server alert: {desc}", alert_type, self.logger, self)
        if header[0] != self.MSG_TYPE_HANDSHAKE:
            raise TLSError(f"Expected CertificateVerify, got {header[0]:02x}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)

        try:
            receive_exact(self.sock, 2)  # Skip version
            length = int.from_bytes(receive_exact(self.sock, 4), 'big')
            data = receive_exact(self.sock, length)
            sig_len = int.from_bytes(data[:2], 'big')
            signature = data[2:2 + sig_len]
        except ConnectionError as e:
            raise TLSError(f"Connection closed during CertificateVerify: {e}", ALERT_CLOSE_NOTIFY, self.logger, self)
        except socket.error as e:
            raise TLSError(f"Socket error receiving CertificateVerify data: {e}", ALERT_INTERNAL_ERROR, self.logger, self)
        except ValueError as e:
            raise TLSError(f"Malformed CertificateVerify message: {e}", ALERT_DECODE_ERROR, self.logger, self)

        transcript_snapshot = bytes(crypto.handshake_transcript)
        message = header + LEGACY_VERSION + len(data).to_bytes(4, 'big') + data
        crypto.handshake_transcript.extend(message)

        try:
            if not crypto.verify_certificate_verify(signature, server_cert, transcript_snapshot):
                raise TLSError("Server CertificateVerify verification failed", ALERT_BAD_CERTIFICATE, self.logger, self)
        except TLSError as e:
            raise  # Propagate TLSError from verify_certificate_verify

        self.handshake_state = STATE_CLIENT_RECEIVED_SERVER_CERT_VERIFY

    def send_finished(self, crypto: ClientCrypto) -> None:
        """
        Send the encrypted Finished message to the server.

        Args:
            crypto (ClientCrypto): Provides the Finished message and encryption.

        Raises:
            TLSError: If state is invalid or sending fails.
        """
        if self.handshake_state != STATE_CLIENT_SENT_CERT_VERIFY:
            raise TLSError("Attempted to send Finished out of order", ALERT_UNEXPECTED_MESSAGE, self.logger, self)

        self.logger.debug("Sending Finished")
        try:
            finished = crypto.compute_finished_message()
            seq_bytes, iv, ct = crypto.encrypt_message(finished)
        except TLSError as e:
            raise  # Propagate TLSError from crypto methods

        message = bytes([self.MSG_TYPE_HANDSHAKE]) + LEGACY_VERSION + len(iv + ct).to_bytes(4, 'big') + iv + ct

        try:
            self.sock.send(message)
        except socket.error as e:
            raise TLSError(f"Failed to send Finished message: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

        crypto.handshake_transcript.extend(message)
        self.handshake_state = STATE_CLIENT_SENT_FINISHED

    def receive_server_finished(self, crypto: ClientCrypto) -> None:
        """
        Receive and verify the server's Finished message.

        Args:
            crypto (ClientCrypto): Decrypts and verifies the message.

        Raises:
            TLSError: If message is invalid or verification fails.
        """
        if self.handshake_state != STATE_CLIENT_SENT_FINISHED:
            raise TLSError("Received Server Finished out of order", ALERT_UNEXPECTED_MESSAGE, self.logger, self)

        self.logger.debug("Receiving Finished")
        try:
            header = receive_exact(self.sock, 1)
        except ConnectionError as e:
            raise TLSError(f"Connection closed receiving Finished: {e}", ALERT_CLOSE_NOTIFY, self.logger, self)
        except socket.error as e:
            raise TLSError(f"Socket error receiving Finished: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

        if header[0] == self.ALERT_TYPE:
            alert_type, desc = self._receive_alert_with_header(header)
            raise TLSError(f"Server alert: {desc}", alert_type, self.logger, self)
        if header[0] != self.MSG_TYPE_HANDSHAKE:
            raise TLSError(f"Expected ServerFinished, got {header[0]:02x}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)

        try:
            receive_exact(self.sock, 2)  # Skip version
            length = int.from_bytes(receive_exact(self.sock, 4), 'big')
            data = receive_exact(self.sock, length)
            iv, ct = data[:12], data[12:]
        except ConnectionError as e:
            raise TLSError(f"Connection closed during Finished: {e}", ALERT_CLOSE_NOTIFY, self.logger, self)
        except socket.error as e:
            raise TLSError(f"Socket error receiving Finished data: {e}", ALERT_INTERNAL_ERROR, self.logger, self)
        except ValueError as e:
            raise TLSError(f"Malformed Finished message: {e}", ALERT_DECODE_ERROR, self.logger, self)

        try:
            decrypted = crypto.decrypt_message(b'', iv, ct)
            if not crypto.verify_finished_message(decrypted):
                raise TLSError("Server Finished verification failed", ALERT_HANDSHAKE_FAILURE, self.logger, self)
        except TLSError as e:
            raise  # Propagate TLSError from decrypt_message or verify_finished_message

        crypto.handshake_transcript.extend(header + LEGACY_VERSION + len(data).to_bytes(4, 'big') + data)
        self.handshake_state = STATE_CLIENT_RECEIVED_SERVER_FINISHED
        crypto.is_handshake_phase = False

    def send_application_data(self, crypto: ClientCrypto, plaintext: bytes) -> None:
        """
        Send encrypted application data to the server.

        Args:
            crypto (ClientCrypto): Encrypts the data.
            plaintext (bytes): Data to send.

        Raises:
            TLSError: If state is invalid or sending fails.
        """
        if self.handshake_state != STATE_CLIENT_APPLICATION:
            raise TLSError("Attempted to send application data before handshake completion",
                           ALERT_UNEXPECTED_MESSAGE, self.logger, self)

        self.logger.debug(f"Sending application data (length: {len(plaintext)} bytes)")
        chunks = [plaintext[i:i + MAX_PLAINTEXT_SIZE] for i in range(0, len(plaintext), MAX_PLAINTEXT_SIZE)]

        for i, chunk in enumerate(chunks):
            is_last = 1 if i == len(chunks) - 1 else 0
            try:
                seq_bytes, iv, ct = crypto.encrypt_message(chunk)
            except TLSError as e:
                raise  # Propagate TLSError from encrypt_message

            flag = bytes([is_last])
            data = seq_bytes + iv + ct + flag
            try:
                self.sock.send(bytes([self.MSG_TYPE_APPLICATION]) + LEGACY_VERSION + len(data).to_bytes(2, 'big') + data)
            except socket.error as e:
                raise TLSError(f"Failed to send application data: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

    def receive_application_data(self, crypto: ClientCrypto) -> bytes:
        """
        Receive and decrypt application data from the server.

        Args:
            crypto (ClientCrypto): Decrypts the data.

        Returns:
            bytes: Decrypted response.

        Raises:
            TLSError: If message is invalid or decryption fails.
        """
        if self.handshake_state != STATE_CLIENT_APPLICATION:
            raise TLSError("Received application data before handshake completion",
                           ALERT_UNEXPECTED_MESSAGE, self.logger, self)

        full_plaintext = bytearray()
        while True:
            try:
                header = receive_exact(self.sock, 1)
            except ConnectionError as e:
                raise TLSError(f"Server closed connection unexpectedly: {e}", ALERT_CLOSE_NOTIFY, self.logger, self)
            except socket.error as e:
                raise TLSError(f"Socket error receiving application data: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

            if header[0] == self.ALERT_TYPE:
                alert_type, desc = self._receive_alert_with_header(header)
                if alert_type == ALERT_CLOSE_NOTIFY:
                    return b"END_SESSION"
                raise TLSError(f"Server alert: {desc}", alert_type, self.logger, self)
            if header[0] != self.MSG_TYPE_APPLICATION:
                raise TLSError(f"Expected application data, got {header[0]:02x}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)

            try:
                receive_exact(self.sock, 2)  # Skip version
                length = int.from_bytes(receive_exact(self.sock, 2), 'big')
                data = receive_exact(self.sock, length)
                seq_bytes = data[:8]
                iv = data[8:20]
                flag = data[-1:]
                ct = data[20:-1]
            except ConnectionError as e:
                raise TLSError(f"Connection closed during application data: {e}", ALERT_CLOSE_NOTIFY, self.logger, self)
            except socket.error as e:
                raise TLSError(f"Socket error receiving application data: {e}", ALERT_INTERNAL_ERROR, self.logger, self)
            except ValueError as e:
                raise TLSError(f"Malformed application data: {e}", ALERT_DECODE_ERROR, self.logger, self)

            try:
                plaintext_chunk = crypto.decrypt_message(seq_bytes, iv, ct)
            except TLSError as e:
                raise  # Propagate TLSError from decrypt_message

            full_plaintext.extend(plaintext_chunk)
            if flag == b"\x01":
                break

        return bytes(full_plaintext)

    def _receive_alert_with_header(self, header: bytes) -> Tuple[int, str]:
        """
        Helper method to receive an alert when the header is already read.

        Args:
            header (bytes): Pre-read alert header.

        Returns:
            Tuple[int, str]: Alert type and description.

        Raises:
            TLSError: If alert is malformed or decryption fails.
        """
        if header[0] != self.ALERT_TYPE:
            raise TLSError(f"Expected alert, got {header[0]:02x}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)

        try:
            version = receive_exact(self.sock, 2)
            if version != LEGACY_VERSION:
                raise TLSError(f"Invalid alert version: {version.hex()}", ALERT_PROTOCOL_VERSION, self.logger, self)
            length = int.from_bytes(receive_exact(self.sock, 4), 'big')
            data = receive_exact(self.sock, length)
        except ConnectionError as e:
            self.logger.info("Connection closed during alert")
            return ALERT_CLOSE_NOTIFY, "Connection closed"
        except socket.error as e:
            raise TLSError(f"Socket error receiving alert: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

        try:
            if self.crypto and not self.crypto.is_handshake_phase:
                if length < 8 + 12:
                    raise TLSError("Encrypted alert too short", ALERT_DECODE_ERROR, self.logger, self)
                seq_bytes = data[:8]
                iv = data[8:20]
                ct = data[20:]
                alert_data = self.crypto.decrypt_message(seq_bytes, iv, ct)
                self.logger.debug(f"Decrypted alert with seq_bytes: {seq_bytes.hex()}")
            else:
                alert_data = data
                self.logger.debug(f"Received unencrypted alert: {alert_data.hex()}")
            alert_type = alert_data[0]
            description = alert_data[1:].decode('utf-8', errors='ignore')
        except TLSError as e:
            raise  # Propagate TLSError from decrypt_message
        except Exception as e:
            raise TLSError(f"Failed to process alert: {e}", ALERT_DECODE_ERROR, self.logger, self)

        self.logger.info(f"Received alert: {ALERT_DESCRIPTIONS.get(alert_type, 'Unknown')} ({alert_type:02x}) - {description}")
        return alert_type, description

    def close(self) -> None:
        """Close the client socket connection."""
        if self.sock:
            try:
                self.sock.close()
            except socket.error as e:
                self.logger.warning(f"Error closing socket: {e}")
        self.logger.info("Client connection closed")