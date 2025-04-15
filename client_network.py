import os
import socket
import logging
import struct
import time
from typing import Dict, Tuple

from cryptography.hazmat.primitives.serialization import Encoding
from client_crypto import ClientCrypto
from errors import TLSError
from utils import (
    ALERT_ACCESS_DENIED, ALERT_DECODE_ERROR, ALERT_DESCRIPTIONS, ALERT_ILLEGAL_PARAMETER, 
    ALERT_INTERNAL_ERROR, ALERT_PROTOCOL_VERSION, ALERT_TYPE, ALERT_UNEXPECTED_MESSAGE, 
    ALERT_CLOSE_NOTIFY, CIPHER_SUITE_CODES, CIPHER_SUITE_NAMES, CIPHER_SUITES, 
    EXTENSION_KEY_SHARE, EXTENSION_SIGNATURE_ALGORITHMS, EXTENSION_SUPPORTED_VERSIONS, 
    HANDSHAKE_TYPE_CERTIFICATE, HANDSHAKE_TYPE_CERTIFICATE_VERIFY, HANDSHAKE_TYPE_FINISHED, 
    LEGACY_VERSION, LENGTH_FIELD_2_BYTES, MAX_PLAINTEXT_SIZE, MSG_TYPE_APPLICATION, 
    MSG_TYPE_HANDSHAKE, SEQ_BYTES_LENGTH, SIGNATURE_ECDSA_SECP384R1_SHA384, STATE_CLIENT_APPLICATION, 
    STATE_CLIENT_INIT, HANDSHAKE_TYPE_CLIENT_HELLO, HANDSHAKE_TYPE_SERVER_HELLO, 
    EXTENSION_SERVER_NAME, EXTENSION_SUPPORTED_GROUPS, EXTENSION_ALPN, GROUP_SECP384R1, 
    GROUP_KYBER512, GROUP_KYBER768, GROUP_KYBER1024, STATE_CLIENT_RECEIVED_SERVER_HELLO, 
    STATE_CLIENT_SENT_HELLO, TLS_VERSION_1_3, SUPPORTED_SIGNATURE_ALGORITHMS, VERSION_LENGTH,
    BaseNetwork, encode_key_share_client_hello, encode_signature_algorithms, 
    receive_exact, encode_extension, decode_extensions,
    SOCKET_RECV_BUFFER_SIZE, SOCKET_CONNECT_TIMEOUT, CONNECTION_RETRY_ATTEMPTS, 
    RETRY_SLEEP_SECONDS, RANDOM_BYTES_LENGTH, DEFAULT_SNI, ALPN_HTTP, IV_LENGTH
)

class ClientNetwork(BaseNetwork):
    """Client-specific network operations for TLS 1.3 communication."""

    def __init__(self, ip: str, port: int, logger: logging.Logger, ca_cert):
        """
        Initialize the ClientNetwork instance.

        Args:
            ip: Server IP address.
            port: Server port number.
            logger: Logger instance for logging network events.
            ca_cert: CA certificate for verifying server certificates.
        """
        super().__init__(logger)
        self.ip = ip
        self.port = port
        self.ca_cert = ca_cert
        self.crypto = None
        self.sock = None
        self.handshake_state = STATE_CLIENT_INIT
        self.is_handshake_encrypted = False

    def connect(self) -> None:
        """
        Establish a connection to the server with retry logic.

        Raises:
            TLSError: If connection fails after retries.
        """
        for attempt in range(CONNECTION_RETRY_ATTEMPTS):
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_RECV_BUFFER_SIZE)
                self.sock.settimeout(SOCKET_CONNECT_TIMEOUT)
                self.sock.connect((self.ip, self.port))
                self.sock.settimeout(None)
                self.logger.info(f"Connected to {self.ip}:{self.port}")
                return
            except socket.error as e:
                if attempt < CONNECTION_RETRY_ATTEMPTS - 1:
                    self.logger.debug(f"Connection attempt {attempt + 1} failed, retrying")
                    time.sleep(RETRY_SLEEP_SECONDS)
                else:
                    raise TLSError(f"Connection failed after {CONNECTION_RETRY_ATTEMPTS} attempts: {e}", ALERT_ACCESS_DENIED, self.logger, None)

    def send_client_hello(self, crypto: ClientCrypto) -> None:
        """
        Send the ClientHello message to initiate the TLS handshake.

        Args:
            crypto: ClientCrypto instance for cryptographic operations.

        Raises:
            TLSError: If the handshake state is invalid.
        """
        if self.handshake_state != STATE_CLIENT_INIT:
            raise TLSError("ClientHello out of order", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
        
        random = os.urandom(RANDOM_BYTES_LENGTH)
        session_id = b"\x00"
        cipher_suites = b"".join(CIPHER_SUITE_CODES[suite] for suite in CIPHER_SUITES)
        cipher_suites_length = len(cipher_suites).to_bytes(LENGTH_FIELD_2_BYTES, 'big')
        compression_methods = b"\x01\x00"
        extensions = bytearray()
        
        extensions.extend(encode_extension(EXTENSION_SUPPORTED_VERSIONS, b"\x02" + TLS_VERSION_1_3))
        sni = DEFAULT_SNI
        sni_data = b"\x00\x00" + len(sni).to_bytes(LENGTH_FIELD_2_BYTES, 'big') + sni
        extensions.extend(encode_extension(EXTENSION_SERVER_NAME, sni_data))
        groups = [GROUP_SECP384R1, GROUP_KYBER512, GROUP_KYBER768, GROUP_KYBER1024]
        group_data = b"".join(g.to_bytes(LENGTH_FIELD_2_BYTES, 'big') for g in groups)
        extensions.extend(encode_extension(EXTENSION_SUPPORTED_GROUPS, group_data))
        extensions.extend(encode_extension(EXTENSION_ALPN, ALPN_HTTP))
        sig_alg_data = encode_signature_algorithms(SUPPORTED_SIGNATURE_ALGORITHMS)
        extensions.extend(encode_extension(EXTENSION_SIGNATURE_ALGORITHMS, sig_alg_data))
        key_shares = [(GROUP_SECP384R1, crypto.ecc_public_key_bytes)]
        for variant, group in zip([1, 2, 3], [GROUP_KYBER512, GROUP_KYBER768, GROUP_KYBER1024]):
            if variant in crypto.kyber_pks:
                key_shares.append((group, crypto.kyber_pks[variant]))
        extensions.extend(encode_key_share_client_hello(key_shares))
        ext_length = len(extensions).to_bytes(LENGTH_FIELD_2_BYTES, 'big')
        client_hello_body = (
            LEGACY_VERSION +
            random +
            session_id +
            cipher_suites_length + cipher_suites +
            compression_methods +
            ext_length + extensions
        )
        handshake_message = bytes([HANDSHAKE_TYPE_CLIENT_HELLO]) + len(client_hello_body).to_bytes(3, 'big') + client_hello_body
        record_layer = bytes([MSG_TYPE_HANDSHAKE]) + LEGACY_VERSION + len(handshake_message).to_bytes(2, 'big') + handshake_message
        self.sock.send(record_layer)
        crypto.handshake_transcript.extend(handshake_message)
        self.handshake_state = STATE_CLIENT_SENT_HELLO
        self.logger.debug("Sent ClientHello with %d cipher suites and %d key shares", len(CIPHER_SUITES), len(key_shares))

    def receive_server_hello(self, crypto: ClientCrypto) -> Dict[str, bytes]:
        """
        Receive and process the ServerHello message.

        Args:
            crypto: ClientCrypto instance for cryptographic operations.

        Returns:
            Dict[str, bytes]: Parsed ServerHello data.

        Raises:
            TLSError: If the message is invalid or unexpected.
        """
        header = receive_exact(self.sock, 1)
        if header[0] != MSG_TYPE_HANDSHAKE:
            raise TLSError(f"Expected handshake, got {header[0]:02x}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
        version = receive_exact(self.sock, VERSION_LENGTH)
        if version != LEGACY_VERSION:
            raise TLSError(f"Expected legacy version 0x0303, got {version.hex()}", ALERT_PROTOCOL_VERSION, self.logger, self)
        length = int.from_bytes(receive_exact(self.sock, LENGTH_FIELD_2_BYTES), 'big')
        data_with_type = receive_exact(self.sock, length)
        if data_with_type[0] != HANDSHAKE_TYPE_SERVER_HELLO:
            raise TLSError(f"Expected ServerHello, got {data_with_type[0]:02x}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
        data = data_with_type[4:]
        
        pos = 0
        legacy_version = data[pos:pos+2]
        if legacy_version != LEGACY_VERSION:
            raise TLSError(f"Invalid legacy version: {legacy_version.hex()}", ALERT_PROTOCOL_VERSION, self.logger, self)
        pos += 2
        random = data[pos:pos+RANDOM_BYTES_LENGTH]
        pos += RANDOM_BYTES_LENGTH
        session_id_len = data[pos]
        pos += 1
        session_id = data[pos:pos+session_id_len]
        pos += session_id_len
        cipher_suite = data[pos:pos+2]
        pos += 2
        compression_method = data[pos]
        if compression_method != 0:
            raise TLSError(f"Unsupported compression method: {compression_method}", ALERT_ILLEGAL_PARAMETER, self.logger, self)
        pos += 1
        extensions_len = int.from_bytes(data[pos:pos+2], 'big')
        pos += 2
        extensions_data = data[pos:pos+extensions_len]
        extensions = decode_extensions(extensions_data)
        if cipher_suite not in CIPHER_SUITE_NAMES:
            raise TLSError(f"Server selected unsupported cipher suite: {cipher_suite.hex()}", ALERT_ILLEGAL_PARAMETER, self.logger, self)
        crypto.cipher_suite = CIPHER_SUITE_NAMES[cipher_suite]
        
        kyber_ct = ecc_pk = b""
        use_hybrid = "Kyber" in crypto.cipher_suite
        kyber_group = {"TLS_AES_256_GCM_SHA384_Kyber512": GROUP_KYBER512, "TLS_AES_256_GCM_SHA384_Kyber768": GROUP_KYBER768, "TLS_AES_256_GCM_SHA384_Kyber1024": GROUP_KYBER1024}.get(crypto.cipher_suite)
        
        for ext_type, ext_value in extensions:
            if ext_type == EXTENSION_KEY_SHARE:
                offset = 0
                while offset < len(ext_value):
                    group, key_len = struct.unpack("!HH", ext_value[offset:offset+4])
                    key_exchange = ext_value[offset+4:offset+4+key_len]
                    if group == GROUP_SECP384R1:
                        ecc_pk = key_exchange
                    elif use_hybrid and group == kyber_group:
                        kyber_ct = key_exchange
                    offset += 4 + key_len
        crypto.handshake_transcript.extend(data_with_type)
        self.handshake_state = STATE_CLIENT_RECEIVED_SERVER_HELLO
        return {"random": random, "ecc_pk": ecc_pk, "kyber_ct": kyber_ct, "session_id": session_id}

    def send_encrypted_handshake_message(self, crypto: ClientCrypto, handshake_type: int, body: bytes) -> None:
        """
        Send an encrypted handshake message.

        Args:
            crypto: ClientCrypto instance for encryption.
            handshake_type: Type of the handshake message.
            body: Body of the handshake message.
        """
        handshake_message = bytes([handshake_type]) + len(body).to_bytes(3, 'big') + body
        crypto.handshake_transcript.extend(handshake_message)
        plaintext = handshake_message + b"\x16"  # Append content type byte (0x16 for handshake)
        _, iv, ct = crypto.encrypt_message(plaintext)
        record_layer = bytes([MSG_TYPE_APPLICATION]) + LEGACY_VERSION + len(iv + ct).to_bytes(2, 'big') + iv + ct
        self.sock.send(record_layer)

    def receive_encrypted_handshake_message(self, crypto: ClientCrypto) -> Tuple[int, bytes]:
        """
        Receive and decrypt an encrypted handshake message.

        Args:
            crypto: ClientCrypto instance for decryption.

        Returns:
            Tuple[int, bytes]: Handshake type and body.

        Raises:
            TLSError: If the message is invalid or decryption fails.
        """
        header = receive_exact(self.sock, 1)
        if header[0] != MSG_TYPE_APPLICATION:
            raise TLSError(f"Expected application_data (0x17), got {header[0]:02x}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
        version = receive_exact(self.sock, VERSION_LENGTH)
        if version != LEGACY_VERSION:
            raise TLSError(f"Expected legacy version 0x0303, got {version.hex()}", ALERT_PROTOCOL_VERSION, self.logger, self)
        length = int.from_bytes(receive_exact(self.sock, LENGTH_FIELD_2_BYTES), 'big')
        data = receive_exact(self.sock, length)
        iv, ct = data[:IV_LENGTH], data[IV_LENGTH:]
        decrypted = crypto.decrypt_message(b'', iv, ct)
        if len(decrypted) < 5 or decrypted[-1] != 0x16:
            raise TLSError("Invalid decrypted handshake message: missing or incorrect content type byte", ALERT_DECODE_ERROR, self.logger, self)
        handshake_message = decrypted[:-1]  # Strip content type byte
        handshake_type = handshake_message[0]
        msg_length = int.from_bytes(handshake_message[1:4], 'big')
        if len(handshake_message) != 4 + msg_length:
            raise TLSError("Invalid handshake message length", ALERT_DECODE_ERROR, self.logger, self)
        body = handshake_message[4:]
        return handshake_type, body

    def send_client_certificate(self, crypto: ClientCrypto) -> None:
        """
        Send the client's certificate to the server.

        Args:
            crypto: ClientCrypto instance containing the certificate.

        Raises:
            TLSError: If no certificate is loaded.
        """
        if crypto.cert is None:
            raise TLSError("No client certificate loaded", ALERT_INTERNAL_ERROR, self.logger, self)
        cert_bytes = crypto.cert.public_bytes(Encoding.DER)
        # Construct CertificateEntry for X.509 with no extensions
        certificate_entry = b"\x00" + len(cert_bytes).to_bytes(3, 'big') + cert_bytes + b"\x00\x00"
        certificate_list_length = len(certificate_entry)
        body = b"\x00" + certificate_list_length.to_bytes(3, 'big') + certificate_entry
        self.send_encrypted_handshake_message(crypto, HANDSHAKE_TYPE_CERTIFICATE, body)

    def send_client_certificate_verify(self, crypto: ClientCrypto) -> None:
        """
        Send the client's CertificateVerify message.

        Args:
            crypto: ClientCrypto instance for computing the signature.
        """
        signature = crypto.compute_certificate_verify()
        body = SIGNATURE_ECDSA_SECP384R1_SHA384 + len(signature).to_bytes(2, 'big') + signature
        self.send_encrypted_handshake_message(crypto, HANDSHAKE_TYPE_CERTIFICATE_VERIFY, body)

    def send_empty_certificate(self, crypto: ClientCrypto) -> None:
        """
        Send an empty Certificate message (for when no certificate is available).

        Args:
            crypto: ClientCrypto instance (unused in this method).
        """
        body = b"\x00\x00\x00\x00"  # Empty context and certificate list
        self.send_encrypted_handshake_message(crypto, HANDSHAKE_TYPE_CERTIFICATE, body)

    def send_finished(self, crypto: ClientCrypto) -> None:
        """
        Send the Finished message to complete the handshake.

        Args:
            crypto: ClientCrypto instance for computing the Finished message.
        """
        finished = crypto.compute_finished_message()
        self.send_encrypted_handshake_message(crypto, HANDSHAKE_TYPE_FINISHED, finished)

    def send_application_data(self, crypto: ClientCrypto, plaintext: bytes) -> None:
        """
        Send application data to the server.

        Args:
            crypto: ClientCrypto instance for encryption.
            plaintext: Data to send.

        Raises:
            TLSError: If attempting to send data before handshake completion.
        """
        if self.handshake_state != STATE_CLIENT_APPLICATION:
            raise TLSError("Attempted to send application data before handshake completion", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
        chunks = [plaintext[i:i + MAX_PLAINTEXT_SIZE] for i in range(0, len(plaintext), MAX_PLAINTEXT_SIZE)]
        start = time.perf_counter()
        for i, chunk in enumerate(chunks):
            is_last = 1 if i == len(chunks) - 1 else 0
            seq_bytes, iv, ct = crypto.encrypt_message(chunk)
            flag = bytes([is_last])
            data = seq_bytes + iv + ct + flag
            self.sock.send(bytes([MSG_TYPE_APPLICATION]) + LEGACY_VERSION + len(data).to_bytes(2, 'big') + data)
        duration = time.perf_counter() - start
        crypto.compute_time += duration
        self.logger.debug(f"Encrypted message ({len(plaintext)} bytes) in {duration:.6f}s")
        self.logger.info(f"Sent application data: {plaintext[:20]}...")

    def receive_application_data(self, crypto: ClientCrypto) -> bytes:
        """
        Receive application data from the server.

        Args:
            crypto: ClientCrypto instance for decryption.

        Returns:
            bytes: Received plaintext data.

        Raises:
            TLSError: If data is received before handshake completion or if there's an error.
        """
        if self.handshake_state != STATE_CLIENT_APPLICATION:
            raise TLSError("Received application data before handshake completion", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
        full_plaintext = bytearray()
        start = time.perf_counter()
        while True:
            header = receive_exact(self.sock, 5)
            content_type = header[0]
            version = header[1:3]
            length = int.from_bytes(header[3:5], 'big')
            if version != LEGACY_VERSION:
                raise TLSError(f"Invalid version: {version.hex()}", ALERT_PROTOCOL_VERSION, self.logger, self)
            data = receive_exact(self.sock, length)

            if content_type == ALERT_TYPE:
                if self.crypto and not self.crypto.is_handshake_phase:
                    seq_bytes = data[:SEQ_BYTES_LENGTH]
                    iv = data[SEQ_BYTES_LENGTH:SEQ_BYTES_LENGTH + IV_LENGTH]
                    ct = data[SEQ_BYTES_LENGTH + IV_LENGTH:]
                    alert_data = self.crypto.decrypt_message(seq_bytes, iv, ct)
                else:
                    alert_data = data
                alert_type = alert_data[0]
                description = alert_data[1:].decode('utf-8', errors='ignore')
                self.logger.info(f"Received alert: {ALERT_DESCRIPTIONS.get(alert_type, 'Unknown')} ({alert_type:02x}) - {description}")
                if alert_type == ALERT_CLOSE_NOTIFY:
                    return b"END_SESSION"
                raise TLSError(f"Server alert: {description}", alert_type, self.logger, self)
            elif content_type == MSG_TYPE_APPLICATION:
                seq_bytes = data[:SEQ_BYTES_LENGTH]
                iv = data[SEQ_BYTES_LENGTH:SEQ_BYTES_LENGTH + IV_LENGTH]
                flag = data[-1:]
                ct = data[SEQ_BYTES_LENGTH + IV_LENGTH:-1]
                plaintext_chunk = crypto.decrypt_message(seq_bytes, iv, ct)
                full_plaintext.extend(plaintext_chunk)
                if flag == b"\x01":
                    break
            else:
                raise TLSError(f"Unexpected content type: {content_type:02x}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
        duration = time.perf_counter() - start
        crypto.compute_time += duration
        self.logger.debug(f"Decrypted message ({len(full_plaintext)} bytes) in {duration:.6f}s")
        self.logger.info(f"Received application data: {full_plaintext[:20]}...")
        return bytes(full_plaintext)

    def close(self) -> None:
        """Close the client connection."""
        if self.sock:
            self.sock.close()
            self.logger.info("Client connection closed")