import os
import socket
import logging
import struct
import time
from typing import Dict

from cryptography.hazmat.primitives.serialization import Encoding
from client_crypto import ClientCrypto
from errors import TLSError
from network import BaseNetwork, receive_exact
from utils import (
    ALERT_ACCESS_DENIED, ALERT_ILLEGAL_PARAMETER, ALERT_INTERNAL_ERROR, ALERT_PROTOCOL_VERSION,
    ALERT_UNEXPECTED_MESSAGE, CIPHER_SUITE_CODES, CIPHER_SUITE_NAMES, CIPHER_SUITES,
    EXTENSION_KEY_SHARE, EXTENSION_SIGNATURE_ALGORITHMS, EXTENSION_SUPPORTED_VERSIONS,
    HANDSHAKE_TYPE_CERTIFICATE, HANDSHAKE_TYPE_CERTIFICATE_VERIFY, HANDSHAKE_TYPE_FINISHED, KYBER_GROUPS,
    LEGACY_VERSION, LENGTH_FIELD_2_BYTES, MSG_TYPE_HANDSHAKE, SIGNATURE_ECDSA_SECP384R1_SHA384,
    STATE_CLIENT_APPLICATION, STATE_CLIENT_INIT, HANDSHAKE_TYPE_CLIENT_HELLO,
    HANDSHAKE_TYPE_SERVER_HELLO, EXTENSION_SERVER_NAME, EXTENSION_SUPPORTED_GROUPS,
    EXTENSION_ALPN, GROUP_SECP384R1, GROUP_KYBER512, GROUP_KYBER768, GROUP_KYBER1024,
    STATE_CLIENT_RECEIVED_SERVER_HELLO, STATE_CLIENT_SENT_HELLO, TLS_VERSION_1_3, 
    SOCKET_RECV_BUFFER_SIZE, SOCKET_CONNECT_TIMEOUT, CONNECTION_RETRY_ATTEMPTS, RETRY_SLEEP_SECONDS, 
    RANDOM_BYTES_LENGTH, DEFAULT_SNI, ALPN_HTTP, SUPPORTED_SIGNATURE_ALGORITHMS, VERSION_LENGTH, 
    encode_key_shares, encode_signature_algorithms, encode_extension, decode_extensions
)

class ClientNetwork(BaseNetwork):
    """
    Client-specific network operations for TLS 1.3 communication (RFC 8446, Section 5).
    """

    def __init__(self, ip: str, port: int, logger: logging.Logger):
        """
        Initialize the ClientNetwork instance.

        Args:
            ip (str): Server IP address.
            port (int): Server port number.
            logger (logging.Logger): Logger for network events.
        """
        super().__init__(ip, port, logger)
        self.handshake_state = STATE_CLIENT_INIT

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
                return
            except socket.error as e:
                if attempt < CONNECTION_RETRY_ATTEMPTS - 1:
                    self.logger.debug(f"Connection attempt {attempt + 1} failed: {e}, retrying")
                    time.sleep(RETRY_SLEEP_SECONDS)
                else:
                    raise TLSError(f"Connection failed after {CONNECTION_RETRY_ATTEMPTS} attempts: {e}", ALERT_ACCESS_DENIED, self.logger, self)

    def send_client_hello(self, crypto: ClientCrypto) -> None:
        """
        Send the ClientHello message to initiate the TLS handshake.

        Args:
            crypto (ClientCrypto): Crypto instance with keys.

        Raises:
            TLSError: If handshake state is invalid or sending fails.
        """
        if self.handshake_state != STATE_CLIENT_INIT:
            raise TLSError(f"ClientHello out of order: state {self.handshake_state}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
        
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
        extensions.extend(encode_key_shares(key_shares, True))
        ext_length = len(extensions).to_bytes(LENGTH_FIELD_2_BYTES, 'big')
        client_hello_body = (
            LEGACY_VERSION + random + session_id + cipher_suites_length + cipher_suites +
            compression_methods + ext_length + extensions
        )
        try:
            self.send_handshake_message(HANDSHAKE_TYPE_CLIENT_HELLO, client_hello_body)
            self.handshake_state = STATE_CLIENT_SENT_HELLO
        except TLSError as e:
            raise

    def receive_server_hello(self, crypto: ClientCrypto) -> Dict[str, bytes]:
        """
        Receive and process the ServerHello message.

        Args:
            crypto (ClientCrypto): Crypto instance for transcript updates.

        Returns:
            Dict[str, bytes]: Parsed ServerHello data (random, ecc_pk, kyber_ct, session_id).

        Raises:
            TLSError: If message is invalid or unexpected.
        """
        try:
            header = receive_exact(self.sock, 1)
            if header[0] != MSG_TYPE_HANDSHAKE:
                raise TLSError(f"Expected handshake (0x16), got {header[0]:02x}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
            version = receive_exact(self.sock, VERSION_LENGTH)
            if version != LEGACY_VERSION:
                raise TLSError(f"Expected legacy version 0x0303, got {version.hex()}", ALERT_PROTOCOL_VERSION, self.logger, self)
            length = int.from_bytes(receive_exact(self.sock, LENGTH_FIELD_2_BYTES), 'big')
            data_with_type = receive_exact(self.sock, length)
            if data_with_type[0] != HANDSHAKE_TYPE_SERVER_HELLO:
                raise TLSError(f"Expected ServerHello (0x02), got {data_with_type[0]:02x}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
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
                raise TLSError(f"Unsupported cipher suite: {cipher_suite.hex()}", ALERT_ILLEGAL_PARAMETER, self.logger, self)
            crypto.cipher_suite = CIPHER_SUITE_NAMES[cipher_suite]
            
            kyber_ct = ecc_pk = b""
            use_hybrid = "Kyber" in crypto.cipher_suite
            kyber_group = KYBER_GROUPS.get(crypto.cipher_suite)
            
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
        except TLSError as e:
            raise
        except Exception as e:
            raise TLSError(f"Failed to process ServerHello: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

    def send_client_certificate(self, crypto: ClientCrypto) -> None:
        """
        Send the client's certificate to the server.

        Args:
            crypto (ClientCrypto): Crypto instance with certificate.

        Raises:
            TLSError: If no certificate is loaded or sending fails.
        """
        if crypto.cert is None:
            raise TLSError("No client certificate loaded", ALERT_INTERNAL_ERROR, self.logger, self)
        cert_bytes = crypto.cert.public_bytes(Encoding.DER)
        certificate_entry = b"\x00" + len(cert_bytes).to_bytes(3, 'big') + cert_bytes + b"\x00\x00"
        body = b"\x00" + len(certificate_entry).to_bytes(3, 'big') + certificate_entry
        try:
            self.send_encrypted_handshake_message(crypto, HANDSHAKE_TYPE_CERTIFICATE, body)
        except TLSError as e:
            raise

    def send_client_certificate_verify(self, crypto: ClientCrypto) -> None:
        """
        Send the client's CertificateVerify message.

        Args:
            crypto (ClientCrypto): Crypto instance for signature.

        Raises:
            TLSError: If sending fails.
        """
        try:
            signature = crypto.compute_certificate_verify()
            body = SIGNATURE_ECDSA_SECP384R1_SHA384 + len(signature).to_bytes(2, 'big') + signature
            self.send_encrypted_handshake_message(crypto, HANDSHAKE_TYPE_CERTIFICATE_VERIFY, body)
        except TLSError as e:
            raise

    def send_empty_certificate(self, crypto: ClientCrypto) -> None:
        """
        Send an empty Certificate message.

        Args:
            crypto (ClientCrypto): Crypto instance (for encryption).

        Raises:
            TLSError: If sending fails.
        """
        body = b"\x00\x00\x00\x00"  # Empty context and certificate list
        try:
            self.send_encrypted_handshake_message(crypto, HANDSHAKE_TYPE_CERTIFICATE, body)
        except TLSError as e:
            raise

    def send_finished(self, crypto: ClientCrypto) -> None:
        """
        Send the Finished message to complete the handshake.

        Args:
            crypto (ClientCrypto): Crypto instance for Finished message.

        Raises:
            TLSError: If sending fails.
        """
        try:
            finished = crypto.compute_finished_message()
            self.send_encrypted_handshake_message(crypto, HANDSHAKE_TYPE_FINISHED, finished)
        except TLSError as e:
            raise

    def send_application_data(self, crypto: ClientCrypto, plaintext: bytes) -> None:
        """
        Send application data to the server.

        Args:
            crypto (ClientCrypto): Crypto instance for encryption.
            plaintext (bytes): Data to send.

        Raises:
            TLSError: If handshake incomplete or sending fails.
        """
        if self.handshake_state != STATE_CLIENT_APPLICATION:
            raise TLSError(f"Cannot send application data: handshake state {self.handshake_state}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
        try:
            self._send_application_data(crypto, plaintext)
        except TLSError as e:
            raise

    def receive_application_data(self, crypto: ClientCrypto) -> bytes:
        """
        Receive application data from the server.

        Args:
            crypto (ClientCrypto): Crypto instance for decryption.

        Returns:
            bytes: Decrypted plaintext.

        Raises:
            TLSError: If handshake incomplete or receiving fails.
        """
        if self.handshake_state != STATE_CLIENT_APPLICATION:
            raise TLSError(f"Cannot receive application data: handshake state {self.handshake_state}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
        try:
            data = self._receive_encrypted_data(crypto)
            return data
        except TLSError as e:
            raise

    def close(self) -> None:
        """
        Close the client connection.
        """
        if self.sock:
            try:
                self.sock.close()
                self.logger.info(f"Client connection closed")
            except socket.error as e:
                self.logger.warning(f"Error closing socket: {e}")
        self.sock = None