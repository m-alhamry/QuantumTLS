import os
import socket
import logging
import struct
from typing import Dict

from cryptography.hazmat.primitives.serialization import Encoding
from src.utils.network import BaseNetwork, receive_exact
from src.server.server_crypto import ServerCrypto
from src.utils.errors import TLSError
from src.utils.utils import (
    ALERT_PROTOCOL_VERSION, ALERT_UNEXPECTED_MESSAGE,
    ALERT_INTERNAL_ERROR, EXTENSION_KEY_SHARE, EXTENSION_SUPPORTED_VERSIONS,
    GROUP_SECP384R1, HANDSHAKE_TYPE_CERTIFICATE, HANDSHAKE_TYPE_CERTIFICATE_REQUEST,
    HANDSHAKE_TYPE_CERTIFICATE_VERIFY, HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS,
    HANDSHAKE_TYPE_FINISHED, HANDSHAKE_TYPE_SERVER_HELLO, KYBER_GROUPS, LEGACY_VERSION, 
    LENGTH_FIELD_2_BYTES, MSG_TYPE_HANDSHAKE, SIGNATURE_ECDSA_SECP384R1_SHA384, 
    STATE_SERVER_INIT, STATE_SERVER_RECEIVED_CLIENT_HELLO, SOCKET_RECV_BUFFER_SIZE, 
    SERVER_LISTEN_BACKLOG, VERSION_LENGTH, RANDOM_BYTES_LENGTH,
    STATE_SERVER_SENT_HELLO, STATE_SERVER_APPLICATION, TLS_VERSION_1_3,
    encode_key_shares, encode_extension, decode_extensions
)

class ServerNetwork(BaseNetwork):
    """
    Server-specific network operations for TLS 1.3 communication (RFC 8446, Section 5).
    """

    def __init__(self, ip: str, port: int, logger: logging.Logger):
        """
        Initialize the ServerNetwork instance.

        Args:
            ip (str): IP address to bind.
            port (int): Port number to bind.
            logger (logging.Logger): Logger for network events.
        """
        super().__init__(ip, port, logger)
        self.server_socket = None
        self.handshake_state = STATE_SERVER_INIT

    def setup(self) -> None:
        """
        Set up the server socket for listening.

        Raises:
            TLSError: If socket setup fails.
        """
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_RECV_BUFFER_SIZE)
            self.server_socket.bind((self.ip, self.port))
            self.server_socket.listen(SERVER_LISTEN_BACKLOG)
        except socket.error as e:
            self.logger.debug(f"Failed to set up server socket: {e}")
            raise

    def receive_client_hello(self, crypto: ServerCrypto) -> Dict[str, bytes]:
        """
        Receive and process the ClientHello message.

        Args:
            crypto (ServerCrypto): Crypto instance for transcript updates.

        Returns:
            Dict[str, bytes]: Parsed ClientHello data (random, session_id, cipher_suites, key_shares, transcript).

        Raises:
            TLSError: If message is invalid or unexpected.
        """
        if self.handshake_state != STATE_SERVER_INIT:
            raise TLSError(f"Received ClientHello out of order: state {self.handshake_state}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
        
        try:
            header = receive_exact(self.sock, 1)
            if header[0] != MSG_TYPE_HANDSHAKE:
                raise TLSError(f"Expected handshake (0x16), got {header[0]:02x}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
            version = receive_exact(self.sock, VERSION_LENGTH)
            if version != LEGACY_VERSION:
                raise TLSError(f"Expected legacy version 0x0303, got {version.hex()}", ALERT_PROTOCOL_VERSION, self.logger, self)
            length = int.from_bytes(receive_exact(self.sock, LENGTH_FIELD_2_BYTES), 'big')
            data_with_type = receive_exact(self.sock, length)
            if data_with_type[0] != 0x01:  # HANDSHAKE_TYPE_CLIENT_HELLO
                raise TLSError(f"Expected ClientHello (0x01), got {data_with_type[0]:02x}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
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
            cipher_suites_len = int.from_bytes(data[pos:pos+2], 'big')
            pos += 2
            cipher_suites = data[pos:pos+cipher_suites_len]
            pos += cipher_suites_len
            compression_methods_len = data[pos]
            pos += 1
            compression_methods = data[pos:pos+compression_methods_len]
            pos += compression_methods_len
            extensions_len = int.from_bytes(data[pos:pos+2], 'big')
            pos += 2
            extensions_data = data[pos:pos+extensions_len]
            extensions = decode_extensions(extensions_data)
            key_shares = {}
            for ext_type, ext_value in extensions:
                if ext_type == EXTENSION_KEY_SHARE:
                    client_shares_len = struct.unpack("!H", ext_value[0:2])[0]
                    offset = 2
                    while offset < 2 + client_shares_len:
                        group, key_len = struct.unpack("!HH", ext_value[offset:offset+4])
                        key_exchange = ext_value[offset+4:offset+4+key_len]
                        key_shares[group] = key_exchange
                        offset += 4 + key_len
            
            self.handshake_state = STATE_SERVER_RECEIVED_CLIENT_HELLO
            crypto.handshake_transcript.extend(data_with_type)
            return {
                "random": random,
                "session_id": session_id,
                "cipher_suites": cipher_suites,
                "key_shares": key_shares,
                "transcript": data_with_type
            }
        except TLSError as e:
            raise
        except Exception as e:
            raise TLSError(f"Failed to process ClientHello: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

    def send_server_hello(self, crypto: ServerCrypto, client_hello: Dict[str, bytes], selected_code: bytes, kyber_ct: bytes | None) -> None:
        """
        Send the ServerHello message in response to ClientHello.

        Args:
            crypto (ServerCrypto): Crypto instance with keys.
            client_hello (Dict[str, bytes]): Parsed ClientHello data.
            selected_code (bytes): Selected cipher suite code.
            kyber_ct (bytes | None): Kyber ciphertext if hybrid.

        Raises:
            TLSError: If handshake state is invalid or sending fails.
        """
        if self.handshake_state != STATE_SERVER_RECEIVED_CLIENT_HELLO:
            raise TLSError(f"ServerHello out of order: state {self.handshake_state}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
        
        random = os.urandom(RANDOM_BYTES_LENGTH)
        session_id = client_hello["session_id"]
        compression_method = b"\x00"
        extensions = bytearray()
        extensions.extend(encode_extension(EXTENSION_SUPPORTED_VERSIONS, TLS_VERSION_1_3))
        key_shares = [(GROUP_SECP384R1, crypto.ecc_public_key_bytes)]
        if kyber_ct:
            kyber_group = KYBER_GROUPS.get(crypto.cipher_suite)
            key_shares.append((kyber_group, kyber_ct))
        extensions.extend(encode_key_shares(key_shares, False))
        ext_length = len(extensions).to_bytes(LENGTH_FIELD_2_BYTES, 'big')
        server_hello_body = (
            LEGACY_VERSION + random + len(session_id).to_bytes(1, 'big') + session_id +
            selected_code + compression_method + ext_length + extensions
        )
        try:
            self.send_handshake_message(HANDSHAKE_TYPE_SERVER_HELLO, server_hello_body)
            self.handshake_state = STATE_SERVER_SENT_HELLO
        except TLSError as e:
            raise

    def send_encrypted_extensions(self, crypto: ServerCrypto) -> None:
        """
        Send the EncryptedExtensions message.

        Args:
            crypto (ServerCrypto): Crypto instance for encryption.

        Raises:
            TLSError: If sending fails.
        """
        body = b"\x00\x00"  # Empty extensions
        try:
            self.send_encrypted_handshake_message(crypto, HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, body)
        except TLSError as e:
            raise

    def send_certificate_request(self, crypto: ServerCrypto) -> None:
        """
        Send the CertificateRequest message for mutual authentication.

        Args:
            crypto (ServerCrypto): Crypto instance for encryption.

        Raises:
            TLSError: If sending fails.
        """
        body = b"\x00"  # Empty context
        try:
            self.send_encrypted_handshake_message(crypto, HANDSHAKE_TYPE_CERTIFICATE_REQUEST, body)
        except TLSError as e:
            raise

    def send_certificate(self, crypto: ServerCrypto) -> None:
        """
        Send the server's Certificate message.

        Args:
            crypto (ServerCrypto): Crypto instance with certificate.

        Raises:
            TLSError: If certificate is missing or sending fails.
        """
        if crypto.cert is None:
            raise TLSError("No server certificate loaded", ALERT_INTERNAL_ERROR, self.logger, self)
        cert_bytes = crypto.cert.public_bytes(Encoding.DER)
        body = b"\x00" + len(cert_bytes).to_bytes(3, 'big') + cert_bytes + b"\x00\x00"
        try:
            self.send_encrypted_handshake_message(crypto, HANDSHAKE_TYPE_CERTIFICATE, body)
        except TLSError as e:
            raise

    def send_certificate_verify(self, crypto: ServerCrypto) -> None:
        """
        Send the server's CertificateVerify message.

        Args:
            crypto (ServerCrypto): Crypto instance for signature.

        Raises:
            TLSError: If sending fails.
        """
        try:
            signature = crypto.compute_certificate_verify()
            body = SIGNATURE_ECDSA_SECP384R1_SHA384 + len(signature).to_bytes(2, 'big') + signature
            self.send_encrypted_handshake_message(crypto, HANDSHAKE_TYPE_CERTIFICATE_VERIFY, body)
        except TLSError as e:
            raise

    def send_finished(self, crypto: ServerCrypto) -> None:
        """
        Send the Finished message to complete the handshake.

        Args:
            crypto (ServerCrypto): Crypto instance for Finished message.

        Raises:
            TLSError: If sending fails.
        """
        try:
            finished = crypto.compute_finished_message()
            self.send_encrypted_handshake_message(crypto, HANDSHAKE_TYPE_FINISHED, finished)
        except TLSError as e:
            raise

    def receive_application_data(self, crypto: ServerCrypto) -> Dict[str, bytes]:
        """
        Receive application data from the client.

        Args:
            crypto (ServerCrypto): Crypto instance for decryption.

        Returns:
            Dict[str, bytes]: {"type": "end_session"} or {"type": "application", "data": plaintext}.

        Raises:
            TLSError: If handshake incomplete or receiving fails.
        """
        if self.handshake_state != STATE_SERVER_APPLICATION:
            raise TLSError(f"Cannot receive application data: handshake state {self.handshake_state}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
        try:
            plaintext = self._receive_encrypted_data(crypto)
            if plaintext == b"END_SESSION":
                return {"type": "end_session"}
            return {"type": "application", "data": plaintext}
        except TLSError as e:
            raise

    def send_application_data(self, crypto: ServerCrypto, plaintext: bytes) -> None:
        """
        Send application data to the client.

        Args:
            crypto (ServerCrypto): Crypto instance for encryption.
            plaintext (bytes): Data to send.

        Raises:
            TLSError: If handshake incomplete or sending fails.
        """
        if self.handshake_state != STATE_SERVER_APPLICATION:
            raise TLSError(f"Cannot send application data: handshake state {self.handshake_state}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
        try:
            self._send_application_data(crypto, plaintext)
        except TLSError as e:
            raise

    def close(self) -> None:
        """
        Close the server connection.
        """
        if self.sock:
            try:
                self.sock.close()
            except socket.error as e:
                self.logger.warning(f"Error closing client socket: {e}")
        if self.server_socket:
            try:
                self.server_socket.close()
            except socket.error as e:
                self.logger.warning(f"Error closing server socket: {e}")
        self.logger.info(f"Server connection closed")
        self.sock = None
        self.server_socket = None