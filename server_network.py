import os
import socket
import logging
import struct
import time
from typing import Dict, Tuple

from cryptography.hazmat.primitives.serialization import Encoding
from server_crypto import ServerCrypto
from errors import TLSError
from utils import (
    ALERT_DECODE_ERROR, ALERT_DESCRIPTIONS, ALERT_PROTOCOL_VERSION, ALERT_TYPE, 
    ALERT_UNEXPECTED_MESSAGE, ALERT_CLOSE_NOTIFY, ALERT_INTERNAL_ERROR, EXTENSION_KEY_SHARE, 
    EXTENSION_SUPPORTED_VERSIONS, GROUP_SECP384R1, GROUP_KYBER512, GROUP_KYBER768, 
    GROUP_KYBER1024, HANDSHAKE_TYPE_CERTIFICATE, HANDSHAKE_TYPE_CERTIFICATE_REQUEST, 
    HANDSHAKE_TYPE_CERTIFICATE_VERIFY, HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, HANDSHAKE_TYPE_FINISHED, 
    LEGACY_VERSION, LENGTH_FIELD_2_BYTES, MAX_PLAINTEXT_SIZE, MSG_TYPE_APPLICATION, 
    MSG_TYPE_HANDSHAKE, SEQ_BYTES_LENGTH, SIGNATURE_ECDSA_SECP384R1_SHA384, STATE_SERVER_APPLICATION,
    STATE_SERVER_INIT, STATE_SERVER_RECEIVED_CLIENT_HELLO, STATE_SERVER_SENT_HELLO, 
    TLS_VERSION_1_3, HANDSHAKE_TYPE_CLIENT_HELLO, HANDSHAKE_TYPE_SERVER_HELLO,
    VERSION_LENGTH, BaseNetwork, encode_key_share_server_hello, receive_exact,
    encode_extension, decode_extensions, SOCKET_RECV_BUFFER_SIZE,
    RANDOM_BYTES_LENGTH, SERVER_LISTEN_BACKLOG, IV_LENGTH
)

class ServerNetwork(BaseNetwork):
    """Server-specific network operations for TLS 1.3 communication."""

    def __init__(self, ip: str, port: int, logger: logging.Logger):
        """
        Initialize the ServerNetwork instance.

        Args:
            ip: IP address to bind.
            port: Port number to bind.
            logger: Logger instance for logging network events.
        """
        super().__init__(logger)
        self.ip = ip
        self.port = port
        self.server_socket = None
        self.conn = None
        self.addr = None
        self.cipher_suite = None
        self.crypto = None
        self.handshake_state = STATE_SERVER_INIT
        self.is_handshake_encrypted = False

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
            self.logger.info(f"Server listening on {self.ip}:{self.port}")
        except socket.error as e:
            raise TLSError(f"Failed to set up server socket: {e}", ALERT_INTERNAL_ERROR, self.logger, None)

    def receive_client_hello(self, crypto: ServerCrypto) -> Dict[str, bytes]:
        """
        Receive and process the ClientHello message.

        Args:
            crypto: ServerCrypto instance for cryptographic operations.

        Returns:
            Dict[str, bytes]: Parsed ClientHello data.

        Raises:
            TLSError: If the message is invalid or unexpected.
        """
        if self.handshake_state != STATE_SERVER_INIT:
            raise TLSError("Received ClientHello out of order", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
        
        header = receive_exact(self.conn, 1)
        if header[0] != MSG_TYPE_HANDSHAKE:
            raise TLSError(f"Expected handshake, got {header[0]:02x}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
        version = receive_exact(self.conn, VERSION_LENGTH)
        if version != LEGACY_VERSION:
            raise TLSError(f"Expected legacy version 0x0303, got {version.hex()}", ALERT_PROTOCOL_VERSION, self.logger, self)
        length = int.from_bytes(receive_exact(self.conn, LENGTH_FIELD_2_BYTES), 'big')
        data_with_type = receive_exact(self.conn, length)
        if data_with_type[0] != HANDSHAKE_TYPE_CLIENT_HELLO:
            raise TLSError(f"Expected ClientHello, got {data_with_type[0]:02x}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
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

    def send_server_hello(self, crypto: ServerCrypto, client_hello: Dict[str, bytes], selected_code: bytes, kyber_ct: bytes | None) -> None:
        """
        Send the ServerHello message in response to the ClientHello.

        Args:
            crypto: ServerCrypto instance for cryptographic operations.
            client_hello: Parsed ClientHello data.
            selected_code: Selected cipher suite code.
            kyber_ct: Kyber ciphertext (if hybrid key exchange is used).
        """
        if self.handshake_state != STATE_SERVER_RECEIVED_CLIENT_HELLO:
            raise TLSError("ServerHello out of order", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
        
        random = os.urandom(RANDOM_BYTES_LENGTH)
        session_id = client_hello["session_id"]
        compression_method = b"\x00"
        extensions = bytearray()
        extensions.extend(encode_extension(EXTENSION_SUPPORTED_VERSIONS, TLS_VERSION_1_3))
        key_shares = [(GROUP_SECP384R1, crypto.ecc_public_key_bytes)]
        if kyber_ct:
            kyber_group = {"TLS_AES_256_GCM_SHA384_Kyber512": GROUP_KYBER512, "TLS_AES_256_GCM_SHA384_Kyber768": GROUP_KYBER768, "TLS_AES_256_GCM_SHA384_Kyber1024": GROUP_KYBER1024}.get(crypto.cipher_suite)
            key_shares.append((kyber_group, kyber_ct))
        extensions.extend(encode_key_share_server_hello(key_shares))
        ext_length = len(extensions).to_bytes(LENGTH_FIELD_2_BYTES, 'big')
        server_hello_body = (
            LEGACY_VERSION +
            random +
            len(session_id).to_bytes(1, 'big') + session_id +
            selected_code +
            compression_method +
            ext_length + extensions
        )
        handshake_message = bytes([HANDSHAKE_TYPE_SERVER_HELLO]) + len(server_hello_body).to_bytes(3, 'big') + server_hello_body
        record_layer = bytes([MSG_TYPE_HANDSHAKE]) + LEGACY_VERSION + len(handshake_message).to_bytes(2, 'big') + handshake_message
        
        self.conn.send(record_layer)
        crypto.handshake_transcript.extend(handshake_message)
        self.handshake_state = STATE_SERVER_SENT_HELLO

    def send_encrypted_handshake_message(self, crypto: ServerCrypto, handshake_type: int, body: bytes) -> None:
        """
        Send an encrypted handshake message.

        Args:
            crypto: ServerCrypto instance for encryption.
            handshake_type: Type of the handshake message.
            body: Body of the handshake message.
        """
        handshake_message = bytes([handshake_type]) + len(body).to_bytes(3, 'big') + body
        crypto.handshake_transcript.extend(handshake_message)
        plaintext = handshake_message + b"\x16"  # Append content type byte (0x16 for handshake)
        _, iv, ct = crypto.encrypt_message(plaintext)
        record_layer = bytes([MSG_TYPE_APPLICATION]) + LEGACY_VERSION + len(iv + ct).to_bytes(2, 'big') + iv + ct
        self.conn.send(record_layer)

    def receive_encrypted_handshake_message(self, crypto: ServerCrypto) -> Tuple[int, bytes]:
        """
        Receive and decrypt an encrypted handshake message.

        Args:
            crypto: ServerCrypto instance for decryption.

        Returns:
            Tuple[int, bytes]: Handshake type and body.

        Raises:
            TLSError: If the message is invalid or decryption fails.
        """
        header = receive_exact(self.conn, 1)
        if header[0] != MSG_TYPE_APPLICATION:
            raise TLSError(f"Expected application_data (0x17), got {header[0]:02x}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
        version = receive_exact(self.conn, VERSION_LENGTH)
        if version != LEGACY_VERSION:
            raise TLSError(f"Expected legacy version 0x0303, got {version.hex()}", ALERT_PROTOCOL_VERSION, self.logger, self)
        length = int.from_bytes(receive_exact(self.conn, LENGTH_FIELD_2_BYTES), 'big')
        data = receive_exact(self.conn, length)
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

    def send_encrypted_extensions(self, crypto: ServerCrypto) -> None:
        """
        Send the EncryptedExtensions message.

        Args:
            crypto: ServerCrypto instance for encryption.
        """
        body = b"\x00\x00"  # Empty extensions
        self.send_encrypted_handshake_message(crypto, HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, body)

    def send_certificate_request(self, crypto: ServerCrypto) -> None:
        """
        Send the CertificateRequest message for mutual authentication.

        Args:
            crypto: ServerCrypto instance for encryption.
        """
        body = b"\x00"  # Empty context
        self.send_encrypted_handshake_message(crypto, HANDSHAKE_TYPE_CERTIFICATE_REQUEST, body)

    def send_certificate(self, crypto: ServerCrypto) -> None:
        """
        Send the server's Certificate message.

        Args:
            crypto: ServerCrypto instance containing the certificate.
        """
        cert_bytes = crypto.cert.public_bytes(Encoding.DER)
        body = b"\x00" + len(cert_bytes).to_bytes(3, 'big') + cert_bytes + b"\x00\x00"
        self.send_encrypted_handshake_message(crypto, HANDSHAKE_TYPE_CERTIFICATE, body)

    def send_certificate_verify(self, crypto: ServerCrypto) -> None:
        """
        Send the server's CertificateVerify message.

        Args:
            crypto: ServerCrypto instance for computing the signature.
        """
        signature = crypto.compute_certificate_verify()
        body = SIGNATURE_ECDSA_SECP384R1_SHA384 + len(signature).to_bytes(2, 'big') + signature
        self.send_encrypted_handshake_message(crypto, HANDSHAKE_TYPE_CERTIFICATE_VERIFY, body)

    def send_finished(self, crypto: ServerCrypto) -> None:
        """
        Send the Finished message to complete the handshake.

        Args:
            crypto: ServerCrypto instance for computing the Finished message.
        """
        finished = crypto.compute_finished_message()
        self.send_encrypted_handshake_message(crypto, HANDSHAKE_TYPE_FINISHED, finished)

    def receive_application_data(self, crypto: ServerCrypto) -> Dict[str, bytes]:
        """
        Receive application data from the client.

        Args:
            crypto: ServerCrypto instance for decryption.

        Returns:
            Dict[str, bytes]: Received data or session end signal.

        Raises:
            TLSError: If data is received before handshake completion or if there's an error.
        """
        if self.handshake_state != STATE_SERVER_APPLICATION:
            raise TLSError("Received application data before handshake completion", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
        full_plaintext = bytearray()
        start = time.perf_counter()
        while True:
            header = receive_exact(self.conn, 1)
            if header[0] == ALERT_TYPE:
                alert_type, desc = self._receive_alert_with_header(header)
                if alert_type == ALERT_CLOSE_NOTIFY:
                    return {"type": "end_session"}
                raise TLSError(f"Client alert: {desc}", alert_type, self.logger, self)
            if header[0] != MSG_TYPE_APPLICATION:
                raise TLSError(f"Expected application data, got {header[0]:02x}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
            receive_exact(self.conn, VERSION_LENGTH)
            length = int.from_bytes(receive_exact(self.conn, LENGTH_FIELD_2_BYTES), 'big')
            data = receive_exact(self.conn, length)
            seq_bytes = data[:SEQ_BYTES_LENGTH]
            iv = data[SEQ_BYTES_LENGTH:SEQ_BYTES_LENGTH + IV_LENGTH]
            flag = data[-1:]
            ct = data[SEQ_BYTES_LENGTH + IV_LENGTH:-1]
            plaintext_chunk = crypto.decrypt_message(seq_bytes, iv, ct)
            full_plaintext.extend(plaintext_chunk)
            if flag == b"\x01":
                break
        duration = time.perf_counter() - start
        crypto.compute_time += duration
        self.logger.debug(f"Decrypted message ({len(full_plaintext)} bytes) in {duration:.6f}s")
        self.logger.info(f"Received plaintext: {full_plaintext[:20]}...")
        plaintext = bytes(full_plaintext)
        if plaintext == b"END_SESSION":
            return {"type": "end_session"}
        return {"type": "application", "data": plaintext}

    def send_application_data(self, crypto: ServerCrypto, plaintext: bytes) -> None:
        """
        Send application data to the client.

        Args:
            crypto: ServerCrypto instance for encryption.
            plaintext: Data to send.

        Raises:
            TLSError: If attempting to send data before handshake completion.
        """
        if self.handshake_state != STATE_SERVER_APPLICATION:
            raise TLSError("Attempted to send application data before handshake completion", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
        chunks = [plaintext[i:i + MAX_PLAINTEXT_SIZE] for i in range(0, len(plaintext), MAX_PLAINTEXT_SIZE)]
        start = time.perf_counter()
        for i, chunk in enumerate(chunks):
            is_last = 1 if i == len(chunks) - 1 else 0
            seq_bytes, iv, ct = crypto.encrypt_message(chunk)
            flag = bytes([is_last])
            data = seq_bytes + iv + ct + flag
            self.conn.send(bytes([MSG_TYPE_APPLICATION]) + LEGACY_VERSION + len(data).to_bytes(2, 'big') + data)
        duration = time.perf_counter() - start
        crypto.compute_time += duration
        self.logger.debug(f"Encrypted message ({len(plaintext)} bytes) in {duration:.6f}s")
        self.logger.info(f"Sent application data: {plaintext[:20]}...")

    def _receive_alert_with_header(self, header: bytes) -> Tuple[int, str]:
        """
        Receive and process an alert message with the given header.

        Args:
            header: First byte of the alert message.

        Returns:
            Tuple[int, str]: Alert type and description.

        Raises:
            TLSError: If the alert is invalid or malformed.
        """
        if header[0] != ALERT_TYPE:
            raise TLSError(f"Expected alert, got {header[0]:02x}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
        version = receive_exact(self.conn, VERSION_LENGTH)
        if version != LEGACY_VERSION:
            raise TLSError(f"Invalid alert version: {version.hex()}", ALERT_PROTOCOL_VERSION, self.logger, self)
        length = int.from_bytes(receive_exact(self.conn, LENGTH_FIELD_2_BYTES), 'big')
        data = receive_exact(self.conn, length)
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
        return alert_type, description

    def close(self) -> None:
        """Close the server connection."""
        if self.conn:
            self.conn.close()
        if self.server_socket:
            self.server_socket.close()
        self.logger.info("Server connection closed")