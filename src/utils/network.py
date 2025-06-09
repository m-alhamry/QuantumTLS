import logging
import socket
import time
from typing import Tuple

from src.utils.errors import TLSError
from src.utils.utils import (
    ALERT_CLOSE_NOTIFY, ALERT_DECODE_ERROR, ALERT_DESCRIPTIONS, ALERT_INTERNAL_ERROR, 
    ALERT_PROTOCOL_VERSION, ALERT_TYPE, ALERT_UNEXPECTED_MESSAGE, 
    HANDSHAKE_TYPE_LENGTH, IV_LENGTH, LEGACY_VERSION, LENGTH_FIELD_2_BYTES, 
    MAX_PLAINTEXT_SIZE, MSG_TYPE_APPLICATION, MSG_TYPE_HANDSHAKE, SEQ_BYTES_LENGTH, VERSION_LENGTH,
)

def receive_exact(sock: socket.socket, size: int) -> bytes:
    """
    Receive exactly the specified number of bytes from a socket.

    Args:
        sock (socket.socket): Socket object.
        size (int): Number of bytes to receive.

    Returns:
        bytes: Received data.

    Raises:
        TLSError: If the connection closes or socket error occurs.
    """
    data = bytearray()
    try:
        while len(data) < size:
            packet = sock.recv(size - len(data))
            if not packet:
                raise TLSError(f"Connection closed: expected {size} bytes, received {len(data)}", ALERT_CLOSE_NOTIFY)
            data.extend(packet)
    except socket.error as e:
        raise TLSError(f"Socket error during receive: {e}", ALERT_INTERNAL_ERROR)
    return bytes(data)

def handle_session_timeout(network: 'BaseNetwork', last_activity: float, timeout: int) -> bool:
    """
    Check if the session has timed out and terminate it if necessary.

    Args:
        network (BaseNetwork): Network object with end_session method.
        last_activity (float): Timestamp of the last activity (in seconds).
        timeout (int): Timeout duration in seconds.

    Returns:
        bool: True if session timed out, False otherwise.
    """
    if time.time() - last_activity > timeout:
        network.end_session(f"Session timed out after {timeout} seconds")
        return True
    return False

class BaseNetwork:
    """
    Base class for network operations in TLS 1.3 communication (RFC 8446, Section 5).
    """

    def __init__(self, ip: str, port: int, logger: logging.Logger):
        """
        Initialize the BaseNetwork instance.

        Args:
            logger (logging.Logger): Logger for network events.
        """
        self.logger = logger
        self.sock = None
        self.ip = ip
        self.port = port
        self.crypto = None

    def send_handshake_message(self, handshake_type: int, body: bytes) -> None:
        """
        Send a plaintext handshake message.

        Args:
            handshake_type (int): Handshake message type.
            body (bytes): Message body.

        Raises:
            TLSError: If sending fails.
        """
        handshake_message = bytes([handshake_type]) + len(body).to_bytes(3, 'big') + body
        record_layer = bytes([MSG_TYPE_HANDSHAKE]) + LEGACY_VERSION + len(handshake_message).to_bytes(2, 'big') + handshake_message
        try:
            self.sock.send(record_layer)
            self.crypto.handshake_transcript.extend(handshake_message)
        except socket.error as e:
            raise TLSError(f"Failed to send handshake message: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

    def send_encrypted_handshake_message(self, crypto, handshake_type: int, body: bytes) -> None:
        """
        Send an encrypted handshake message.

        Args:
            crypto: Crypto instance for encryption.
            handshake_type (int): Handshake message type.
            body (bytes): Message body.

        Raises:
            TLSError: If encryption or sending fails.
        """
        handshake_message = bytes([handshake_type]) + len(body).to_bytes(3, 'big') + body
        crypto.handshake_transcript.extend(handshake_message)
        plaintext = handshake_message + b"\x16"  # Handshake content type
        try:
            _, iv, ct = crypto.encrypt_message(plaintext)
            record_layer = bytes([MSG_TYPE_APPLICATION]) + LEGACY_VERSION + len(iv + ct).to_bytes(2, 'big') + iv + ct
            self.sock.send(record_layer)
        except TLSError as e:
            raise
        except socket.error as e:
            raise TLSError(f"Failed to send encrypted handshake message: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

    def receive_encrypted_handshake_message(self, crypto) -> Tuple[int, bytes]:
        """
        Receive and decrypt an encrypted handshake message.

        Args:
            crypto: Crypto instance for decryption.

        Returns:
            Tuple[int, bytes]: Handshake type and body.

        Raises:
            TLSError: If message is invalid or decryption fails.
        """
        try:
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
                raise TLSError("Invalid decrypted handshake message: missing or incorrect content type", ALERT_DECODE_ERROR, self.logger, self)
            handshake_message = decrypted[:-1] # Strip content type byte
            handshake_type = handshake_message[0]
            msg_length = int.from_bytes(handshake_message[1:4], 'big')
            if len(handshake_message) != 4 + msg_length:
                raise TLSError(f"Invalid handshake message length: expected {4 + msg_length}, got {len(handshake_message)}", ALERT_DECODE_ERROR, self.logger, self)
            body = handshake_message[4:]
            return handshake_type, body
        except TLSError as e:
            raise
        except socket.error as e:
            raise TLSError(f"Socket error receiving handshake message: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

    def _send_application_data(self, crypto, plaintext: bytes) -> None:
        """
        Send application data in chunks.

        Args:
            crypto: Crypto instance for encryption.
            plaintext (bytes): Data to send.

        Raises:
            TLSError: If sending fails.
        """
        start = time.perf_counter()
        chunks = [plaintext[i:i + MAX_PLAINTEXT_SIZE] for i in range(0, len(plaintext), MAX_PLAINTEXT_SIZE)]
        try:
            for i, chunk in enumerate(chunks):
                is_last = 1 if i == len(chunks) - 1 else 0
                seq_bytes, iv, ct = crypto.encrypt_message(chunk)
                flag = bytes([is_last])
                data = seq_bytes + iv + ct + flag
                self.sock.send(bytes([MSG_TYPE_APPLICATION]) + LEGACY_VERSION + len(data).to_bytes(2, 'big') + data)
            duration = time.perf_counter() - start
            self.logger.debug(f"Message encrypted and sent successfully: {plaintext[:20]} ({len(plaintext)} bytes) in {duration:.6f} seconds")
        except TLSError as e:
            raise
        except socket.error as e:
            raise TLSError(f"Failed to send application data: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

    def _receive_encrypted_data(self, crypto) -> bytes:
        """
        Receive and decrypt application data.

        Args:
            crypto: Crypto instance for decryption.

        Returns:
            bytes: Decrypted plaintext.

        Raises:
            TLSError: If receiving or decryption fails.
        """
        full_plaintext = bytearray()
        try:
            while True:
                header = receive_exact(self.sock, 1)
                start = time.perf_counter()
                if header[0] == ALERT_TYPE:
                    alert_type, desc = self._receive_alert_with_header(header)
                    if alert_type == ALERT_CLOSE_NOTIFY:
                        return b"END_SESSION"
                    raise TLSError(f"Server alert: {desc}", alert_type, self.logger, self)
                if header[0] != MSG_TYPE_APPLICATION:
                    raise TLSError(f"Expected application data (0x17), got {header[0]:02x}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
                receive_exact(self.sock, VERSION_LENGTH)
                length = int.from_bytes(receive_exact(self.sock, LENGTH_FIELD_2_BYTES), 'big')
                data = receive_exact(self.sock, length)
                seq_bytes = data[:SEQ_BYTES_LENGTH]
                iv = data[SEQ_BYTES_LENGTH:SEQ_BYTES_LENGTH + IV_LENGTH]
                flag = data[-1:]
                ct = data[SEQ_BYTES_LENGTH + IV_LENGTH:-1]
                plaintext_chunk = crypto.decrypt_message(seq_bytes, iv, ct)
                full_plaintext.extend(plaintext_chunk)
                if flag == b"\x01":
                    break
            duration = time.perf_counter() - start
            self.logger.debug(f"Message received and decrypted successfully: {full_plaintext[:20]}... ({len(full_plaintext)} bytes) in {duration:.6f} seconds")
            return bytes(full_plaintext)
        except TLSError as e:
            raise
        except socket.error as e:
            raise TLSError(f"Socket error receiving application data: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

    def send_alert(self, alert_type: int, description: str = "", encrypt: bool = False) -> None:
        """
        Send a TLS alert message.

        Args:
            alert_type (int): TLS alert type code.
            description (str): Human-readable description.
            encrypt (bool): If True, encrypt the alert (post-handshake).

        Raises:
            TLSError: If sending fails.
        """
        alert_data = bytes([alert_type]) + description.encode('utf-8')
        try:
            if self.crypto and encrypt and not self.crypto.is_handshake_phase:
                seq_bytes, iv, ct = self.crypto.encrypt_message(alert_data)
                message = bytes([ALERT_TYPE]) + LEGACY_VERSION + len(seq_bytes + iv + ct).to_bytes(2, 'big') + seq_bytes + iv + ct
            else:
                message = bytes([ALERT_TYPE]) + LEGACY_VERSION + len(alert_data).to_bytes(2, 'big') + alert_data
            self.sock.send(message)
            self.logger.info(f"Sent alert {alert_type:02x} ({description})")
        except socket.error as e:
            raise TLSError(f"Failed to send alert: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

    def receive_alert(self) -> Tuple[int, str]:
        """
        Receive and process a TLS alert message.

        Returns:
            Tuple[int, str]: Alert type and description.

        Raises:
            TLSError: If message is not an alert or malformed.
        """
        try:
            header = receive_exact(self.sock, HANDSHAKE_TYPE_LENGTH)
            if header[0] != ALERT_TYPE:
                raise TLSError(f"Expected alert (0x15), got {header[0]:02x}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
            version = receive_exact(self.sock, VERSION_LENGTH)
            if version != LEGACY_VERSION:
                raise TLSError(f"Invalid alert version: {version.hex()}", ALERT_PROTOCOL_VERSION, self.logger, self)
            length = int.from_bytes(receive_exact(self.sock, LENGTH_FIELD_2_BYTES), 'big')
            data = receive_exact(self.sock, length)
            if self.crypto and not self.crypto.is_handshake_phase:
                seq_bytes = data[:SEQ_BYTES_LENGTH]
                iv = data[SEQ_BYTES_LENGTH:SEQ_BYTES_LENGTH + IV_LENGTH]
                ct = data[SEQ_BYTES_LENGTH + IV_LENGTH:]
                alert_data = self.crypto.decrypt_message(seq_bytes, iv, ct)
            else:
                alert_data = data
            alert_type = alert_data[0]
            description = alert_data[1:].decode('utf-8', errors='ignore')
            self.logger.info(f"Received alert {alert_type:02x} ({description})")
            return alert_type, description
        except TLSError as e:
            raise
        except socket.error as e:
            raise TLSError(f"Socket error receiving alert: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

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
        if header[0] != ALERT_TYPE:
            raise TLSError(f"Expected alert, got {header[0]:02x}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)

        try:
            version = receive_exact(self.sock, VERSION_LENGTH)
            if version != LEGACY_VERSION:
                raise TLSError(f"Invalid alert version: {version.hex()}", ALERT_PROTOCOL_VERSION, self.logger, self)
            length = int.from_bytes(receive_exact(self.sock, LENGTH_FIELD_2_BYTES), 'big')
            data = receive_exact(self.sock, length)
        except ConnectionError as e:
            self.logger.info("Connection closed during alert")
            return ALERT_CLOSE_NOTIFY, "Connection closed"
        except socket.error as e:
            raise TLSError(f"Socket error receiving alert: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

        try:
            if self.crypto and not self.crypto.is_handshake_phase:
                seq_iv_legnth = SEQ_BYTES_LENGTH + IV_LENGTH
                if length < seq_iv_legnth:
                    raise TLSError("Encrypted alert too short", ALERT_DECODE_ERROR, self.logger, self)
                seq_bytes = data[:SEQ_BYTES_LENGTH]
                iv = data[SEQ_BYTES_LENGTH:seq_iv_legnth]
                ct = data[seq_iv_legnth:]
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
    
    def end_session(self, log_message: str) -> None:
        """
        Terminate the session with a close_notify alert.

        Args:
            log_message (str): Message to log upon termination.
        """
        self.logger.info(log_message)
        try:
            self.send_alert(ALERT_CLOSE_NOTIFY, "Session terminated", encrypt=(self.crypto and not self.crypto.is_handshake_phase))
        except TLSError as e:
            self.logger.warning(f"Failed to send close_notify: {e}")