# Imports modules for logging, networking, and data packing
import logging
import socket
import struct
import time
from typing import Tuple, List

# Define TLS 1.3 alert types (RFC 8446, Section 6)
ALERT_CLOSE_NOTIFY = 0x00
ALERT_UNEXPECTED_MESSAGE = 0x0A
ALERT_BAD_RECORD_MAC = 0x14
ALERT_DECRYPTION_FAILED_RESERVED = 0x15
ALERT_RECORD_OVERFLOW = 0x16
ALERT_DECOMPRESSION_FAILURE = 0x1E
ALERT_HANDSHAKE_FAILURE = 0x28
ALERT_BAD_CERTIFICATE = 0x2A
ALERT_UNSUPPORTED_CERTIFICATE = 0x2B
ALERT_CERTIFICATE_REVOKED = 0x2C
ALERT_CERTIFICATE_EXPIRED = 0x2D
ALERT_CERTIFICATE_UNKNOWN = 0x2E
ALERT_ILLEGAL_PARAMETER = 0x2F
ALERT_UNKNOWN_CA = 0x30
ALERT_ACCESS_DENIED = 0x31
ALERT_DECODE_ERROR = 0x32
ALERT_DECRYPT_ERROR = 0x33
ALERT_EXPORT_RESTRICTION_RESERVED = 0x3C
ALERT_PROTOCOL_VERSION = 0x46
ALERT_INSUFFICIENT_SECURITY = 0x47
ALERT_INTERNAL_ERROR = 0x50
ALERT_INAPPROPRIATE_FALLBACK = 0x56
ALERT_USER_CANCELED = 0x5A
ALERT_NO_RENEGOTIATION = 0x64
ALERT_MISSING_EXTENSION = 0x6D
ALERT_UNSUPPORTED_EXTENSION = 0x6E
ALERT_CERTIFICATE_UNOBTAINABLE = 0x6F
ALERT_UNRECOGNIZED_NAME = 0x70
ALERT_BAD_CERTIFICATE_STATUS_RESPONSE = 0x71
ALERT_BAD_CERTIFICATE_HASH_VALUE = 0x72
ALERT_UNKNOWN_PSK_IDENTITY = 0x73
ALERT_CERTIFICATE_REQUIRED = 0x74

# Mapping of alert types to descriptions
ALERT_DESCRIPTIONS = {
    ALERT_CLOSE_NOTIFY: "close_notify",
    ALERT_UNEXPECTED_MESSAGE: "unexpected_message",
    ALERT_BAD_RECORD_MAC: "bad_record_mac",
    ALERT_DECRYPTION_FAILED_RESERVED: "decryption_failed_RESERVED",
    ALERT_RECORD_OVERFLOW: "record_overflow",
    ALERT_DECOMPRESSION_FAILURE: "decompression_failure",
    ALERT_HANDSHAKE_FAILURE: "handshake_failure",
    ALERT_BAD_CERTIFICATE: "bad_certificate",
    ALERT_UNSUPPORTED_CERTIFICATE: "unsupported_certificate",
    ALERT_CERTIFICATE_REVOKED: "certificate_revoked",
    ALERT_CERTIFICATE_EXPIRED: "certificate_expired",
    ALERT_CERTIFICATE_UNKNOWN: "certificate_unknown",
    ALERT_ILLEGAL_PARAMETER: "illegal_parameter",
    ALERT_UNKNOWN_CA: "unknown_ca",
    ALERT_ACCESS_DENIED: "access_denied",
    ALERT_DECODE_ERROR: "decode_error",
    ALERT_DECRYPT_ERROR: "decrypt_error",
    ALERT_EXPORT_RESTRICTION_RESERVED: "export_restriction_RESERVED",
    ALERT_PROTOCOL_VERSION: "protocol_version",
    ALERT_INSUFFICIENT_SECURITY: "insufficient_security",
    ALERT_INTERNAL_ERROR: "internal_error",
    ALERT_INAPPROPRIATE_FALLBACK: "inappropriate_fallback",
    ALERT_USER_CANCELED: "user_canceled",
    ALERT_NO_RENEGOTIATION: "no_renegotiation",
    ALERT_MISSING_EXTENSION: "missing_extension",
    ALERT_UNSUPPORTED_EXTENSION: "unsupported_extension",
    ALERT_CERTIFICATE_UNOBTAINABLE: "certificate_unobtainable",
    ALERT_UNRECOGNIZED_NAME: "unrecognized_name",
    ALERT_BAD_CERTIFICATE_STATUS_RESPONSE: "bad_certificate_status_response",
    ALERT_BAD_CERTIFICATE_HASH_VALUE: "bad_certificate_hash_value",
    ALERT_UNKNOWN_PSK_IDENTITY: "unknown_psk_identity",
    ALERT_CERTIFICATE_REQUIRED: "certificate_required"
}

# TLS 1.3 extension types
EXTENSION_SERVER_NAME = 0x0000
EXTENSION_SUPPORTED_GROUPS = 0x000A
EXTENSION_ALPN = 0x0010
EXTENSION_SUPPORTED_VERSIONS = 0x002B

# Protocol versions
TLS_VERSION_1_3 = b"\x03\x04"  # TLS 1.3
LEGACY_VERSION = b"\x03\x03"   # TLS 1.2 for record layer compatibility

# Supported groups
GROUP_SECP384R1 = 0x0018
GROUP_KYBER512 = 0xFF01
GROUP_KYBER768 = 0xFF02
GROUP_KYBER1024 = 0xFF03

# Kyber public key and ciphertext lengths
KYBER_PK_LENGTHS = {
    "TLS_AES_256_GCM_SHA384_Kyber512": 800,
    "TLS_AES_256_GCM_SHA384_Kyber768": 1184,
    "TLS_AES_256_GCM_SHA384_Kyber1024": 1568
}

KYBER_CT_LENGTHS = {
    "TLS_AES_256_GCM_SHA384_Kyber512": 768,
    "TLS_AES_256_GCM_SHA384_Kyber768": 1088,
    "TLS_AES_256_GCM_SHA384_Kyber1024": 1568
}

def encode_extension(ext_type: int, ext_data: bytes) -> bytes:
    """
    Encode an extension in Type-Length-Value (TLV) format.

    Args:
        ext_type: Extension type identifier (2 bytes).
        ext_data: Extension data.

    Returns:
        bytes: Encoded extension (type: 2 bytes, length: 2 bytes, data).
    """
    return struct.pack("!HH", ext_type, len(ext_data)) + ext_data

def decode_extensions(data: bytes) -> List[Tuple[int, bytes]]:
    """
    Decode a list of extensions from raw bytes.

    Args:
        data: Raw extension data.

    Returns:
        List of (extension type, extension data) tuples.
    """
    extensions = []
    offset = 0
    while offset < len(data):
        ext_type, ext_len = struct.unpack("!HH", data[offset:offset+4])
        ext_data = data[offset+4:offset+4+ext_len]
        extensions.append((ext_type, ext_data))
        offset += 4 + ext_len
    return extensions

def setup_logging(name: str, log_file: str, level: int = logging.INFO) -> logging.Logger:
    """
    Configure a logger with both file and console handlers.

    Args:
        name: Name of the logger (e.g., 'client', 'server').
        log_file: Path to the log file.
        level: Logging level (default: INFO).

    Returns:
        Configured logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    # File handler with detailed format
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    # Console handler with concise format
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(f'({name}) %(levelname)s: %(message)s'))
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger

def receive_exact(sock: socket.socket, size: int) -> bytes:
    """
    Receive exactly the specified number of bytes from a socket.

    Args:
        sock: Socket to read from.
        size: Number of bytes to receive.

    Returns:
        bytes: Received data.

    Raises:
        ConnectionError: If connection closes before receiving all bytes.
    """
    data = bytearray()
    while len(data) < size:
        packet = sock.recv(size - len(data))
        if not packet:
            raise ConnectionError(f"Expected {size} bytes, got {len(data)}")
        data.extend(packet)
    return bytes(data)

def prompt_ip_port(is_server: bool = False, logger: logging.Logger | None = None) -> Tuple[str, int]:
    """
    Prompt the user for an IP address and port number with input validation.

    Args:
        is_server: True if binding (server mode), False if connecting (client mode).
        logger: Optional logger for warning messages.

    Returns:
        Tuple containing validated IP address and port number.
    """
    prompt = "Enter IP address to bind" if is_server else "Enter server IP address"
    while True:
        try:
            ip = input(f"{prompt} [default: 127.0.0.1]: ").strip() or "127.0.0.1"
            socket.inet_aton(ip)  # Validate IP address
            port = int(input("Enter port number [default: 65432]: ").strip() or 65432)
            if 1 <= port <= 65535:
                return ip, port
            if logger:
                logger.warning("Port must be between 1 and 65535")
        except (ValueError, socket.error) as e:
            if logger:
                logger.warning(f"Invalid input: {e}")

def handle_session_timeout(network: 'BaseNetwork', last_activity: float, timeout: int) -> bool:
    """
    Check if the session has timed out and terminate it if necessary.

    Args:
        network: Network object with end_session method.
        last_activity: Timestamp of the last activity (in seconds since epoch).
        timeout: Timeout duration in seconds.

    Returns:
        True if the session timed out, False otherwise.
    """
    if time.time() - last_activity > timeout:
        network.end_session(f"Session timed out after {timeout} seconds")
        return True
    return False

class BaseNetwork:
    """
    Base class providing common network communication utilities, including alert handling.

    Attributes:
        logger: Logger for network events.
        sock: Socket for communication (set by subclasses).
        crypto: Cryptographic object for encryption/decryption (set by subclasses).
        MSG_TYPE_HANDSHAKE: Constant for handshake message type (0x16).
        MSG_TYPE_APPLICATION: Constant for application data type (0x17).
        ALERT_TYPE: Constant for alert message type (0x15).
        LEGACY_VERSION: TLS 1.2 version bytes (0x0303) for record layer compatibility.
    """
    MSG_TYPE_HANDSHAKE = 0x16
    MSG_TYPE_APPLICATION = 0x17
    ALERT_TYPE = 0x15
    LEGACY_VERSION = b"\x03\x03"

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.sock = None
        self.crypto = None

    def send_alert(self, alert_type: int, description: str = "", encrypt: bool = False) -> None:
        """
        Send an alert message to the peer.

        Args:
            alert_type: Alert type code (e.g., ALERT_CLOSE_NOTIFY).
            description: Optional description for debugging (default: "").
            encrypt: True to encrypt the alert (post-handshake), False otherwise.
        """
        alert_data = bytes([alert_type]) + description.encode('utf-8')
        try:
            if encrypt and self.crypto and not self.crypto.is_handshake_phase:
                # Encrypt alert if post-handshake
                iv, ct = self.crypto.encrypt_message(alert_data)
                message = bytes([self.ALERT_TYPE]) + LEGACY_VERSION + len(iv + ct).to_bytes(4, 'big') + iv + ct
                self.logger.debug(f"Sending encrypted alert: IV={iv.hex()}, CT={ct.hex()}")
            else:
                # Send unencrypted alert
                message = bytes([self.ALERT_TYPE]) + LEGACY_VERSION + len(alert_data).to_bytes(4, 'big') + alert_data
                self.logger.debug(f"Sending unencrypted alert: {alert_data.hex()}")
            self.sock.send(message)
            self.logger.info(f"Sent alert: {ALERT_DESCRIPTIONS.get(alert_type, 'Unknown')} ({alert_type:02x}) - {description}")
        except socket.error as e:
            self.logger.warning(f"Failed to send alert: {e}")

    def receive_alert(self) -> Tuple[int, str]:
        """
        Receive an alert message from the peer.

        Returns:
            Tuple containing alert type and description.

        Raises:
            ValueError: If the message is not an alert or is malformed.
        """
        try:
            header = receive_exact(self.sock, 1)
            if not header:
                self.logger.info("Connection closed during alert reception")
                return ALERT_CLOSE_NOTIFY, "Connection closed"
            if header[0] != self.ALERT_TYPE:
                raise ValueError(f"Expected alert, got {header[0]:02x}")
            version = receive_exact(self.sock, 2)
            if version != LEGACY_VERSION:
                raise ValueError(f"Invalid alert version: {version.hex()}")
            length = int.from_bytes(receive_exact(self.sock, 4), 'big')
            data = receive_exact(self.sock, length)
            if self.crypto and not self.crypto.is_handshake_phase and length >= 12:
                # Decrypt alert if post-handshake
                iv, ct = data[:12], data[12:]
                alert_data = self.crypto.decrypt_message(iv, ct)
                self.logger.debug(f"Decrypted alert: {alert_data.hex()}")
            else:
                alert_data = data
                self.logger.debug(f"Unencrypted alert: {alert_data.hex()}")
            alert_type = alert_data[0]
            description = alert_data[1:].decode('utf-8', errors='ignore')
            self.logger.info(f"Received alert: {ALERT_DESCRIPTIONS.get(alert_type, 'Unknown')} ({alert_type:02x}) - {description}")
            return alert_type, description
        except ConnectionError:
            self.logger.info("Connection closed during alert reception")
            return ALERT_CLOSE_NOTIFY, "Connection closed"
        except ValueError as e:
            self.logger.error(f"Alert processing failed: {e}")
            raise

    def end_session(self, log_message: str) -> None:
        """
        Terminate the session by sending a CLOSE_NOTIFY alert.

        Args:
            log_message: Message to log upon session closure.
        """
        self.logger.info(log_message)
        self.send_alert(ALERT_CLOSE_NOTIFY, "Session terminated", encrypt=(self.crypto and not self.crypto.is_handshake_phase))