import logging
import socket
import struct
import time
from typing import Tuple, List

# Network settings
DEFAULT_IP = "127.0.0.1"
DEFAULT_PORT = 65432
SOCKET_RECV_BUFFER_SIZE = 16384
SOCKET_CONNECT_TIMEOUT = 10.0
SOCKET_ACCEPT_TIMEOUT = 1.0
CONNECTION_RETRY_ATTEMPTS = 3
RETRY_SLEEP_SECONDS = 1
SERVER_LISTEN_BACKLOG = 5
MAX_PLAINTEXT_SIZE = 16384
SESSION_TIMEOUT = 30
LENGTH_FIELD_2_BYTES = 2
LENGTH_FIELD_4_BYTES = 4

# File locations
DEFAULT_JSON_FILE = "large_data.json"
DEFAULT_CA_CERT = "ca.crt"
DEFAULT_CLIENT_CERT = "client.crt"
DEFAULT_CLIENT_KEY = "client.key"
DEFAULT_SERVER_CERT = "server.crt"
DEFAULT_SERVER_KEY = "server.key"

# Cryptographic constants
RANDOM_BYTES_LENGTH = 32
CERT_VERIFY_CONTEXT_PADDING = b" " * 64
TLS13_CLIENT_CERT_VERIFY_CONTEXT = b"TLS 1.3, client CertificateVerify"
TLS13_SERVER_CERT_VERIFY_CONTEXT = b"TLS 1.3, server CertificateVerify"
HKDF_INFO_INITIAL_KEY = b"tls13 initial key"
HKDF_INFO_EARLY_SECRET = b""
HKDF_INFO_HANDSHAKE_KEY = b"tls13 handshake key"
HKDF_INFO_MASTER_SECRET = b"tls13 master secret"
HKDF_INFO_APPLICATION_KEY = b"tls13 application key"
KEY_LENGTH = 32
IV_LENGTH = 12
SEQ_BYTES_LENGTH = 8

# Protocol defaults
DEFAULT_SNI = b"example.com"
ALPN_HTTP = b"\x04http"
VERSION_LENGTH = 2
HANDSHAKE_TYPE_LENGTH = 1
ALERT_TYPE_LENGTH = 1
CERT_VERIFY_SIG_LENGTH_FIELD = 2

# Message types
MSG_TYPE_HANDSHAKE = 0x16
MSG_TYPE_APPLICATION = 0x17
ALERT_TYPE = 0x15

# Handshake states
STATE_CLIENT_INIT = 0
STATE_CLIENT_SENT_HELLO = 1
STATE_CLIENT_RECEIVED_SERVER_HELLO = 2
STATE_CLIENT_APPLICATION = 7
STATE_SERVER_INIT = 10
STATE_SERVER_RECEIVED_CLIENT_HELLO = 11
STATE_SERVER_SENT_HELLO = 12
STATE_SERVER_APPLICATION = 17

# TLS 1.3 handshake message types
HANDSHAKE_TYPE_CLIENT_HELLO = 0x01
HANDSHAKE_TYPE_SERVER_HELLO = 0x02
HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = 0x08
HANDSHAKE_TYPE_CERTIFICATE_REQUEST = 0x0D
HANDSHAKE_TYPE_CERTIFICATE = 0x0B
HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 0x0F
HANDSHAKE_TYPE_FINISHED = 0x14

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

# Extension types
EXTENSION_SERVER_NAME = 0x0000
EXTENSION_SUPPORTED_GROUPS = 0x000A
EXTENSION_ALPN = 0x0010
EXTENSION_SUPPORTED_VERSIONS = 0x002B
EXTENSION_SIGNATURE_ALGORITHMS = 0x000D
EXTENSION_KEY_SHARE = 0x0033

# Protocol versions
TLS_VERSION_1_3 = b"\x03\x04"
LEGACY_VERSION = b"\x03\x03"

# Supported groups
GROUP_SECP384R1 = 0x0018
GROUP_KYBER512 = 0xFF01
GROUP_KYBER768 = 0xFF02
GROUP_KYBER1024 = 0xFF03

# Signature algorithms
SIGNATURE_ECDSA_SECP384R1_SHA384 = b"\x05\x03"
SUPPORTED_SIGNATURE_ALGORITHMS = [SIGNATURE_ECDSA_SECP384R1_SHA384]

# Cipher suites
CIPHER_SUITES = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_256_GCM_SHA384_Kyber512",
    "TLS_AES_256_GCM_SHA384_Kyber768",
    "TLS_AES_256_GCM_SHA384_Kyber1024"
]

CIPHER_SUITE_CODES = {
    "TLS_AES_256_GCM_SHA384": b"\x13\x01",
    "TLS_AES_256_GCM_SHA384_Kyber512": b"\xFF\x01",
    "TLS_AES_256_GCM_SHA384_Kyber768": b"\xFF\x02",
    "TLS_AES_256_GCM_SHA384_Kyber1024": b"\xFF\x03",
}

CIPHER_SUITE_NAMES = {v: k for k, v in CIPHER_SUITE_CODES.items()}

def encode_signature_algorithms(algorithms: List[bytes]) -> bytes:
    """
    Encode a list of signature algorithms into a byte string for the TLS extension.

    Args:
        algorithms: List of signature algorithm identifiers (each 2 bytes).

    Returns:
        bytes: Encoded byte string with length prefix.
    """
    sig_alg_list = b"".join(algorithms)
    return struct.pack("!H", len(sig_alg_list)) + sig_alg_list

def encode_key_share_client_hello(key_shares: List[Tuple[int, bytes]]) -> bytes:
    """
    Encode the key share extension for the ClientHello message.

    Args:
        key_shares: List of tuples containing (group, key_exchange).

    Returns:
        bytes: Encoded extension byte string.
    """
    client_shares = b""
    for group, key_exchange in key_shares:
        client_shares += struct.pack("!H", group) + struct.pack("!H", len(key_exchange)) + key_exchange
    return encode_extension(EXTENSION_KEY_SHARE, struct.pack("!H", len(client_shares)) + client_shares)

def encode_key_share_server_hello(key_shares: List[Tuple[int, bytes]]) -> bytes:
    """
    Encode the key share extension for the ServerHello message.

    Args:
        key_shares: List of tuples containing (group, key_exchange).

    Returns:
        bytes: Encoded extension byte string.
    """
    server_shares = b""
    for group, key_exchange in key_shares:
        server_shares += struct.pack("!H", group) + struct.pack("!H", len(key_exchange)) + key_exchange
    return encode_extension(EXTENSION_KEY_SHARE, server_shares)

def encode_extension(ext_type: int, ext_data: bytes) -> bytes:
    """
    Encode a single TLS extension with type and data.

    Args:
        ext_type: Extension type (2 bytes).
        ext_data: Extension data.

    Returns:
        bytes: Encoded extension (type, length, data).
    """
    return struct.pack("!HH", ext_type, len(ext_data)) + ext_data

def decode_extensions(data: bytes) -> List[Tuple[int, bytes]]:
    """
    Decode a byte string containing multiple TLS extensions.

    Args:
        data: Byte string containing extensions.

    Returns:
        List[Tuple[int, bytes]]: List of (extension_type, extension_data) tuples.
    """
    extensions = []
    offset = 0
    while offset < len(data):
        ext_type, ext_len = struct.unpack("!HH", data[offset:offset + LENGTH_FIELD_4_BYTES])
        ext_data = data[offset + LENGTH_FIELD_4_BYTES:offset + LENGTH_FIELD_4_BYTES + ext_len]
        extensions.append((ext_type, ext_data))
        offset += LENGTH_FIELD_4_BYTES + ext_len
    return extensions

def setup_logging(name: str, log_file: str, level: int = logging.INFO) -> logging.Logger:
    """
    Configure and return a logger with file and console handlers.

    Args:
        name: Name of the logger.
        log_file: Path to the log file.
        level: Logging level (default: INFO).

    Returns:
        logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(f'({name}) %(levelname)s: %(message)s'))
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger

def receive_exact(sock: socket.socket, size: int) -> bytes:
    """
    Receive exactly the specified number of bytes from a socket.

    Args:
        sock: Socket object.
        size: Number of bytes to receive.

    Returns:
        bytes: Received data.

    Raises:
        ConnectionError: If the connection closes before all data is received.
    """
    data = bytearray()
    while len(data) < size:
        packet = sock.recv(size - len(data))
        if not packet:
            raise ConnectionError(f"Expected {size} bytes, received {len(data)}")
        data.extend(packet)
    return bytes(data)

def handle_session_timeout(network: 'BaseNetwork', last_activity: float, timeout: int) -> bool:
    """
    Check if the session has timed out and terminate it if necessary.

    Args:
        network: Network object with end_session method.
        last_activity: Timestamp of the last activity (in seconds).
        timeout: Timeout duration in seconds.

    Returns:
        bool: True if session timed out, False otherwise.
    """
    if time.time() - last_activity > timeout:
        network.end_session(f"Session timed out after {timeout} seconds")
        return True
    return False

def prompt_ip_port(is_server: bool = False, logger: logging.Logger = None) -> Tuple[str, int]:
    """
    Prompt the user for an IP address and port number.

    Args:
        is_server: If True, prompt for binding IP (server); otherwise, server IP (client).
        logger: Optional logger for error messages.

    Returns:
        Tuple[str, int]: IP address and port number.

    Raises:
        ValueError: If input is invalid (handled within the loop).
    """
    prompt = "Enter IP address to bind" if is_server else "Enter server IP address"
    while True:
        try:
            ip = input(f"{prompt} [default: {DEFAULT_IP}]: ").strip() or DEFAULT_IP
            socket.inet_aton(ip)  # Validate IP address
            port = int(input(f"Enter port number [default: {DEFAULT_PORT}]: ").strip() or DEFAULT_PORT)
            if 1 <= port <= 65535:
                return ip, port
            if logger:
                logger.warning("Port must be between 1 and 65535")
        except (ValueError, socket.error) as e:
            if logger:
                logger.warning(f"Invalid input: {e}")

class BaseNetwork:
    """Base class for network operations in TLS 1.3 communication."""

    def __init__(self, logger: logging.Logger):
        """
        Initialize the BaseNetwork instance.

        Args:
            logger: Logger instance for logging network events.
        """
        self.logger = logger
        self.sock = None
        self.crypto = None

    def send_alert(self, alert_type: int, description: str = "", encrypt: bool = False) -> None:
        """
        Send a TLS alert message.

        Args:
            alert_type: TLS alert type code (e.g., ALERT_CLOSE_NOTIFY).
            description: Human-readable description of the alert.
            encrypt: If True, encrypt the alert (used after handshake).
        """
        alert_data = bytes([alert_type]) + description.encode('utf-8')
        try:
            start_time = time.perf_counter()
            if self.crypto and not self.crypto.is_handshake_phase and encrypt:
                seq_bytes, iv, ct = self.crypto.encrypt_message(alert_data)
                message = bytes([ALERT_TYPE]) + LEGACY_VERSION + len(seq_bytes + iv + ct).to_bytes(2, 'big') + seq_bytes + iv + ct
            else:
                message = bytes([ALERT_TYPE]) + LEGACY_VERSION + len(alert_data).to_bytes(2, 'big') + alert_data
            self.sock.send(message)
            self.logger.debug(f"Sent alert in {time.perf_counter() - start_time:.6f}s: {ALERT_DESCRIPTIONS.get(alert_type, 'Unknown')} ({alert_type:02x}) - {description}")
        except socket.error as e:
            self.logger.warning(f"Failed to send alert: {e}")

    def receive_alert(self) -> Tuple[int, str]:
        """
        Receive and process a TLS alert message.

        Returns:
            Tuple[int, str]: Alert type and description.

        Raises:
            TLSError: If the message is not an alert or is malformed.
        """
        from errors import TLSError  # Late import to avoid circular dependency
        header = receive_exact(self.sock, HANDSHAKE_TYPE_LENGTH)
        if header[0] != ALERT_TYPE:
            raise TLSError(f"Expected alert, got {header[0]:02x}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
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
        self.logger.info(f"Received alert: {ALERT_DESCRIPTIONS.get(alert_type, 'Unknown')} ({alert_type:02x}) - {description}")
        return alert_type, description

    def end_session(self, log_message: str) -> None:
        """
        Terminate the session by sending a close_notify alert.

        Args:
            log_message: Message to log upon session termination.
        """
        self.logger.info(log_message)
        self.send_alert(ALERT_CLOSE_NOTIFY, "Session terminated", encrypt=(self.crypto and not self.crypto.is_handshake_phase))