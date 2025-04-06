# Imports modules for logging, networking, and data packing
from asyncio.log import logger
import logging
import socket
import struct
import time
from typing import Tuple, List

# Handshake states for client
STATE_CLIENT_INIT = 0
STATE_CLIENT_SENT_HELLO = 1
STATE_CLIENT_RECEIVED_SERVER_HELLO = 2
STATE_CLIENT_RECEIVED_SERVER_CERT_VERIFY = 3
STATE_CLIENT_SENT_CERT_VERIFY = 4
STATE_CLIENT_SENT_FINISHED = 5
STATE_CLIENT_RECEIVED_SERVER_FINISHED = 6
STATE_CLIENT_APPLICATION = 7

# Handshake states for server
STATE_SERVER_INIT = 10
STATE_SERVER_RECEIVED_CLIENT_HELLO = 11
STATE_SERVER_SENT_HELLO = 12
STATE_SERVER_SENT_CERT_VERIFY = 13
STATE_SERVER_RECEIVED_CLIENT_CERT_VERIFY = 14
STATE_SERVER_RECEIVED_CLIENT_FINISHED = 15
STATE_SERVER_SENT_FINISHED = 16
STATE_SERVER_APPLICATION = 17

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

# Extension types (IANA registry: https://www.iana.org/assignments/tls-extensiontype-values/)
EXTENSION_SERVER_NAME = 0x0000
EXTENSION_SUPPORTED_GROUPS = 0x000A
EXTENSION_ALPN = 0x0010
EXTENSION_SUPPORTED_VERSIONS = 0x002B
EXTENSION_SIGNATURE_ALGORITHMS = 0x000D
EXTENSION_KEY_SHARE = 0x0033

# Protocol versions
TLS_VERSION_1_3 = b"\x03\x04"  # TLS 1.3
LEGACY_VERSION = b"\x03\x03"   # TLS 1.2 for record layer compatibility

# Supported groups
GROUP_SECP384R1 = 0x0018
GROUP_KYBER512 = 0xFF01
GROUP_KYBER768 = 0xFF02
GROUP_KYBER1024 = 0xFF03

# Supported signature algorithms
SIGNATURE_ECDSA_SECP384R1_SHA384 = b"\x05\x03"  # ecdsa_secp384r1_sha384
SIGNATURE_RSA_PSS_RSAE_SHA384 = b"\x08\x05"     # rsa_pss_rsae_sha384
SUPPORTED_SIGNATURE_ALGORITHMS = [
    SIGNATURE_ECDSA_SECP384R1_SHA384,
    SIGNATURE_RSA_PSS_RSAE_SHA384,
]

# CIPHER_SUITES: List of available cipher suites for negotiation
CIPHER_SUITES = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_256_GCM_SHA384_Kyber512",
    "TLS_AES_256_GCM_SHA384_Kyber768",
    "TLS_AES_256_GCM_SHA384_Kyber1024"
]

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

# Maximum plaintext size per TLS record
MAX_PLAINTEXT_SIZE = 16384

# Helper function to encode Signature Algorithms extension
def encode_signature_algorithms(algorithms: List[bytes]) -> bytes:
    """
    Encode the Signature Algorithms extension for ClientHello.
    
    Args:
        algorithms: List of 2-byte signature algorithm identifiers.
    
    Returns:
        bytes: Encoded extension data (length + list of algorithms).
    """
    sig_alg_list = b"".join(algorithms)
    return struct.pack("!H", len(sig_alg_list)) + sig_alg_list

# Helper functions for Key Share extension
def encode_key_share_client_hello(key_shares: List[Tuple[int, bytes]]) -> bytes:
    """
    Encode the Key Share extension for ClientHello with multiple key shares.
    
    Args:
        key_shares: List of (group, key_exchange) tuples.
    
    Returns:
        bytes: Encoded extension (length + list of key share entries).
    """
    client_shares = b""
    for group, key_exchange in key_shares:
        client_shares += struct.pack("!H", group) + struct.pack("!H", len(key_exchange)) + key_exchange
    return encode_extension(EXTENSION_KEY_SHARE, struct.pack("!H", len(client_shares)) + client_shares)

def encode_key_share_server_hello(key_shares: List[Tuple[int, bytes]]) -> bytes:
    """
    Encode the Key Share extension for ServerHello with multiple key shares.
    
    Args:
        key_shares: List of (group, key_exchange) tuples.
    
    Returns:
        bytes: Encoded extension (list of key share entries).
    """
    server_shares = b""
    for group, key_exchange in key_shares:
        server_shares += struct.pack("!H", group) + struct.pack("!H", len(key_exchange)) + key_exchange
    return encode_extension(EXTENSION_KEY_SHARE, server_shares)

# Encode an extension: type (2 bytes) + length (2 bytes) + data
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

# Decode extensions from a byte string
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
        try:
            packet = sock.recv(size - len(data))
            if not packet:
                raise ConnectionError(f"Expected {size} bytes, got {len(data)}")
            data.extend(packet)
        except socket.error as e:
            raise  # Let caller handle socket-specific errors
    return bytes(data)

# SESSION_TIMEOUT: Time in seconds after which the session times out
SESSION_TIMEOUT = 30

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

def prompt_cipher_suite(cipher_suite) -> str:
    """
    Prompt the server user to select a cipher suite from available options sent by the client.

    Returns:
        str: The selected cipher suite.
    """
    # Display the available cipher suites to the user
    print("\nClient supported cipher suites::")
    for i, suite in enumerate(cipher_suite, 1):
        print(f"{i}. {suite}")
    
    # Loop until a valid choice is made
    while True:
        try:
            # Prompt the user for a choice, defaulting to 1
            choice = input(f"Choose a cipher suite (1-{len(cipher_suite)}) [default: 1]: ").strip() or "1"
            
            # Convert the choice to an integer
            choice = int(choice)
            
            # Check if the choice is within the valid range
            if 1 <= choice <= len(cipher_suite):
                # Return the selected cipher suite
                return cipher_suite[choice - 1]
            
            # Log a warning for an invalid choice
            logger.warning(f"Invalid choice. Enter a number between 1 and {len(cipher_suite)}.")
        except ValueError:
            # Log a warning for invalid input
            logger.warning("Invalid input. Please enter a number.")

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
            alert_type (int): Alert type code (e.g., ALERT_CLOSE_NOTIFY).
            description (str): Optional description for debugging.
            encrypt (bool): True to encrypt the alert (post-handshake).
        """
        alert_data = bytes([alert_type]) + description.encode('utf-8')
        try:
            if self.crypto and not self.crypto.is_handshake_phase and encrypt:
                seq_bytes, iv, ct = self.crypto.encrypt_message(alert_data)
                message = bytes([self.ALERT_TYPE]) + LEGACY_VERSION + len(seq_bytes + iv + ct).to_bytes(4, 'big') + seq_bytes + iv + ct
                self.logger.debug(f"Sending encrypted alert: seq={seq_bytes.hex()}, IV={iv.hex()}, CT={ct.hex()}")
            else:
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
            Tuple[int, str]: Alert type and description.

        Raises:
            TLSError: If the message is not an alert or is malformed.
        """
        from errors import TLSError  # Local import to avoid circular dependency
        try:
            header = receive_exact(self.sock, 1)
            if header[0] != self.ALERT_TYPE:
                raise TLSError(f"Expected alert, got {header[0]:02x}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
            version = receive_exact(self.sock, 2)
            if version != LEGACY_VERSION:
                raise TLSError(f"Invalid alert version: {version.hex()}", ALERT_PROTOCOL_VERSION, self.logger, self)
            length = int.from_bytes(receive_exact(self.sock, 4), 'big')
            data = receive_exact(self.sock, length)

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
            self.logger.info(f"Received alert: {ALERT_DESCRIPTIONS.get(alert_type, 'Unknown')} ({alert_type:02x}) - {description}")
            return alert_type, description
        except ConnectionError:
            self.logger.info("Connection closed during alert reception")
            return ALERT_CLOSE_NOTIFY, "Connection closed"
        except TLSError as e:
            raise
        except Exception as e:
            raise TLSError(f"Alert processing failed: {e}", ALERT_DECODE_ERROR, self.logger, self)

    def end_session(self, log_message: str) -> None:
        """
        Terminate the session by sending a CLOSE_NOTIFY alert.

        Args:
            log_message (str): Message to log upon session closure.
        """
        self.logger.info(log_message)
        self.send_alert(ALERT_CLOSE_NOTIFY, "Session terminated", encrypt=(self.crypto and not self.crypto.is_handshake_phase))