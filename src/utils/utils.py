"""Constants and bounded binary encoding for the custom QTL2 protocol."""
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import struct

DEFAULT_IP = '127.0.0.1'
DEFAULT_PORT = 65432
DEFAULT_CIPHER = 6  # ML-KEM-768
DEFAULT_CERT_DIR = Path('credentials')
DEFAULT_JSON_FILE = str(Path(__file__).resolve().parents[1] / 'large_data.json')
HANDSHAKE_TIMEOUT = 10.0
SESSION_TIMEOUT = 30.0
MESSAGE_TIMEOUT = 30.0
SHUTDOWN_TIMEOUT = 5.0
MAX_CONNECTIONS = 16
MAX_PLAINTEXT_SIZE = 16384
MAX_MESSAGE_SIZE = 8 * 1024 * 1024
MAX_MESSAGE_CHUNKS = 4096
MAX_RECORDS_PER_KEY = 1 << 20
MAX_TRANSCRIPT_SIZE = 65536
RECORD_MAGIC = b'QTL2'
RECORD_HEADER = struct.Struct('!4sBI')
MAX_RECORD_SIZE = MAX_PLAINTEXT_SIZE + 32
PROTOCOL_VERSION = b'\x00\x02'
KEY_LENGTH = 32
IV_LENGTH = 12
SEQ_BYTES_LENGTH = 8
HASH_LENGTH = 48
CERT_VERIFY_CONTEXT_PADDING = b' ' * 64
TLS13_CLIENT_CERT_VERIFY_CONTEXT = b'QTL2 client CertificateVerify'
TLS13_SERVER_CERT_VERIFY_CONTEXT = b'QTL2 server CertificateVerify'
SIGNATURE_ECDSA_SECP384R1_SHA384 = b'\x05\x03'
MSG_TYPE_HANDSHAKE = 0x16
MSG_TYPE_APPLICATION = 0x17
ALERT_TYPE = 0x15
HANDSHAKE_TYPE_CLIENT_HELLO = 1
HANDSHAKE_TYPE_SERVER_HELLO = 2
HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = 8
HANDSHAKE_TYPE_CERTIFICATE = 11
HANDSHAKE_TYPE_CERTIFICATE_REQUEST = 13
HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 15
HANDSHAKE_TYPE_FINISHED = 20
HANDSHAKE_TYPE_ACK = 254
STATE_CLIENT_INIT = 0
STATE_CLIENT_SENT_HELLO = 1
STATE_CLIENT_RECEIVED_SERVER_HELLO = 2
STATE_CLIENT_APPLICATION = 7
STATE_SERVER_INIT = 10
STATE_SERVER_RECEIVED_CLIENT_HELLO = 11
STATE_SERVER_SENT_HELLO = 12
STATE_SERVER_APPLICATION = 17
ALERT_CLOSE_NOTIFY = 0
ALERT_UNEXPECTED_MESSAGE = 10
ALERT_BAD_RECORD_MAC = 20
ALERT_RECORD_OVERFLOW = 22
ALERT_HANDSHAKE_FAILURE = 40
ALERT_BAD_CERTIFICATE = 42
ALERT_CERTIFICATE_EXPIRED = 45
ALERT_ILLEGAL_PARAMETER = 47
ALERT_DECODE_ERROR = 50
ALERT_PROTOCOL_VERSION = 70
ALERT_INTERNAL_ERROR = 80
ALERT_CERTIFICATE_REQUIRED = 116
ALERT_DESCRIPTIONS = {
    0: 'close_notify', 10: 'unexpected_message', 20: 'bad_record_mac',
    22: 'record_overflow', 40: 'handshake_failure', 42: 'bad_certificate',
    45: 'certificate_expired', 47: 'illegal_parameter', 50: 'decode_error',
    70: 'protocol_version', 80: 'internal_error', 116: 'certificate_required',
}
GROUP_SECP384R1 = 0x0018
# Historical suite labels retained as Python API names, not TLS wire compatibility.
CIPHER_SUITES = ['TLS_AES_256_GCM_SHA384'] + [
    'TLS_AES_256_GCM_SHA384_' + name
    for name in ['Kyber512', 'Kyber768', 'Kyber1024', 'MLKEM512', 'MLKEM768', 'MLKEM1024']
]
CIPHER_SUITE_CODES = {suite: (0x1302 if i == 0 else 0xFF00 + i).to_bytes(2, 'big')
                      for i, suite in enumerate(CIPHER_SUITES)}
CIPHER_SUITE_NAMES = {code: suite for suite, code in CIPHER_SUITE_CODES.items()}
KEM_MAP = {1: 'Kyber512', 2: 'Kyber768', 3: 'Kyber1024',
           4: 'ML-KEM-512', 5: 'ML-KEM-768', 6: 'ML-KEM-1024'}
KYBER_VARIANTS = {suite: i for i, suite in enumerate(CIPHER_SUITES) if i}
KYBER_GROUPS = {suite: 0xFF00 + i for suite, i in KYBER_VARIANTS.items()}
KYBER_PK_SIZES = {suite: [800, 1184, 1568][(i - 1) % 3] for suite, i in KYBER_VARIANTS.items()}
KYBER_CT_SIZES = {suite: [768, 1088, 1568][(i - 1) % 3] for suite, i in KYBER_VARIANTS.items()}


def vector(data: bytes, width: int = 2) -> bytes:
    return len(data).to_bytes(width, 'big') + data


class Reader:
    """Every nested length is checked and every structure must be fully consumed."""
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, size: int) -> bytes:
        if size < 0 or size > len(self.data) - self.pos:
            raise ValueError('Truncated message')
        result = self.data[self.pos:self.pos + size]
        self.pos += size
        return result

    def uint(self, width: int) -> int:
        return int.from_bytes(self.take(width), 'big')

    def vector(self, width: int = 2) -> bytes:
        return self.take(self.uint(width))

    def finish(self):
        if self.pos != len(self.data):
            raise ValueError('Unexpected trailing bytes')


def close_logging(logger):
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        handler.close()


def setup_logging(name: str, log_file: str, level=logging.INFO):
    # Only entry points configure logs. Connections share one bounded rotating log.
    logger = logging.getLogger(name)
    close_logging(logger)
    logger.setLevel(level)
    logger.propagate = False
    Path(log_file).parent.mkdir(parents=True, exist_ok=True)
    file_handler = RotatingFileHandler(log_file, maxBytes=2 * 1024 * 1024, backupCount=3, encoding='utf-8')
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
    file_handler.setFormatter(formatter)
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.addHandler(console)
    return logger
