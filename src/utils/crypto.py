"""QTL2 cryptography. TLS-inspired schedule with a separate QTL2 domain."""
from __future__ import annotations
import hashlib
import hmac
import logging
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from src.utils.certificates import validate_ca, validate_certificate
from src.utils.errors import TLSError
from src.utils.utils import (
    ALERT_BAD_CERTIFICATE, ALERT_BAD_RECORD_MAC, ALERT_CERTIFICATE_REQUIRED,
    ALERT_DECODE_ERROR, ALERT_HANDSHAKE_FAILURE, ALERT_ILLEGAL_PARAMETER, ALERT_INTERNAL_ERROR,
    CERT_VERIFY_CONTEXT_PADDING, DEFAULT_CERT_DIR, HASH_LENGTH, IV_LENGTH, KEY_LENGTH,
    KEM_MAP, KYBER_CT_SIZES, KYBER_PK_SIZES, MAX_RECORDS_PER_KEY, MAX_TRANSCRIPT_SIZE,
    Reader, SEQ_BYTES_LENGTH, SIGNATURE_ECDSA_SECP384R1_SHA384, vector,
)


def generate_ecc_keys(logger):
    key = ec.generate_private_key(ec.SECP384R1())
    public = key.public_key()
    return key, public, public.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def create_kem(variant):
    if variant not in KEM_MAP:
        raise TLSError(f'Invalid KEM variant: {variant}', ALERT_ILLEGAL_PARAMETER)
    try:
        import oqs  # ECC-only operation never imports OQS or generates KEM keys.
        return oqs.KeyEncapsulation(KEM_MAP[variant])
    except Exception as exc:
        raise TLSError(f'KEM unavailable: {KEM_MAP[variant]}', ALERT_INTERNAL_ERROR) from exc


def generate_kyber_keys(variant, logger):
    kem = create_kem(2 if variant is None else variant)
    try:
        return kem, kem.generate_keypair()
    except Exception:
        kem.free()
        raise


def get_hash(data):
    return hashlib.sha384(data).digest()


def hkdf_extract(salt, ikm):
    return hmac.digest(salt, ikm, 'sha384')


def expand_label(secret, label, context=b'', length=HASH_LENGTH):
    label = b'qtl2 ' + label
    info = length.to_bytes(2, 'big') + vector(label, 1) + vector(context, 1)
    return HKDFExpand(algorithm=hashes.SHA384(), length=length, info=info).derive(secret)


def derive_secret(secret, label, transcript=b''):
    return expand_label(secret, label, get_hash(transcript))


def encode_certificate(cert):
    der = cert.public_bytes(serialization.Encoding.DER)
    return b'\x00' + vector(vector(der, 3) + b'\x00\x00', 3)


def parse_and_validate_certificate(body, network, context='Client'):
    try:
        reader = Reader(body)
        if reader.vector(1) != b'':
            raise ValueError('Certificate context must be empty')
        entries = Reader(reader.vector(3))
        reader.finish()
        if not entries.data:
            raise TLSError('Certificate required', ALERT_CERTIFICATE_REQUIRED)
        cert_bytes = entries.vector(3)
        if entries.vector() != b'':
            raise ValueError('Certificate entry extensions not supported')
        entries.finish()
        cert = x509.load_der_x509_certificate(cert_bytes)
    except TLSError:
        raise
    except ValueError as exc:
        raise TLSError(f'Malformed certificate message: {exc}', ALERT_DECODE_ERROR) from exc
    validate_certificate(cert, network.crypto.ca_cert, context.lower(),
                         network.server_name if context == 'Server' else None)
    return cert_bytes


def validate_and_verify_certificate_verify(body, cert_bytes, network, crypto, logger):
    try:
        reader = Reader(body)
        if reader.take(2) != SIGNATURE_ECDSA_SECP384R1_SHA384:
            raise ValueError('Unsupported signature algorithm')
        signature = reader.vector()
        reader.finish()
    except ValueError as exc:
        raise TLSError(str(exc), ALERT_DECODE_ERROR) from exc
    crypto.verify_certificate_verify(signature, cert_bytes)


class TLSCrypto:
    """Historical class name; this implements QTL2, not interoperable TLS."""
    def __init__(self, logger: logging.Logger, network=None, *, role, cert_dir=DEFAULT_CERT_DIR):
        self.logger = logger
        self.network = network
        self.role = role
        self.cert_dir = Path(cert_dir)
        self.cert = self.cert_private_key = self.ca_cert = None
        self.cipher_suite = None
        self.ecc_private_key = self.ecc_public_key_bytes = None
        self.handshake_transcript = bytearray()
        self.handshake_secret = None
        self.application_transcript = None
        self.send_key = self.recv_key = self.send_iv = self.recv_iv = None
        self.send_finished_key = self.recv_finished_key = None
        self.send_seq = self.recv_seq = 0
        self.is_handshake_phase = True
        self._load_ca_certificate()

    @property
    def keys_ready(self):
        return self.send_key is not None and self.recv_key is not None

    def _load_ca_certificate(self):
        try:
            self.ca_cert = x509.load_pem_x509_certificate((self.cert_dir / 'ca.crt').read_bytes())
            validate_ca(self.ca_cert)
        except TLSError:
            raise
        except (OSError, ValueError) as exc:
            raise TLSError(f'Cannot load trust root: {exc}', ALERT_INTERNAL_ERROR) from exc

    def load_certificate(self, cert_path, key_path):
        try:
            cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
            key = serialization.load_pem_private_key(Path(key_path).read_bytes(), password=None)
            validate_certificate(cert, self.ca_cert, self.role)
            if key.public_key().public_numbers() != cert.public_key().public_numbers():
                raise ValueError('Private key does not match certificate')
            self.cert, self.cert_private_key = cert, key
        except TLSError:
            raise
        except Exception as exc:
            raise TLSError(f'Cannot load identity: {exc}', ALERT_BAD_CERTIFICATE) from exc

    def load_identity(self):
        self.load_certificate(self.cert_dir / (self.role + '.crt'), self.cert_dir / (self.role + '.key'))

    def append_handshake(self, kind, body):
        message = bytes([kind]) + vector(body, 3)
        if len(self.handshake_transcript) + len(message) > MAX_TRANSCRIPT_SIZE:
            raise TLSError('Handshake transcript too large', ALERT_DECODE_ERROR)
        self.handshake_transcript.extend(message)

    def get_transcript_hash(self):
        return get_hash(self.handshake_transcript)

    def _signature_input(self, peer=False, transcript=None):
        role = ('server' if self.role == 'client' else 'client') if peer else self.role
        context = b'QTL2 ' + role.encode('ascii') + b' CertificateVerify'
        return CERT_VERIFY_CONTEXT_PADDING + context + b'\x00' + get_hash(
            self.handshake_transcript if transcript is None else transcript)

    def compute_certificate_verify(self):
        if self.cert_private_key is None:
            raise TLSError('Identity not loaded', ALERT_INTERNAL_ERROR)
        return self.cert_private_key.sign(self._signature_input(), ec.ECDSA(hashes.SHA384()))

    def verify_certificate_verify(self, signature, peer_cert_bytes, transcript=None):
        try:
            key = x509.load_der_x509_certificate(peer_cert_bytes).public_key()
            key.verify(signature, self._signature_input(True, transcript), ec.ECDSA(hashes.SHA384()))
        except Exception as exc:
            raise TLSError('CertificateVerify verification failed', ALERT_BAD_CERTIFICATE) from exc
        return True

    def generate_ecc_keys(self):
        self.ecc_private_key, _, self.ecc_public_key_bytes = generate_ecc_keys(self.logger)

    def get_expected_kyber_pk_size(self, suite):
        return KYBER_PK_SIZES.get(suite)

    def get_expected_kyber_ct_size(self, suite):
        return KYBER_CT_SIZES.get(suite)

    def derive_handshake_keys(self, pre_master_secret):
        zero = bytes(HASH_LENGTH)
        early = hkdf_extract(zero, zero)
        self.handshake_secret = hkdf_extract(derive_secret(early, b'derived'), pre_master_secret)

    def _set_traffic_keys(self, client_secret, server_secret):
        send, recv = (client_secret, server_secret) if self.role == 'client' else (server_secret, client_secret)
        self.send_key = expand_label(send, b'key', length=KEY_LENGTH)
        self.recv_key = expand_label(recv, b'key', length=KEY_LENGTH)
        self.send_iv = expand_label(send, b'iv', length=IV_LENGTH)
        self.recv_iv = expand_label(recv, b'iv', length=IV_LENGTH)
        self.send_seq = self.recv_seq = 0
        return send, recv

    def activate_handshake_keys(self):
        if self.handshake_secret is None or self.keys_ready:
            raise TLSError('Invalid handshake key transition', ALERT_INTERNAL_ERROR)
        client = derive_secret(self.handshake_secret, b'c hs traffic', self.handshake_transcript)
        server = derive_secret(self.handshake_secret, b's hs traffic', self.handshake_transcript)
        send, recv = self._set_traffic_keys(client, server)
        self.send_finished_key = expand_label(send, b'finished')
        self.recv_finished_key = expand_label(recv, b'finished')

    def compute_finished_message(self):
        if self.send_finished_key is None:
            raise TLSError('Finished key unavailable', ALERT_INTERNAL_ERROR)
        return hmac.digest(self.send_finished_key, self.get_transcript_hash(), 'sha384')

    def verify_finished_message(self, received):
        if self.recv_finished_key is None:
            raise TLSError('Finished key unavailable', ALERT_INTERNAL_ERROR)
        expected = hmac.digest(self.recv_finished_key, self.get_transcript_hash(), 'sha384')
        return hmac.compare_digest(received, expected)

    def derive_application_key(self):
        if self.handshake_secret is None or self.application_transcript is None or not self.is_handshake_phase:
            raise TLSError('Invalid application key transition', ALERT_INTERNAL_ERROR)
        master = hkdf_extract(derive_secret(self.handshake_secret, b'derived'), bytes(HASH_LENGTH))
        self._set_traffic_keys(derive_secret(master, b'c ap traffic', self.application_transcript),
                               derive_secret(master, b's ap traffic', self.application_transcript))
        self.handshake_secret = self.send_finished_key = self.recv_finished_key = None
        self.ecc_private_key = self.cert_private_key = None
        self.is_handshake_phase = False

    @staticmethod
    def nonce(iv, seq):
        return bytes(a ^ b for a, b in zip(iv, seq.to_bytes(IV_LENGTH, 'big')))

    def encrypt_message(self, plaintext, aad=b''):
        if not self.keys_ready:
            raise TLSError('Encryption keys unavailable', ALERT_INTERNAL_ERROR)
        if self.send_seq >= MAX_RECORDS_PER_KEY:
            raise TLSError('Traffic key limit reached; reconnect', ALERT_HANDSHAKE_FAILURE)
        seq = self.send_seq.to_bytes(SEQ_BYTES_LENGTH, 'big')
        iv = self.nonce(self.send_iv, self.send_seq)
        ct = AESGCM(self.send_key).encrypt(iv, plaintext, aad + seq)
        self.send_seq += 1
        return seq, iv, ct

    def decrypt_message(self, seq_bytes, iv, ciphertext, aad=b''):
        if not self.keys_ready:
            raise TLSError('Decryption keys unavailable', ALERT_INTERNAL_ERROR)
        if self.recv_seq >= MAX_RECORDS_PER_KEY:
            raise TLSError('Traffic key limit reached; reconnect', ALERT_HANDSHAKE_FAILURE)
        if len(seq_bytes) != SEQ_BYTES_LENGTH or int.from_bytes(seq_bytes, 'big') != self.recv_seq:
            raise TLSError('Replay or out-of-order record', ALERT_BAD_RECORD_MAC)
        if iv != self.nonce(self.recv_iv, self.recv_seq):
            raise TLSError('Invalid record nonce', ALERT_BAD_RECORD_MAC)
        try:
            plaintext = AESGCM(self.recv_key).decrypt(iv, ciphertext, aad + seq_bytes)
        except (InvalidTag, ValueError) as exc:
            raise TLSError('Record authentication failed', ALERT_BAD_RECORD_MAC) from exc
        self.recv_seq += 1
        return plaintext

    def clear_sensitive_data(self):
        # Python cannot guarantee physical erasure of immutable bytes. Drop references;
        # subclasses also explicitly cleanse/free native KEM storage.
        for attr in ('handshake_secret', 'application_transcript', 'send_key', 'recv_key',
                     'send_iv', 'recv_iv', 'send_finished_key', 'recv_finished_key',
                     'ecc_private_key', 'cert_private_key'):
            setattr(self, attr, None)
        self.handshake_transcript = bytearray()
        self.is_handshake_phase = False
