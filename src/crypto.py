import time
import logging
from typing import Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate

import oqs
import os
from datetime import datetime, timezone

from src.errors import TLSError
from src.utils import (
    ALERT_BAD_CERTIFICATE, ALERT_CERTIFICATE_EXPIRED, ALERT_DECODE_ERROR, ALERT_HANDSHAKE_FAILURE,
    ALERT_BAD_RECORD_MAC, ALERT_UNEXPECTED_MESSAGE, ALERT_INTERNAL_ERROR, ALERT_ILLEGAL_PARAMETER,
    CERT_VERIFY_CONTEXT_PADDING, DEFAULT_CA_CERT, HKDF_INFO_EARLY_SECRET, HKDF_INFO_HANDSHAKE_KEY,
    HKDF_INFO_INITIAL_KEY, IV_LENGTH, HKDF_INFO_MASTER_SECRET, HKDF_INFO_APPLICATION_KEY, KEM_MAP,
    KEY_LENGTH, KYBER_CT_SIZES, KYBER_PK_SIZES, SEQ_BYTES_LENGTH, SIGNATURE_ECDSA_SECP384R1_SHA384
)

def generate_ecc_keys(logger: logging.Logger) -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey, bytes]:
    """
    Generate ECC private and public keys using the secp384r1 curve.

    Args:
        logger (logging.Logger): Logger for debugging and performance logging.

    Returns:
        Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey, bytes]: Private key, public key, and public key bytes.

    Raises:
        TLSError: If key generation fails due to cryptographic library issues.
    """
    start = time.perf_counter()
    try:
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()
        public_key_bytes = public_key.public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
    except Exception as e:
        raise TLSError(f"ECC key generation failed: {e}", ALERT_INTERNAL_ERROR, logger)
    duration = time.perf_counter() - start
    logger.debug(f"Generated ECC keys in {duration:.6f} seconds")
    return private_key, public_key, public_key_bytes

def generate_kyber_keys(variant: int | None, logger: logging.Logger) -> Tuple[oqs.KeyEncapsulation, bytes]:
    """
    Generate Kyber key encapsulation mechanism (KEM) keys.

    Args:
        variant (int | None): Kyber variant (1=Kyber512, 2=Kyber768, 3=Kyber1024, None defaults to Kyber768).
        logger (logging.Logger): Logger for debugging and performance logging.

    Returns:
        Tuple[oqs.KeyEncapsulation, bytes]: KEM object and public key.

    Raises:
        TLSError: If an invalid variant is provided or key generation fails.
    """
    start = time.perf_counter()
    kem_alg = KEM_MAP.get(variant, "Kyber768")
    if variant not in KEM_MAP and variant is not None:
        raise TLSError(f"Invalid Kyber variant: {variant}", ALERT_ILLEGAL_PARAMETER, logger)
    try:
        kem = oqs.KeyEncapsulation(kem_alg)
        public_key = kem.generate_keypair()
    except Exception as e:
        raise TLSError(f"Kyber key generation failed for {kem_alg}: {e}", ALERT_INTERNAL_ERROR, logger)
    duration = time.perf_counter() - start
    logger.debug(f"Generated {kem_alg} keys in {duration:.6f} seconds")
    return kem, public_key

def get_hash(input_data: bytes) -> bytes:
    """
    Compute the SHA384 hash of the input data.

    Args:
        input_data (bytes): Data to hash.

    Returns:
        bytes: SHA384 hash value.

    Raises:
        TLSError: If hashing fails due to cryptographic library issues.
    """
    try:
        digest = hashes.Hash(hashes.SHA384())
        digest.update(input_data)
        return digest.finalize()
    except Exception as e:
        raise TLSError(f"Hash computation failed: {e}", ALERT_INTERNAL_ERROR)

def validate_and_verify_certificate_verify(body: bytes, cert_bytes: bytes, network, crypto, logger) -> None:
    """
    Validate and verify the CertificateVerify message.

    Args:
        body (bytes): CertificateVerify message body.
        cert_bytes (bytes): Certificate bytes to verify against.
        network: Network object for sending alerts.
        crypto: Crypto instance with verification methods.
        logger (logging.Logger): Logger for debugging.

    Raises:
        TLSError: If the message is invalid or verification fails.
    """
    if len(body) < 4:
        raise TLSError("Invalid CertificateVerify message length", ALERT_DECODE_ERROR, logger, network)
    
    algorithm = body[0:2]
    sig_len = int.from_bytes(body[2:4], 'big')
    if len(body) != 4 + sig_len:
        raise TLSError(f"Invalid signature length in CertificateVerify: expected {4 + sig_len}, got {len(body)}", ALERT_DECODE_ERROR, logger, network)
    signature = body[4:4 + sig_len]

    if algorithm != SIGNATURE_ECDSA_SECP384R1_SHA384:
        raise TLSError(f"Unsupported signature algorithm: {algorithm.hex()}", ALERT_HANDSHAKE_FAILURE, logger, network)

    transcript_snapshot = bytes(crypto.handshake_transcript)
    if not crypto.verify_certificate_verify(signature, cert_bytes, transcript_snapshot):
        raise TLSError("CertificateVerify verification failed", ALERT_BAD_CERTIFICATE, logger, network)

def parse_and_validate_certificate(body: bytes, network, context: str = "Client") -> bytes:
    """
    Parse and validate a Certificate message.

    Args:
        body (bytes): Certificate message body.
        network: Network object for sending alerts.
        context (str): "Client" or "Server" to indicate the certificate source.

    Returns:
        bytes: Raw certificate bytes if valid.

    Raises:
        TLSError: If parsing or validation fails.
    """
    if context == "Client":
        if len(body) < 4:
            raise TLSError("Invalid Certificate message length", ALERT_DECODE_ERROR, network.logger, network)
        context_length = body[0]
        if context_length != 0:
            raise TLSError("Unexpected certificate_request_context", ALERT_UNEXPECTED_MESSAGE, network.logger, network)
        cert_list_len = int.from_bytes(body[1:4], 'big')
        if len(body) != 4 + cert_list_len:
            raise TLSError(f"Invalid certificate_list length: expected {4 + cert_list_len}, got {len(body)}", ALERT_DECODE_ERROR, network.logger, network)
        cert_list = body[4:4 + cert_list_len]
        
        if len(cert_list) < 6:
            raise TLSError("Certificate_list too short", ALERT_DECODE_ERROR, network.logger, network)
        cert_type = cert_list[0]
        if cert_type != 0:  # X.509
            raise TLSError(f"Unsupported certificate_type: {cert_type}", ALERT_HANDSHAKE_FAILURE, network.logger, network)
        cert_data_len = int.from_bytes(cert_list[1:4], 'big')
        if len(cert_list) < 4 + cert_data_len + 2:
            raise TLSError(f"Invalid cert_data length: expected {4 + cert_data_len + 2}, got {len(cert_list)}", ALERT_DECODE_ERROR, network.logger, network)
        ext_len = int.from_bytes(cert_list[4 + cert_data_len:6 + cert_data_len], 'big')
        if ext_len != 0:
            raise TLSError("Certificate extensions not supported", ALERT_HANDSHAKE_FAILURE, network.logger, network)
        cert_bytes = cert_list[4:4 + cert_data_len]
    else:  # Server
        cert_len = int.from_bytes(body[1:4], 'big')
        if len(body) < 4 + cert_len:
            raise TLSError(f"Invalid server certificate length: expected >= {4 + cert_len}, got {len(body)}", ALERT_DECODE_ERROR, network.logger, network)
        cert_bytes = body[4:4 + cert_len]

    try:
        cert_obj = load_der_x509_certificate(cert_bytes)
    except ValueError as e:
        raise TLSError(f"Failed to parse {context} certificate: {e}", ALERT_BAD_CERTIFICATE, network.logger, network)
    
    ca_cert = network.crypto.ca_cert
    ca_public_key = ca_cert.public_key()
    try:
        ca_public_key.verify(cert_obj.signature, cert_obj.tbs_certificate_bytes, ec.ECDSA(hashes.SHA384()))
    except Exception:
        raise TLSError(f"{context} certificate signature verification failed", ALERT_BAD_CERTIFICATE, network.logger, network)
    
    current_time = datetime.now(timezone.utc)
    if current_time < cert_obj.not_valid_before_utc:
        raise TLSError(f"{context} certificate not yet valid", ALERT_BAD_CERTIFICATE, network.logger, network)
    elif current_time > cert_obj.not_valid_after_utc:
        raise TLSError(f"{context} certificate has expired", ALERT_CERTIFICATE_EXPIRED, network.logger, network)
    
    network.logger.debug(f"Validated {context} certificate")
    return cert_bytes

class TLSCrypto:
    """
    Base class for TLS 1.3 cryptographic operations, implementing key derivation and encryption (RFC 8446, Section 7).
    """

    def __init__(self, logger: logging.Logger, network=None):
        """
        Initialize the TLSCrypto instance.

        Args:
            logger (logging.Logger): Logger for cryptographic events.
            network (optional): Network object for sending alerts.

        Raises:
            TLSError: If CA certificate loading fails.
        """
        self.logger = logger
        self.network = network
        self.cert = None
        self.cert_private_key = None
        self.ca_cert = None
        self.cipher_suite = None  # Selected cipher suite
        self.ecc_private_key = None
        self.ecc_public_key_bytes = None
        self.kyber_ss = None  # Kyber shared secret
        self.handshake_transcript = bytearray()
        self.initial_secret = None
        self.handshake_secret = None
        self.application_key = None
        self.send_seq = 0
        self.recv_seq = 0
        self.is_handshake_phase = True
        self._load_ca_certificate()

    def _load_ca_certificate(self) -> None:
        """Load the CA certificate for verification."""
        try:
            with open(DEFAULT_CA_CERT, "rb") as f:
                self.ca_cert = load_pem_x509_certificate(f.read())
            self.logger.debug(f"Loaded CA certificate")
        except Exception as e:
            raise TLSError(f"Failed to load CA certificate: {e}", ALERT_INTERNAL_ERROR, self.logger, self.network)

    def load_certificate(self, cert_path: str, key_path: str) -> None:
        """
        Load and verify the certificate and private key.

        Args:
            cert_path (str): Path to the certificate file.
            key_path (str): Path to the private key file.

        Raises:
            TLSError: If certificate loading or verification fails.
        """
        try:
            with open(cert_path, "rb") as f:
                self.cert = load_pem_x509_certificate(f.read())
            with open(key_path, "rb") as f:
                self.cert_private_key = load_pem_private_key(f.read(), password=None)
            ca_public_key = self.ca_cert.public_key()
            ca_public_key.verify(self.cert.signature, self.cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA384()))
            public_key_from_private = self.cert_private_key.public_key()
            cert_public_key = self.cert.public_key()
            if public_key_from_private.public_numbers() != cert_public_key.public_numbers():
                raise TLSError("Private key does not match certificate", ALERT_INTERNAL_ERROR, self.logger, self.network)
            self.logger.debug(f"Loaded and verified certificate")
        except Exception as e:
            raise TLSError(f"Failed to load or verify certificate: {e}", ALERT_INTERNAL_ERROR, self.logger, self.network)

    def compute_certificate_verify(self) -> bytes:
        """
        Compute the CertificateVerify signature over the handshake transcript.

        Returns:
            bytes: ECDSA signature.

        Raises:
            TLSError: If prerequisites are missing.
        """
        if not self.cert_private_key:
            raise TLSError("Private key not loaded", ALERT_INTERNAL_ERROR, self.logger, self.network)
        if not self.certificate_verify_context:
            raise TLSError("Certificate verify context not set", ALERT_INTERNAL_ERROR, self.logger, self.network)
        transcript_hash = self.get_transcript_hash()
        context = CERT_VERIFY_CONTEXT_PADDING + self.certificate_verify_context + b"\x00"
        signature_input = context + transcript_hash
        try:
            signature = self.cert_private_key.sign(signature_input, ec.ECDSA(hashes.SHA384()))
        except Exception as e:
            raise TLSError(f"Failed to compute CertificateVerify: {e}", ALERT_INTERNAL_ERROR, self.logger, self.network)
        self.logger.debug(f"Computed CertificateVerify")
        return signature

    def verify_certificate_verify(self, signature: bytes, peer_cert_bytes: bytes, transcript: bytes = None) -> bool:
        """
        Verify the peer's CertificateVerify signature.

        Args:
            signature (bytes): Signature to verify.
            peer_cert_bytes (bytes): Peer's certificate bytes.
            transcript (bytes, optional): Transcript snapshot (defaults to current).

        Returns:
            bool: True if valid, raises exception otherwise.

        Raises:
            TLSError: If verification fails or prerequisites are missing.
        """
        if not self.peer_certificate_verify_context:
            raise TLSError("Peer certificate verify context not set", ALERT_INTERNAL_ERROR, self.logger, self.network)
        try:
            peer_cert_obj = load_der_x509_certificate(peer_cert_bytes)
            peer_public_key = peer_cert_obj.public_key()
            transcript_to_use = transcript if transcript is not None else self.handshake_transcript
            context = CERT_VERIFY_CONTEXT_PADDING + self.peer_certificate_verify_context + b"\x00"
            signature_input = context + get_hash(transcript_to_use)
            peer_public_key.verify(signature, signature_input, ec.ECDSA(hashes.SHA384()))
        except Exception as e:
            raise TLSError(f"CertificateVerify verification failed: {e}", ALERT_BAD_CERTIFICATE, self.logger, self.network)
        return True
    
    def get_expected_kyber_pk_size(self, cipher_suite) -> int | None:
        """Return the expected Kyber public key size based on the cipher suite."""
        return KYBER_PK_SIZES.get(cipher_suite)

    def get_expected_kyber_ct_size(self, cipher_suite) -> int | None:
        """Return the expected Kyber ciphertext size based on the cipher suite."""
        return KYBER_CT_SIZES.get(cipher_suite)

    def generate_ecc_keys(self) -> None:
        """Generate and store ECC keys for the TLS handshake."""
        self.ecc_private_key, _, self.ecc_public_key_bytes = generate_ecc_keys(self.logger)

    def encrypt_message(self, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt a message using AES-GCM with the current key.

        Args:
            plaintext (bytes): Data to encrypt.

        Returns:
            Tuple[bytes, bytes, bytes]: Sequence number bytes, IV, and ciphertext.

        Raises:
            TLSError: If encryption fails or no key is available.
        """
        key = self.handshake_secret if self.is_handshake_phase else self.application_key
        if not key:
            raise TLSError("No encryption key available", ALERT_INTERNAL_ERROR, self.logger, self.network)
        iv = os.urandom(IV_LENGTH)
        try:
            aesgcm = AESGCM(key)
            if not self.is_handshake_phase:
                self.send_seq += 1
                seq_bytes = self.send_seq.to_bytes(SEQ_BYTES_LENGTH, 'big')
                ct = aesgcm.encrypt(iv, plaintext, seq_bytes)
            else:
                seq_bytes = b''
                ct = aesgcm.encrypt(iv, plaintext, None)
        except Exception as e:
            raise TLSError(f"Encryption failed: {e}", ALERT_INTERNAL_ERROR, self.logger, self.network)
        return seq_bytes, iv, ct

    def decrypt_message(self, seq_bytes: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        """
        Decrypt a message using AES-GCM with the current key.

        Args:
            seq_bytes (bytes): Sequence number bytes (application phase only).
            iv (bytes): Initialization vector.
            ciphertext (bytes): Encrypted data.

        Returns:
            bytes: Decrypted plaintext.

        Raises:
            TLSError: If decryption fails, replay detected, or sequence invalid.
        """
        key = self.handshake_secret if self.is_handshake_phase else self.application_key
        if not key:
            raise TLSError("No decryption key available", ALERT_INTERNAL_ERROR, self.logger, self.network)
        try:
            aesgcm = AESGCM(key)
            if not self.is_handshake_phase:
                if len(seq_bytes) != SEQ_BYTES_LENGTH:
                    raise TLSError(f"Invalid sequence number length: expected {SEQ_BYTES_LENGTH}, got {len(seq_bytes)}", ALERT_BAD_RECORD_MAC, self.logger, self.network)
                received_seq = int.from_bytes(seq_bytes, 'big')
                expected_seq = self.recv_seq + 1
                if received_seq != expected_seq:
                    raise TLSError(f"Replay detected: expected seq {expected_seq}, got {received_seq}", ALERT_BAD_RECORD_MAC, self.logger, self.network)
                plaintext = aesgcm.decrypt(iv, ciphertext, seq_bytes)
                self.recv_seq = received_seq
            else:
                if seq_bytes:
                    raise TLSError("Unexpected sequence number in handshake phase", ALERT_UNEXPECTED_MESSAGE, self.logger, self.network)
                plaintext = aesgcm.decrypt(iv, ciphertext, None)
        except InvalidTag:
            raise TLSError("Decryption failed due to invalid tag", ALERT_BAD_RECORD_MAC, self.logger, self.network)
        except Exception as e:
            raise TLSError(f"Decryption failed: {e}", ALERT_INTERNAL_ERROR, self.logger, self.network)
        return plaintext

    def compute_finished_message(self) -> bytes:
        """
        Compute the Finished message hash for the handshake.

        Returns:
            bytes: SHA384 hash of the handshake transcript.

        Raises:
            TLSError: If hash computation fails.
        """
        try:
            finished = get_hash(self.handshake_transcript)
        except TLSError as e:
            raise TLSError(f"Failed to compute Finished message: {e}", ALERT_INTERNAL_ERROR, self.logger, self.network)
        self.logger.debug(f"Computed Finished message")
        return finished

    def verify_finished_message(self, received: bytes) -> bool:
        """
        Verify the received Finished message against the computed hash.

        Args:
            received (bytes): Received Finished message.

        Returns:
            bool: True if verification succeeds.

        Raises:
            TLSError: If hash computation fails.
        """
        expected = self.compute_finished_message()
        result = received == expected
        self.logger.debug(f"Finished message verification: {'success' if result else 'failed'}")
        return result

    def derive_handshake_keys(self, pre_master_secret: bytes) -> None:
        """
        Derive handshake keys from the pre-master secret.

        Args:
            pre_master_secret (bytes): Pre-master secret from key exchange.

        Raises:
            TLSError: If key derivation fails.
        """
        start = time.perf_counter()
        try:
            hkdf = HKDF(algorithm=hashes.SHA384(), length=KEY_LENGTH, salt=b"", info=HKDF_INFO_INITIAL_KEY)
            self.initial_secret = hkdf.derive(pre_master_secret)
            hkdf = HKDF(algorithm=hashes.SHA384(), length=KEY_LENGTH, salt=b"", info=HKDF_INFO_EARLY_SECRET)
            early_secret = hkdf.derive(b"\x00" * KEY_LENGTH)
            hkdf = HKDF(algorithm=hashes.SHA384(), length=KEY_LENGTH, salt=early_secret, info=HKDF_INFO_HANDSHAKE_KEY)
            self.handshake_secret = hkdf.derive(pre_master_secret)
        except Exception as e:
            raise TLSError(f"Handshake key derivation failed: {e}", ALERT_INTERNAL_ERROR, self.logger, self.network)
        duration = time.perf_counter() - start
        self.logger.debug(f"Derived handshake keys in {duration:.6f} seconds")

    def derive_application_key(self) -> None:
        """
        Derive the application key from the handshake secret and transcript.

        Raises:
            TLSError: If key derivation fails.
        """
        start = time.perf_counter()
        try:
            hkdf = HKDF(algorithm=hashes.SHA384(), length=KEY_LENGTH, salt=self.handshake_secret, info=HKDF_INFO_MASTER_SECRET)
            master_secret = hkdf.derive(self.handshake_transcript)
            hkdf = HKDF(algorithm=hashes.SHA384(), length=KEY_LENGTH, salt=master_secret, info=HKDF_INFO_APPLICATION_KEY)
            self.application_key = hkdf.derive(b"")
            self.send_seq = 0
            self.recv_seq = 0
            self.is_handshake_phase = False
        except Exception as e:
            raise TLSError(f"Application key derivation failed: {e}", ALERT_INTERNAL_ERROR, self.logger, self.network)
        duration = time.perf_counter() - start
        self.logger.debug(f"Derived application key in {duration:.6f} seconds")

    def get_transcript_hash(self) -> bytes:
        """
        Compute the SHA384 hash of the current handshake transcript.

        Returns:
            bytes: Transcript hash.

        Raises:
            TLSError: If hash computation fails.
        """
        try:
            return get_hash(self.handshake_transcript)
        except TLSError as e:
            raise TLSError(f"Transcript hash computation failed: {e}", ALERT_INTERNAL_ERROR, self.logger, self.network)

    def clear_sensitive_data(self) -> None:
        """
        Clear all sensitive cryptographic data from memory.
        """
        for attr in ['initial_secret', 'handshake_secret', 'application_key', 'ecc_private_key']:
            setattr(self, attr, None)
        self.is_handshake_phase = False
        self.logger.debug(f"Cleared sensitive cryptographic data")