import time
import logging
from typing import Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import oqs
import os

from errors import TLSError
from utils import (
    ALERT_INTERNAL_ERROR, ALERT_HANDSHAKE_FAILURE, ALERT_BAD_RECORD_MAC, 
    IV_LENGTH, HKDF_INFO_MASTER_SECRET, HKDF_INFO_APPLICATION_KEY,
    KEY_LENGTH, SEQ_BYTES_LENGTH
)

def generate_ecc_keys(logger: logging.Logger) -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey, bytes]:
    """
    Generate ECC private and public keys using the secp384r1 curve.

    Args:
        logger: Logger instance for debugging and performance logging.

    Returns:
        Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey, bytes]: Private key, public key, and public key bytes.
    """
    start = time.perf_counter()
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    logger.debug(f"Generated ECC keys in {time.perf_counter() - start:.6f} seconds")
    return private_key, public_key, public_key_bytes

def generate_kyber_keys(variant: int | None, logger: logging.Logger) -> Tuple[oqs.KeyEncapsulation, bytes]:
    """
    Generate Kyber key encapsulation mechanism (KEM) keys.

    Args:
        variant: Kyber variant (1 for Kyber512, 2 for Kyber768, 3 for Kyber1024, None defaults to Kyber768).
        logger: Logger instance for debugging and performance logging.

    Returns:
        Tuple[oqs.KeyEncapsulation, bytes]: KEM object and public key.
    """
    start = time.perf_counter()
    kem_map = {1: "Kyber512", 2: "Kyber768", 3: "Kyber1024"}
    kem_alg = kem_map.get(variant, "Kyber768")
    kem = oqs.KeyEncapsulation(kem_alg) # Kyber private key stored inside kem
    public_key = kem.generate_keypair()
    logger.debug(f"Generated {kem_alg} keys in {time.perf_counter() - start:.6f} seconds")
    return kem, public_key

def get_hash(input_data: bytes) -> bytes:
    """
    Compute the SHA384 hash of the input data.

    Args:
        input_data: Data to hash.

    Returns:
        bytes: SHA384 hash value.
    """
    digest = hashes.Hash(hashes.SHA384())
    digest.update(input_data)
    return digest.finalize()

class TLSCrypto:
    """Base class for TLS 1.3 cryptographic operations."""

    def __init__(self, logger: logging.Logger, network=None):
        """
        Initialize the TLSCrypto instance.

        Args:
            logger: Logger instance for logging cryptographic events.
            network: Optional network object for sending alerts.
        """
        self.logger = logger
        self.network = network
        self.handshake_transcript = bytearray()
        self.initial_secret = None
        self.handshake_secret = None
        self.application_key = None
        self.send_seq = 0
        self.recv_seq = 0
        self.compute_time = 0.0
        self.is_handshake_phase = True
        self.ecc_private_key = None
        self.ecc_public_key_bytes = None

    def generate_ecc_keys(self) -> None:
        """Generate ECC keys for the TLS handshake and store them in the instance."""
        self.ecc_private_key, _, self.ecc_public_key_bytes = generate_ecc_keys(self.logger)

    def encrypt_message(self, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt a message using AES-GCM with the current key.

        Args:
            plaintext: Data to encrypt.

        Returns:
            Tuple[bytes, bytes, bytes]: Sequence number bytes, IV, and ciphertext.

        Raises:
            TLSError: If no encryption key is available.
        """
        key = self.handshake_secret if self.is_handshake_phase else self.application_key
        if not key:
            raise TLSError("No encryption key available", ALERT_INTERNAL_ERROR, self.logger, self.network)
        iv = os.urandom(IV_LENGTH)
        aesgcm = AESGCM(key)
        if not self.is_handshake_phase:
            self.send_seq += 1
            seq_bytes = self.send_seq.to_bytes(SEQ_BYTES_LENGTH, 'big')
            ct = aesgcm.encrypt(iv, plaintext, seq_bytes)
        else:
            seq_bytes = b''
            ct = aesgcm.encrypt(iv, plaintext, None)
        return seq_bytes, iv, ct

    def decrypt_message(self, seq_bytes: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        """
        Decrypt a message using AES-GCM with the current key.

        Args:
            seq_bytes: Sequence number bytes (used in application phase).
            iv: Initialization vector.
            ciphertext: Encrypted data.

        Returns:
            bytes: Decrypted plaintext.

        Raises:
            TLSError: If decryption fails or replay is detected.
        """
        key = self.handshake_secret if self.is_handshake_phase else self.application_key
        if not key:
            raise TLSError("No decryption key available", ALERT_INTERNAL_ERROR, self.logger, self.network)
        aesgcm = AESGCM(key)
        try:
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
                    raise TLSError("Unexpected sequence number in handshake phase", ALERT_HANDSHAKE_FAILURE, self.logger, self.network)
                plaintext = aesgcm.decrypt(iv, ciphertext, None)
        except InvalidTag:
            raise TLSError("Decryption failed due to invalid tag", ALERT_BAD_RECORD_MAC, self.logger, self.network)
        return plaintext

    def compute_finished_message(self) -> bytes:
        """
        Compute the Finished message hash for the handshake.

        Returns:
            bytes: SHA384 hash of the handshake transcript.
        """
        start = time.perf_counter()
        finished = get_hash(self.handshake_transcript)
        duration = time.perf_counter() - start
        self.compute_time += duration
        self.logger.debug(f"Computed Finished message in {duration:.6f}s")
        return finished

    def verify_finished_message(self, received: bytes) -> bool:
        """
        Verify the received Finished message against the computed hash.

        Args:
            received: Received Finished message.

        Returns:
            bool: True if verification succeeds, False otherwise.
        """
        expected = self.compute_finished_message()
        result = received == expected
        self.logger.debug(f"Finished message verification: {'success' if result else 'failed'}")
        return result

    def derive_application_key(self) -> None:
        """
        Derive the application key from the handshake secret and transcript.
        """
        start = time.perf_counter()
        hkdf = HKDF(algorithm=hashes.SHA384(), length=KEY_LENGTH, salt=self.handshake_secret, info=HKDF_INFO_MASTER_SECRET)
        master_secret = hkdf.derive(self.handshake_transcript)
        hkdf = HKDF(algorithm=hashes.SHA384(), length=KEY_LENGTH, salt=master_secret, info=HKDF_INFO_APPLICATION_KEY)
        self.application_key = hkdf.derive(b"")
        self.send_seq = 0
        self.recv_seq = 0
        self.is_handshake_phase = False
        duration = time.perf_counter() - start
        self.compute_time += duration
        self.logger.debug(f"Derived application key in {duration:.6f}s, send_seq={self.send_seq}, recv_seq={self.recv_seq}")

    def get_transcript_hash(self) -> bytes:
        """
        Compute the SHA384 hash of the current handshake transcript.

        Returns:
            bytes: Transcript hash.
        """
        return get_hash(self.handshake_transcript)

    def clear_sensitive_data(self) -> None:
        """
        Clear all sensitive cryptographic data from memory.
        """
        for attr in ['initial_secret', 'handshake_secret', 'application_key']:
            if getattr(self, attr):
                setattr(self, attr, None)
        self.ecc_private_key = None
        self.is_handshake_phase = False
        self.logger.debug("Cleared sensitive cryptographic data")