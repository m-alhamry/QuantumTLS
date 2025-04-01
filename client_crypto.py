# Imports necessary modules for logging, file operations, and timing
import logging
import os
import time
from typing import Dict, Tuple

# Imports cryptographic primitives for key derivation, encryption, and signatures
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate

# Imports utility functions for key generation
from crypto import generate_ecc_keys, generate_kyber_keys

class ClientCrypto:
    """
    Handles client-side cryptographic operations for a TLS 1.3-like protocol.

    Attributes:
        logger: Logger for cryptographic events.
        ecc_private_key: ECC private key for key exchange.
        ecc_public_key_bytes: Serialized ECC public key.
        kyber_kem: Kyber KEM instance for hybrid key exchange.
        kyber_pk: Kyber public key.
        kyber_ss: Kyber shared secret.
        server_public_key: Server's ECC public key.
        handshake_transcript: Accumulated handshake messages for integrity.
        initial_secret: Initial key derivation secret.
        handshake_secret: Key for handshake encryption.
        application_key: Key for application data encryption.
        cipher_suite: Negotiated cipher suite.
        cert: Client certificate.
        cert_private_key: Client certificate private key.
        ca_cert: CA certificate for verification.
        send_seq: Send sequence number (for future use).
        recv_seq: Receive sequence number (for future use).
        compute_time: Total cryptographic compute time for performance tracking.
        is_handshake_phase: True during handshake, False after completion.
    """
    def __init__(self, logger: logging.Logger):
        # Initialize logger and cryptographic attributes
        self.logger = logger
        self.ecc_private_key = None
        self.ecc_public_key_bytes = None
        self.kyber_kem = None
        self.kyber_pk = None
        self.kyber_ss = None
        self.server_public_key = None
        self.handshake_transcript = bytearray()
        self.initial_secret = None
        self.handshake_secret = None
        self.application_key = None
        self.cipher_suite = None
        self.cert = None
        self.cert_private_key = None
        self.ca_cert = None
        self.send_seq = 0
        self.recv_seq = 0
        self.compute_time = 0.0
        self.is_handshake_phase = True
        # Load certificates during initialization
        self.load_ca_certificate()
        self.load_certificate()

    def load_ca_certificate(self) -> None:
        """Load the CA certificate for verifying the server's certificate."""
        with open("ca.crt", "rb") as f:
            self.ca_cert = load_pem_x509_certificate(f.read())
        self.logger.info("Loaded CA certificate for server verification")

    def load_certificate(self) -> None:
        """
        Load and verify the client's certificate and private key against the CA.

        Raises:
            ValueError: If certificate verification fails.
        """
        # Load client certificate
        with open("client.crt", "rb") as f:
            self.cert = load_pem_x509_certificate(f.read())
        # Load client private key
        with open("client.key", "rb") as f:
            self.cert_private_key = load_pem_private_key(f.read(), password=None)
        
        try:
            # Verify client certificate against CA
            ca_public_key = self.ca_cert.public_key()
            ca_public_key.verify(
                self.cert.signature,
                self.cert.tbs_certificate_bytes,
                ec.ECDSA(hashes.SHA384())
            )
            self.logger.info("Client certificate verified against CA")
        except Exception as e:
            self.logger.error(f"Client certificate verification failed: {e}")
            raise ValueError(f"Invalid client certificate: {e}")
        self.logger.info("Loaded client certificate and private key")

    def compute_certificate_verify(self) -> bytes:
        """
        Compute the CertificateVerify message by signing the handshake transcript.

        Returns:
            bytes: Signature over the transcript.
        """
        start = time.perf_counter()
        # TLS 1.3-specific context string for CertificateVerify
        context = b" " * 64 + b"TLS 1.3, client CertificateVerify" + b"\x00"
        self.logger.debug(f"Transcript length before signing: {len(self.handshake_transcript)} bytes")
        # Compute SHA-384 hash of context and transcript
        digest = hashes.Hash(hashes.SHA384())
        digest.update(context + self.handshake_transcript)
        transcript_hash = digest.finalize()
        # Sign the hash with the client's private key
        signature = self.cert_private_key.sign(transcript_hash, ec.ECDSA(hashes.SHA384()))
        self.compute_time += time.perf_counter() - start
        self.logger.debug(f"CertificateVerify computed in {time.perf_counter() - start:.6f} seconds")
        return signature

    def verify_certificate_verify(self, signature: bytes, server_cert: bytes, transcript: bytes = None) -> bool:
        """
        Verify the server's CertificateVerify message.

        Args:
            signature: Server's signature over the transcript.
            server_cert: Server's certificate in PEM format.
            transcript: Optional transcript snapshot; defaults to current transcript.

        Returns:
            bool: True if signature is valid, False otherwise.

        Raises:
            ValueError: If certificate parsing fails.
        """
        start = time.perf_counter()
        try:
            # Parse server's certificate
            server_cert_obj = load_pem_x509_certificate(server_cert)
            server_public_key = server_cert_obj.public_key()
        except Exception as e:
            self.logger.error(f"Failed to parse server certificate: {e}")
            raise ValueError(f"Certificate parsing error: {e}")
        
        # Use provided transcript or current one
        transcript_to_use = transcript if transcript is not None else self.handshake_transcript
        # TLS 1.3-specific context string for server CertificateVerify
        context = b" " * 64 + b"TLS 1.3, server CertificateVerify" + b"\x00"
        # Compute SHA-384 hash
        digest = hashes.Hash(hashes.SHA384())
        digest.update(context + transcript_to_use)
        transcript_hash = digest.finalize()
        
        try:
            # Verify the signature
            server_public_key.verify(signature, transcript_hash, ec.ECDSA(hashes.SHA384()))
            self.compute_time += time.perf_counter() - start
            self.logger.debug(f"Server CertificateVerify verified in {time.perf_counter() - start:.6f} seconds")
            return True
        except Exception as e:
            self.logger.error(f"Server signature verification failed: {e}")
            return False

    def generate_keys(self, use_hybrid: bool, kyber_variant: int | None) -> None:
        """
        Generate ECC and optionally Kyber keys based on the cipher suite.

        Args:
            use_hybrid: True to generate both ECC and Kyber keys, False for ECC only.
            kyber_variant: Kyber variant (1=Kyber512, 2=Kyber768, 3=Kyber1024) or None.
        """
        start = time.perf_counter()
        # Generate ECC key pair
        self.ecc_private_key, _, self.ecc_public_key_bytes = generate_ecc_keys(self.logger)
        # Generate Kyber keys if hybrid mode is enabled
        if use_hybrid and kyber_variant:
            self.kyber_kem, self.kyber_pk = generate_kyber_keys(kyber_variant, self.logger)
        self.compute_time += time.perf_counter() - start
        self.logger.info(f"Generated {'hybrid ECC+Kyber' if use_hybrid else 'ECC'} keys in {time.perf_counter() - start:.6f} seconds")

    def decapsulate_kyber(self, kyber_ct: bytes) -> bytes:
        """
        Decapsulate the Kyber shared secret from the server's ciphertext.

        Args:
            kyber_ct: Kyber ciphertext received from the server.

        Returns:
            bytes: Shared secret.
        """
        start = time.perf_counter()
        # Decapsulate using the Kyber KEM instance
        kyber_ss = self.kyber_kem.decap_secret(kyber_ct)
        self.compute_time += time.perf_counter() - start
        self.logger.debug(f"Kyber decapsulation completed in {time.perf_counter() - start:.6f} seconds")
        return kyber_ss

    def derive_handshake_keys(self, server_hello: Dict[str, bytes], use_hybrid: bool) -> None:
        """
        Derive handshake keys using a multi-stage HKDF process.

        Args:
            server_hello: Server's handshake data containing public keys.
            use_hybrid: True if using hybrid key exchange with Kyber.
        """
        start = time.perf_counter()
        # Decapsulate Kyber shared secret if hybrid mode
        if use_hybrid:
            self.kyber_ss = self.decapsulate_kyber(server_hello["kyber_ct"])
        # Load server's ECC public key
        self.server_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), server_hello["ecc_pk"])
        # Compute ECC shared secret
        ecc_shared = self.ecc_private_key.exchange(ec.ECDH(), self.server_public_key)
        # Combine ECC and Kyber shared secrets if hybrid
        pre_master_secret = ecc_shared + (self.kyber_ss if use_hybrid else b"")
        # Derive initial secret
        hkdf = HKDF(algorithm=hashes.SHA384(), length=32, salt=b"", info=b"tls13 initial key")
        self.initial_secret = hkdf.derive(pre_master_secret)
        # Derive early secret (zero-filled for simplicity)
        hkdf = HKDF(algorithm=hashes.SHA384(), length=32, salt=b"", info=b"")
        early_secret = hkdf.derive(b"\x00" * 32)
        # Derive handshake secret
        hkdf = HKDF(algorithm=hashes.SHA384(), length=32, salt=early_secret, info=b"tls13 handshake key")
        self.handshake_secret = hkdf.derive(pre_master_secret)
        self.compute_time += time.perf_counter() - start
        self.logger.info(f"Derived handshake keys in {time.perf_counter() - start:.6f} seconds")

    def derive_application_key(self) -> None:
        """Derive the application key after the handshake completes."""
        start = time.perf_counter()
        # Derive master secret from handshake secret and transcript
        hkdf = HKDF(algorithm=hashes.SHA384(), length=32, salt=self.handshake_secret, info=b"tls13 master secret")
        master_secret = hkdf.derive(self.handshake_transcript)
        # Derive application key
        hkdf = HKDF(algorithm=hashes.SHA384(), length=32, salt=master_secret, info=b"tls13 application key")
        self.application_key = hkdf.derive(b"")
        # Reset sequence numbers
        self.send_seq = self.recv_seq = 0
        self.compute_time += time.perf_counter() - start
        self.logger.info(f"Derived application key in {time.perf_counter() - start:.6f} seconds")

    def compute_finished_message(self) -> bytes:
        """
        Compute the Finished message hash for handshake verification.

        Returns:
            bytes: SHA-384 hash of the handshake transcript.
        """
        start = time.perf_counter()
        # Compute SHA-384 hash of the transcript
        digest = hashes.Hash(hashes.SHA384())
        digest.update(self.handshake_transcript)
        finished = digest.finalize()
        self.compute_time += time.perf_counter() - start
        self.logger.debug(f"Finished message computed in {time.perf_counter() - start:.6f} seconds")
        return finished

    def verify_finished_message(self, received: bytes) -> bool:
        """
        Verify the server's Finished message against the local transcript hash.

        Args:
            received: Finished message received from the server.

        Returns:
            bool: True if the message matches the computed hash, False otherwise.
        """
        expected = self.compute_finished_message()
        return received == expected

    def encrypt_message(self, plaintext: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt a message using AES-GCM with the appropriate key.

        Args:
            plaintext: Data to encrypt.

        Returns:
            Tuple[bytes, bytes]: IV and ciphertext.

        Raises:
            ValueError: If no encryption key is available.
        """
        # Select the appropriate key based on handshake phase
        key = self.handshake_secret if self.is_handshake_phase else self.application_key
        if not key:
            raise ValueError("No encryption key available")
        start = time.perf_counter()
        # Generate a fresh 12-byte IV
        iv = os.urandom(12)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(iv, plaintext, None)
        self.send_seq += 1
        duration = time.perf_counter() - start
        self.logger.debug(f"Encrypted {len(plaintext)} bytes in {duration:.6f} seconds")
        return iv, ct

    def decrypt_message(self, iv: bytes, ciphertext: bytes) -> bytes:
        """
        Decrypt a message using AES-GCM with the appropriate key.

        Args:
            iv: Initialization vector.
            ciphertext: Encrypted data.

        Returns:
            bytes: Decrypted plaintext.

        Raises:
            ValueError: If no decryption key is available.
        """
        # Select the appropriate key based on handshake phase
        key = self.handshake_secret if self.is_handshake_phase else self.application_key
        if not key:
            raise ValueError("No decryption key available")
        start = time.perf_counter()
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(iv, ciphertext, None)
        self.recv_seq += 1
        duration = time.perf_counter() - start
        self.logger.debug(f"Decrypted {len(ciphertext)} bytes in {duration:.6f} seconds")
        return plaintext

    def clear_sensitive_data(self) -> None:
        """Erase sensitive cryptographic data to prevent leakage."""
        # Clear sensitive attributes
        for attr in ['kyber_ss', 'initial_secret', 'handshake_secret', 'application_key']:
            if getattr(self, attr):
                setattr(self, attr, None)
        self.ecc_private_key = None
        self.is_handshake_phase = False
        self.logger.debug("Cleared sensitive cryptographic data")