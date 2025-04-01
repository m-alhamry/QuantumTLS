# Imports modules for logging, file operations, and timing
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

# Imports utility functions for key generation and encapsulation
from crypto import generate_ecc_keys, generate_kyber_keys, encapsulate_kyber

class ServerCrypto:
    """
    Handles server-side cryptographic operations for a TLS 1.3-like protocol.

    Attributes:
        logger: Logger for cryptographic events.
        ecc_private_key: ECC private key for key exchange.
        ecc_public_key_bytes: Serialized ECC public key.
        kyber_kem: Kyber KEM instance for hybrid key exchange.
        kyber_ss: Kyber shared secret.
        client_public_key: Client's ECC public key.
        handshake_transcript: Accumulated handshake messages for integrity.
        initial_secret: Initial key derivation secret.
        handshake_secret: Key for handshake encryption.
        application_key: Key for application data encryption.
        cert: Server certificate.
        cert_private_key: Server certificate private key.
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
        self.kyber_ss = None
        self.client_public_key = None
        self.handshake_transcript = bytearray()
        self.initial_secret = None
        self.handshake_secret = None
        self.application_key = None
        self.cert = None
        self.cert_private_key = None
        self.ca_cert = None
        self.send_seq = 0
        self.recv_seq = 0
        self.compute_time = 0.0
        self.is_handshake_phase = True
        self.load_certificate()

    def load_certificate(self) -> None:
        """Load the server certificate, private key, and CA certificate."""
        # Load server certificate
        with open("server.crt", "rb") as f:
            self.cert = load_pem_x509_certificate(f.read())
        # Load server private key
        with open("server.key", "rb") as f:
            self.cert_private_key = load_pem_private_key(f.read(), password=None)
        # Load CA certificate
        with open("ca.crt", "rb") as f:
            self.ca_cert = load_pem_x509_certificate(f.read())
        self.logger.info("Loaded server certificate, private key, and CA certificate")

    def compute_certificate_verify(self) -> bytes:
        """
        Compute the CertificateVerify message by signing the handshake transcript.

        Returns:
            bytes: Signature over the transcript.
        """
        start = time.perf_counter()
        # TLS 1.3-specific context string for server CertificateVerify
        context = b" " * 64 + b"TLS 1.3, server CertificateVerify" + b"\x00"
        self.logger.debug(f"Transcript length before signing: {len(self.handshake_transcript)} bytes")
        # Compute SHA-384 hash
        digest = hashes.Hash(hashes.SHA384())
        digest.update(context + self.handshake_transcript)
        transcript_hash = digest.finalize()
        # Sign the hash
        signature = self.cert_private_key.sign(transcript_hash, ec.ECDSA(hashes.SHA384()))
        self.compute_time += time.perf_counter() - start
        self.logger.debug(f"CertificateVerify computed in {time.perf_counter() - start:.6f} seconds")
        return signature

    def verify_certificate_verify(self, signature: bytes, client_cert: bytes, transcript: bytes = None) -> bool:
        """
        Verify the client's CertificateVerify message.

        Args:
            signature: Client's signature over the transcript.
            client_cert: Client's certificate in PEM format.
            transcript: Optional transcript snapshot; defaults to current transcript.

        Returns:
            bool: True if signature is valid, False otherwise.

        Raises:
            ValueError: If certificate parsing fails.
        """
        start = time.perf_counter()
        try:
            # Parse client certificate
            client_cert_obj = load_pem_x509_certificate(client_cert)
            client_public_key = client_cert_obj.public_key()
        except Exception as e:
            self.logger.error(f"Failed to parse client certificate: {e}")
            raise ValueError(f"Certificate parsing error: {e}")
        
        # Use provided or current transcript
        transcript_to_use = transcript if transcript is not None else self.handshake_transcript
        # TLS 1.3-specific context string for client CertificateVerify
        context = b" " * 64 + b"TLS 1.3, client CertificateVerify" + b"\x00"
        # Compute SHA-384 hash
        digest = hashes.Hash(hashes.SHA384())
        digest.update(context + transcript_to_use)
        transcript_hash = digest.finalize()
        
        try:
            # Verify signature
            client_public_key.verify(signature, transcript_hash, ec.ECDSA(hashes.SHA384()))
            self.compute_time += time.perf_counter() - start
            self.logger.debug(f"Client CertificateVerify verified in {time.perf_counter() - start:.6f} seconds")
            return True
        except Exception as e:
            self.logger.error(f"Client signature verification failed: {e}")
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
        # Generate Kyber keys if hybrid mode
        if use_hybrid and kyber_variant:
            self.kyber_kem, _ = generate_kyber_keys(kyber_variant, self.logger)
        self.compute_time += time.perf_counter() - start
        self.logger.info(f"Generated {'hybrid ECC+Kyber' if use_hybrid else 'ECC'} keys in {time.perf_counter() - start:.6f} seconds")

    def encapsulate_kyber(self, client_kyber_pk: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate the Kyber shared secret using the client's public key.

        Args:
            client_kyber_pk: Client's Kyber public key.

        Returns:
            Tuple[bytes, bytes]: Ciphertext and shared secret.

        Raises:
            ValueError: If encapsulation fails.
        """
        start = time.perf_counter()
        # Encapsulate using Kyber KEM
        ct, ss = encapsulate_kyber(self.kyber_kem, client_kyber_pk, self.logger)
        if not ss:
            raise ValueError("Kyber encapsulation failed")
        self.compute_time += time.perf_counter() - start
        self.logger.debug(f"Kyber encapsulation completed in {time.perf_counter() - start:.6f} seconds")
        return ct, ss

    def derive_handshake_keys(self, client_hello: Dict[str, bytes], use_hybrid: bool, kyber_ss: bytes | None) -> None:
        """
        Derive handshake keys using a multi-stage HKDF process.

        Args:
            client_hello: Client's handshake data containing public keys and certificate.
            use_hybrid: True if using hybrid key exchange with Kyber.
            kyber_ss: Kyber shared secret or None if not hybrid.

        Raises:
            ValueError: If client certificate verification fails.
        """
        start = time.perf_counter()
        # Verify client certificate
        cert = load_pem_x509_certificate(client_hello["cert"])
        try:
            ca_public_key = self.ca_cert.public_key()
            ca_public_key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA384()))
            self.logger.info("Verified client certificate against CA")
        except Exception as e:
            self.logger.error(f"Client certificate verification failed: {e}")
            raise ValueError(f"Client certificate verification failed: {e}")
        # Load client's ECC public key
        self.client_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), client_hello["ecc_pk"])
        # Compute ECC shared secret
        ecc_shared = self.ecc_private_key.exchange(ec.ECDH(), self.client_public_key)
        # Combine ECC and Kyber shared secrets if hybrid
        pre_master_secret = ecc_shared + (kyber_ss if use_hybrid else b"")
        # Derive initial secret
        hkdf = HKDF(algorithm=hashes.SHA384(), length=32, salt=b"", info=b"tls13 initial key")
        self.initial_secret = hkdf.derive(pre_master_secret)
        # Derive early secret
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
        # Derive master secret
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
        # Compute SHA-384 hash
        digest = hashes.Hash(hashes.SHA384())
        digest.update(self.handshake_transcript)
        finished = digest.finalize()
        self.compute_time += time.perf_counter() - start
        self.logger.debug(f"Finished message computed in {time.perf_counter() - start:.6f} seconds")
        return finished

    def verify_finished_message(self, received: bytes) -> bool:
        """
        Verify the client's Finished message against the local transcript hash.

        Args:
            received: Finished message received from the client.

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
        # Select appropriate key
        key = self.handshake_secret if self.is_handshake_phase else self.application_key
        if not key:
            raise ValueError("No encryption key available")
        start = time.perf_counter()
        # Generate fresh IV
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
        # Select appropriate key
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