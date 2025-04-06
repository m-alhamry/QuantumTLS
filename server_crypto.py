import logging
import os
import time
from typing import Dict, Tuple

import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate

from crypto import TLSError, generate_ecc_keys, generate_kyber_keys, encapsulate_kyber
from utils import ALERT_BAD_CERTIFICATE, ALERT_HANDSHAKE_FAILURE, ALERT_INTERNAL_ERROR, ALERT_BAD_RECORD_MAC

class ServerCrypto:
    """
    Handles server-side cryptographic operations for a TLS 1.3-like protocol.

    Attributes:
        logger (logging.Logger): Logger for cryptographic events.
        network (Any, optional): Network object for sending alerts.
        ecc_private_key: ECC private key for key exchange.
        ecc_public_key_bytes: Serialized ECC public key.
        kyber_kem: Kyber KEM instance for hybrid key exchange.
        kyber_ss: Kyber shared secret.
        client_public_key: Client's ECC public key.
        handshake_transcript (bytearray): Accumulated handshake messages.
        initial_secret: Initial key derivation secret.
        handshake_secret: Key for handshake encryption.
        application_key: Key for application data encryption.
        cert: Server certificate.
        cert_private_key: Server certificate private key.
        ca_cert: CA certificate for verification.
        send_seq (int): Send sequence number.
        recv_seq (int): Receive sequence number.
        compute_time (float): Total cryptographic compute time.
        is_handshake_phase (bool): True during handshake, False after.
    """
    SEQ_BYTES_LENGTH = 8  # 8 bytes for a 64-bit integer sequence number

    def __init__(self, logger: logging.Logger, network=None):
        """
        Initialize the ServerCrypto object.

        Args:
            logger: Logger for cryptographic events.
            network (optional): Network object for sending alerts via TLSError.
        """
        self.logger = logger
        self.network = network
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
        """
        Load and verify the server's certificate and private key against the CA.

        Raises:
            TLSError: If certificate loading or verification fails.
        """
        try:
            with open("server.crt", "rb") as f:
                self.cert = load_pem_x509_certificate(f.read())
        except FileNotFoundError:
            raise TLSError("Server certificate file not found", ALERT_INTERNAL_ERROR, self.logger, self.network)
        except Exception as e:
            raise TLSError(f"Failed to load server certificate: {e}", ALERT_INTERNAL_ERROR, self.logger, self.network)

        try:
            with open("server.key", "rb") as f:
                self.cert_private_key = load_pem_private_key(f.read(), password=None)
        except FileNotFoundError:
            raise TLSError("Server private key file not found", ALERT_INTERNAL_ERROR, self.logger, self.network)
        except Exception as e:
            raise TLSError(f"Failed to load server private key: {e}", ALERT_INTERNAL_ERROR, self.logger, self.network)

        try:
            with open("ca.crt", "rb") as f:
                self.ca_cert = load_pem_x509_certificate(f.read())
        except FileNotFoundError:
            raise TLSError("CA certificate file not found", ALERT_INTERNAL_ERROR, self.logger, self.network)
        except Exception as e:
            raise TLSError(f"Failed to load CA certificate: {e}", ALERT_INTERNAL_ERROR, self.logger, self.network)

        try:
            ca_public_key = self.ca_cert.public_key()
            ca_public_key.verify(self.cert.signature, self.cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA384()))
            self.logger.info("Server certificate verified against CA")
        except Exception as e:
            raise TLSError(f"Server certificate verification failed: {e}", ALERT_BAD_CERTIFICATE, self.logger, self.network)

        self.logger.info("Loaded server certificate and private key")

    def compute_certificate_verify(self) -> bytes:
        """
        Compute the CertificateVerify message by signing the handshake transcript.

        Returns:
            bytes: Signature over the transcript.

        Raises:
            TLSError: If signature computation fails.
        """
        start = time.perf_counter()
        context = b" " * 64 + b"TLS 1.3, server CertificateVerify" + b"\x00"
        self.logger.debug(f"Transcript length before signing: {len(self.handshake_transcript)} bytes")

        try:
            digest = hashes.Hash(hashes.SHA384())
            digest.update(context + self.handshake_transcript)
            transcript_hash = digest.finalize()
            signature = self.cert_private_key.sign(transcript_hash, ec.ECDSA(hashes.SHA384()))
        except Exception as e:
            raise TLSError(f"Failed to compute CertificateVerify signature: {e}", ALERT_INTERNAL_ERROR, self.logger, self.network)

        self.compute_time += time.perf_counter() - start
        self.logger.debug(f"Computed CertificateVerify in {time.perf_counter() - start:.6f} seconds")
        return signature

    def verify_certificate_verify(self, signature: bytes, client_cert: bytes, transcript: bytes = None) -> bool:
        """
        Verify the client's CertificateVerify message.

        Args:
            signature (bytes): Client's signature over the transcript.
            client_cert (bytes): Client's certificate in PEM format.
            transcript (bytes, optional): Transcript snapshot; defaults to current transcript.

        Returns:
            bool: True if signature is valid.

        Raises:
            TLSError: If certificate parsing or signature verification fails.
        """
        start = time.perf_counter()
        try:
            client_cert_obj = load_pem_x509_certificate(client_cert)
            client_public_key = client_cert_obj.public_key()
        except Exception as e:
            raise TLSError(f"Failed to parse client certificate: {e}", ALERT_BAD_CERTIFICATE, self.logger, self.network)

        transcript_to_use = transcript if transcript is not None else self.handshake_transcript
        context = b" " * 64 + b"TLS 1.3, client CertificateVerify" + b"\x00"
        try:
            digest = hashes.Hash(hashes.SHA384())
            digest.update(context + transcript_to_use)
            transcript_hash = digest.finalize()
            client_public_key.verify(signature, transcript_hash, ec.ECDSA(hashes.SHA384()))
        except Exception as e:
            raise TLSError(f"Client CertificateVerify verification failed: {e}", ALERT_BAD_CERTIFICATE, self.logger, self.network)

        self.compute_time += time.perf_counter() - start
        self.logger.debug(f"Verified client CertificateVerify in {time.perf_counter() - start:.6f} seconds")
        return True

    def generate_keys(self, use_hybrid: bool, kyber_variant: int | None) -> None:
        """
        Generate ECC and optionally Kyber keys based on the cipher suite.

        Args:
            use_hybrid (bool): True for both ECC and Kyber keys, False for ECC only.
            kyber_variant (int | None): Kyber variant (1=Kyber512, 2=Kyber768, 3=Kyber1024) or None.

        Raises:
            TLSError: If key generation fails.
        """
        start = time.perf_counter()
        try:
            self.ecc_private_key, _, self.ecc_public_key_bytes = generate_ecc_keys(self.logger)
        except Exception as e:
            raise TLSError(f"ECC key generation failed: {e}", ALERT_INTERNAL_ERROR, self.logger, self.network)

        if use_hybrid and kyber_variant:
            try:
                self.kyber_kem, self.kyber_pk = generate_kyber_keys(kyber_variant, self.logger)
            except TLSError as e:
                raise TLSError(f"Kyber key generation failed: {e}", e.alert_type, self.logger, self.network)

        self.compute_time += time.perf_counter() - start
        self.logger.debug(f"Generated keys in {time.perf_counter() - start:.6f} seconds")

    def encapsulate_kyber(self, client_kyber_pk: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate the Kyber shared secret using the client's public key.

        Args:
            client_kyber_pk (bytes): Client's Kyber public key.

        Returns:
            Tuple[bytes, bytes]: Ciphertext and shared secret.

        Raises:
            TLSError: If encapsulation fails.
        """
        start = time.perf_counter()
        try:
            ct, ss = encapsulate_kyber(self.kyber_kem, client_kyber_pk, self.logger)
        except Exception as e:
            raise TLSError(f"Kyber encapsulation failed: {e}", ALERT_INTERNAL_ERROR, self.logger, self.network)

        self.compute_time += time.perf_counter() - start
        self.logger.debug(f"Encapsulated Kyber shared secret in {time.perf_counter() - start:.6f} seconds")
        return ct, ss

    def derive_handshake_keys(self, client_hello: Dict[str, bytes], use_hybrid: bool, kyber_ss: bytes | None) -> None:
        """
        Derive handshake keys from the client's hello message.

        Args:
            client_hello (Dict[str, bytes]): Client's handshake data.
            use_hybrid (bool): True for hybrid key exchange.
            kyber_ss (bytes | None): Kyber shared secret if hybrid.

        Raises:
            TLSError: If key derivation fails.
        """
        start = time.perf_counter()
        try:
            self.client_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), client_hello["ecc_pk"])
            ecc_shared = self.ecc_private_key.exchange(ec.ECDH(), self.client_public_key)
        except Exception as e:
            raise TLSError(f"ECDH shared secret computation failed: {e}", ALERT_HANDSHAKE_FAILURE, self.logger, self.network)

        if use_hybrid:
            if kyber_ss is None:
                raise TLSError("Missing Kyber shared secret for hybrid mode", ALERT_HANDSHAKE_FAILURE, self.logger, self.network)
            try:
                combined_secret = ecc_shared + kyber_ss
                digest = hashes.Hash(hashes.SHA384())
                digest.update(combined_secret)
                pre_master_secret = digest.finalize()
            except Exception as e:
                raise TLSError(f"Hybrid key derivation failed: {e}", ALERT_HANDSHAKE_FAILURE, self.logger, self.network)
        else:
            pre_master_secret = ecc_shared

        try:
            hkdf = HKDF(algorithm=hashes.SHA384(), length=32, salt=b"", info=b"tls13 initial key")
            self.initial_secret = hkdf.derive(pre_master_secret)
            hkdf = HKDF(algorithm=hashes.SHA384(), length=32, salt=b"", info=b"")
            early_secret = hkdf.derive(b"\x00" * 32)
            hkdf = HKDF(algorithm=hashes.SHA384(), length=32, salt=early_secret, info=b"tls13 handshake key")
            self.handshake_secret = hkdf.derive(pre_master_secret)
        except Exception as e:
            raise TLSError(f"Handshake key derivation failed: {e}", ALERT_HANDSHAKE_FAILURE, self.logger, self.network)

        self.compute_time += time.perf_counter() - start

    def derive_application_key(self) -> None:
        """
        Derive the application key after the handshake completes.

        Raises:
            TLSError: If key derivation fails.
        """
        start = time.perf_counter()
        try:
            hkdf = HKDF(algorithm=hashes.SHA384(), length=32, salt=self.handshake_secret, info=b"tls13 master secret")
            master_secret = hkdf.derive(self.handshake_transcript)
            hkdf = HKDF(algorithm=hashes.SHA384(), length=32, salt=master_secret, info=b"tls13 application key")
            self.application_key = hkdf.derive(b"")
        except Exception as e:
            raise TLSError(f"Application key derivation failed: {e}", ALERT_INTERNAL_ERROR, self.logger, self.network)

        self.send_seq = self.recv_seq = 0
        self.compute_time += time.perf_counter() - start

    def compute_finished_message(self) -> bytes:
        """
        Compute the Finished message hash for handshake verification.

        Returns:
            bytes: SHA-384 hash of the handshake transcript.

        Raises:
            TLSError: If hash computation fails.
        """
        start = time.perf_counter()
        try:
            digest = hashes.Hash(hashes.SHA384())
            digest.update(self.handshake_transcript)
            finished = digest.finalize()
        except Exception as e:
            raise TLSError(f"Failed to compute Finished message: {e}", ALERT_HANDSHAKE_FAILURE, self.logger, self.network)

        self.compute_time += time.perf_counter() - start
        self.logger.debug(f"Computed Finished message in {time.perf_counter() - start:.6f} seconds")
        return finished

    def verify_finished_message(self, received: bytes) -> bool:
        """
        Verify the client's Finished message against the local transcript hash.

        Args:
            received (bytes): Finished message from the client.

        Returns:
            bool: True if the message matches the computed hash.

        Raises:
            TLSError: Propagated from compute_finished_message if computation fails.
        """
        expected = self.compute_finished_message()
        return received == expected

    def encrypt_message(self, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt a message using AES-GCM with the appropriate key.

        Args:
            plaintext (bytes): Data to encrypt.

        Returns:
            Tuple[bytes, bytes, bytes]: Sequence bytes, IV, and ciphertext.

        Raises:
            TLSError: If encryption fails or no key is available.
        """
        key = self.handshake_secret if self.is_handshake_phase else self.application_key
        if not key:
            raise TLSError("No encryption key available", ALERT_INTERNAL_ERROR, self.logger, self.network)

        start = time.perf_counter()
        try:
            iv = os.urandom(12)
            aesgcm = AESGCM(key)
            if not self.is_handshake_phase:
                self.send_seq += 1
                seq_bytes = self.send_seq.to_bytes(self.SEQ_BYTES_LENGTH, 'big')
                ct = aesgcm.encrypt(iv, plaintext, seq_bytes)
                self.logger.debug(f"Encrypted application data with sequence number {self.send_seq}")
            else:
                seq_bytes = b''
                ct = aesgcm.encrypt(iv, plaintext, None)
                self.logger.debug("Encrypted handshake data")
        except Exception as e:
            raise TLSError(f"Encryption failed: {e}", ALERT_INTERNAL_ERROR, self.logger, self.network)

        self.compute_time += time.perf_counter() - start
        return seq_bytes, iv, ct

    def decrypt_message(self, seq_bytes: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        """
        Decrypt a message using AES-GCM with the appropriate key.

        Args:
            seq_bytes (bytes): Sequence number bytes (empty for handshake).
            iv (bytes): Initialization vector.
            ciphertext (bytes): Encrypted data.

        Returns:
            bytes: Decrypted plaintext.

        Raises:
            TLSError: If decryption fails or sequence number is invalid.
        """
        key = self.handshake_secret if self.is_handshake_phase else self.application_key
        if not key:
            raise TLSError("No decryption key available", ALERT_INTERNAL_ERROR, self.logger, self.network)

        start = time.perf_counter()
        try:
            aesgcm = AESGCM(key)
            if not self.is_handshake_phase:
                if len(seq_bytes) != self.SEQ_BYTES_LENGTH:
                    raise TLSError(f"Invalid sequence number length: expected {self.SEQ_BYTES_LENGTH}, got {len(seq_bytes)}",
                                   ALERT_BAD_RECORD_MAC, self.logger, self.network)
                received_seq = int.from_bytes(seq_bytes, 'big')
                expected_seq = self.recv_seq + 1
                if received_seq != expected_seq:
                    raise TLSError(f"Replay detected: expected seq {expected_seq}, got {received_seq}",
                                   ALERT_BAD_RECORD_MAC, self.logger, self.network)
                plaintext = aesgcm.decrypt(iv, ciphertext, seq_bytes)
                self.recv_seq = received_seq
                self.logger.debug(f"Decrypted application data with sequence number {received_seq}")
            else:
                if seq_bytes:
                    raise TLSError("Unexpected sequence number in handshake phase",
                                   ALERT_HANDSHAKE_FAILURE, self.logger, self.network)
                plaintext = aesgcm.decrypt(iv, ciphertext, None)
                self.logger.debug("Decrypted handshake data")
        except cryptography.exceptions.InvalidTag:
            alert_type = ALERT_HANDSHAKE_FAILURE if self.is_handshake_phase else ALERT_BAD_RECORD_MAC
            raise TLSError("Decryption failed: invalid tag", alert_type, self.logger, self.network)
        except TLSError as e:
            raise  # Propagate specific TLSError
        except Exception as e:
            alert_type = ALERT_HANDSHAKE_FAILURE if self.is_handshake_phase else ALERT_BAD_RECORD_MAC
            raise TLSError(f"Decryption failed: {e}", alert_type, self.logger, self.network)

        self.compute_time += time.perf_counter() - start
        return plaintext

    def clear_sensitive_data(self) -> None:
        """Erase sensitive cryptographic data to prevent leakage."""
        for attr in ['kyber_ss', 'initial_secret', 'handshake_secret', 'application_key']:
            if getattr(self, attr):
                setattr(self, attr, None)
        self.ecc_private_key = None
        self.is_handshake_phase = False
        self.logger.debug("Cleared sensitive cryptographic data")