import logging
import time
from typing import Dict, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate

from crypto import TLSCrypto, TLSError, generate_kyber_keys, get_hash
from utils import (
    ALERT_BAD_CERTIFICATE, ALERT_HANDSHAKE_FAILURE, ALERT_INTERNAL_ERROR, CERT_VERIFY_CONTEXT_PADDING, 
    DEFAULT_SERVER_CERT, DEFAULT_SERVER_KEY, TLS13_CLIENT_CERT_VERIFY_CONTEXT, TLS13_SERVER_CERT_VERIFY_CONTEXT,
    HKDF_INFO_INITIAL_KEY, HKDF_INFO_EARLY_SECRET, HKDF_INFO_HANDSHAKE_KEY, KEY_LENGTH
)

class ServerCrypto(TLSCrypto):
    """Server-specific cryptographic operations for TLS 1.3."""

    def __init__(self, logger: logging.Logger, network=None):
        """
        Initialize the ServerCrypto instance.

        Args:
            logger: Logger instance for logging cryptographic events.
            network: Optional network object for sending alerts.
        """
        super().__init__(logger, network)
        self.client_public_key = None
        self.cipher_suite = None
        self.kyber_kem = None
        self.kyber_ss = None
        self.cert = None
        self.cert_private_key = None
        self.load_certificate()

    def load_certificate(self) -> None:
        """
        Load the server's certificate and private key.

        Raises:
            TLSError: If certificate or key loading fails.
        """
        try:
            with open(DEFAULT_SERVER_CERT, "rb") as f:
                self.cert = load_pem_x509_certificate(f.read())
            with open(DEFAULT_SERVER_KEY, "rb") as f:
                self.cert_private_key = load_pem_private_key(f.read(), password=None)
            self.logger.info("Loaded server certificate and private key")
            # Verify key-certificate match
            public_key_from_private = self.cert_private_key.public_key()
            cert_public_key = self.cert.public_key()
            if public_key_from_private.public_numbers() != cert_public_key.public_numbers():
                raise TLSError("Server private key and certificate mismatch", ALERT_INTERNAL_ERROR, self.logger, self.network)
            self.logger.info("Server certificate and private key match verified")
            self.logger.info("Server certificate verified against CA")
        
        except Exception as e:
            raise TLSError(f"Failed to load server certificate or key: {e}", ALERT_INTERNAL_ERROR, self.logger, self.network)

    def compute_certificate_verify(self) -> bytes:
        """
        Compute the CertificateVerify signature for the server.

        Returns:
            bytes: Signature over the handshake transcript.
        """
        start = time.perf_counter()
        transcript_hash = self.get_transcript_hash()
        context = CERT_VERIFY_CONTEXT_PADDING + TLS13_SERVER_CERT_VERIFY_CONTEXT + b"\x00"
        signature_input = context + transcript_hash
        signature = self.cert_private_key.sign(signature_input, ec.ECDSA(hashes.SHA384()))
        duration = time.perf_counter() - start
        self.compute_time += duration
        self.logger.debug(f"Computed CertificateVerify in {duration:.6f}s")
        return signature

    def verify_certificate_verify(self, signature: bytes, client_cert: bytes, transcript: bytes = None) -> bool:
        """
        Verify the client's CertificateVerify signature.

        Args:
            signature: Signature to verify.
            client_cert: Client's certificate bytes.
            transcript: Optional transcript snapshot (defaults to current transcript).

        Returns:
            bool: True if verification succeeds, False otherwise.

        Raises:
            TLSError: If verification fails.
        """
        start = time.perf_counter()
        try:
            client_cert_obj = load_der_x509_certificate(client_cert)
        except ValueError as e:
            raise TLSError(f"Failed to parse client certificate: {e}", ALERT_BAD_CERTIFICATE, self.logger, self.network)
        client_public_key = client_cert_obj.public_key()
        transcript_to_use = transcript if transcript is not None else self.handshake_transcript
        context = CERT_VERIFY_CONTEXT_PADDING + TLS13_CLIENT_CERT_VERIFY_CONTEXT + b"\x00"
        signature_input = context + get_hash(transcript_to_use)
        try:
            client_public_key.verify(signature, signature_input, ec.ECDSA(hashes.SHA384()))
        except Exception:
            raise TLSError("Client CertificateVerify verification failed", ALERT_BAD_CERTIFICATE, self.logger, self.network)
        duration = time.perf_counter() - start
        self.compute_time += duration
        self.logger.debug(f"Verified CertificateVerify in {duration:.6f}s")
        return True

    def generate_keys(self, use_hybrid: bool, kyber_variant: int | None) -> None:
        """
        Generate ECC and Kyber keys for the server.

        Args:
            use_hybrid: Whether to use hybrid key exchange with Kyber.
            kyber_variant: Kyber variant to use (1 for Kyber512, 2 for Kyber768, 3 for Kyber1024).
        """
        self.generate_ecc_keys()
        if use_hybrid and kyber_variant:
            self.kyber_kem, _ = generate_kyber_keys(kyber_variant, self.logger)

    def encapsulate_kyber(self, client_kyber_pk: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate the client's Kyber public key to generate ciphertext and shared secret.

        Args:
            client_kyber_pk: Client's Kyber public key.

        Returns:
            Tuple[bytes, bytes]: Kyber ciphertext and shared secret.
        """
        start = time.perf_counter()
        ct, ss = self.kyber_kem.encap_secret(client_kyber_pk)
        duration = time.perf_counter() - start
        self.compute_time += duration
        self.logger.debug(f"Encapsulated Kyber shared secret in {duration:.6f}s")
        return ct, ss

    def derive_handshake_keys(self, client_hello: Dict[str, bytes], use_hybrid: bool, kyber_ss: bytes | None) -> None:
        """
        Derive handshake keys from the client's hello message.

        Args:
            client_hello: Dictionary containing client's public keys.
            use_hybrid: Whether to use hybrid key exchange with Kyber.
            kyber_ss: Kyber shared secret (if hybrid is used).
        """
        start = time.perf_counter()
        self.client_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), client_hello["ecc_pk"])
        ecc_shared = self.ecc_private_key.exchange(ec.ECDH(), self.client_public_key)
        if use_hybrid:
            if kyber_ss is None:
                raise TLSError("Missing Kyber shared secret", ALERT_HANDSHAKE_FAILURE, self.logger, self.network)
            combined_secret = ecc_shared + kyber_ss
            pre_master_secret = get_hash(combined_secret)
        else:
            pre_master_secret = ecc_shared

        hkdf = HKDF(algorithm=hashes.SHA384(), length=KEY_LENGTH, salt=b"", info=HKDF_INFO_INITIAL_KEY)
        self.initial_secret = hkdf.derive(pre_master_secret)
        hkdf = HKDF(algorithm=hashes.SHA384(), length=KEY_LENGTH, salt=b"", info=HKDF_INFO_EARLY_SECRET)
        early_secret = hkdf.derive(b"\x00" * KEY_LENGTH)
        hkdf = HKDF(algorithm=hashes.SHA384(), length=KEY_LENGTH, salt=early_secret, info=HKDF_INFO_HANDSHAKE_KEY)
        self.handshake_secret = hkdf.derive(pre_master_secret)
        
        duration = time.perf_counter() - start
        self.compute_time += duration
        self.logger.debug(f"Derived handshake keys in {duration:.6f}s")

    def clear_sensitive_data(self) -> None:
        """
        Clear all sensitive cryptographic data from memory.
        """
        super().clear_sensitive_data()
        self.kyber_ss = None
        self.logger.debug("Cleared server-specific sensitive data")