import logging
import time
from typing import Dict

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate

from crypto import TLSCrypto, TLSError, generate_kyber_keys, get_hash
from utils import (
    ALERT_BAD_CERTIFICATE, ALERT_INTERNAL_ERROR, CERT_VERIFY_CONTEXT_PADDING, 
    DEFAULT_CLIENT_CERT, DEFAULT_CLIENT_KEY, TLS13_CLIENT_CERT_VERIFY_CONTEXT,
    TLS13_SERVER_CERT_VERIFY_CONTEXT, HKDF_INFO_INITIAL_KEY,
    HKDF_INFO_EARLY_SECRET, HKDF_INFO_HANDSHAKE_KEY, KEY_LENGTH
)

class ClientCrypto(TLSCrypto):
    """Client-specific cryptographic operations for TLS 1.3."""

    def __init__(self, logger: logging.Logger, ca_cert, network=None):
        """
        Initialize the ClientCrypto instance.

        Args:
            logger: Logger instance for logging cryptographic events.
            ca_cert: CA certificate for verifying server certificates.
            network: Optional network object for sending alerts.
        """
        super().__init__(logger, network)
        self.ca_cert = ca_cert
        self.kyber_kems = {}
        self.kyber_pks = {}
        self.kyber_ss = None
        self.server_public_key = None
        self.cipher_suite = None
        self.cert = None
        self.cert_private_key = None

    def load_certificate(self) -> None:
        """
        Load and verify the client's certificate and private key.

        Raises:
            TLSError: If certificate loading or verification fails.
        """
        try:
            with open(DEFAULT_CLIENT_CERT, "rb") as f:
                self.cert = load_pem_x509_certificate(f.read())
            with open(DEFAULT_CLIENT_KEY, "rb") as f:
                self.cert_private_key = load_pem_private_key(f.read(), password=None)
            self.logger.info("Loaded client certificate and private key")
            ca_public_key = self.ca_cert.public_key()
            ca_public_key.verify(self.cert.signature, self.cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA384()))
            # Verify key-certificate match
            public_key_from_private = self.cert_private_key.public_key()
            cert_public_key = self.cert.public_key()
            if public_key_from_private.public_numbers() != cert_public_key.public_numbers():
                raise TLSError("Client private key does not match certificate", ALERT_INTERNAL_ERROR, self.logger, self.network)
            self.logger.info("Client certificate and private key match verified")
            self.logger.info("Client certificate verified against CA")
        except Exception as e:
            raise TLSError(f"Failed to load or verify client certificate: {e}", ALERT_INTERNAL_ERROR, self.logger, self.network)

    def compute_certificate_verify(self) -> bytes:
        """
        Compute the CertificateVerify signature for the client.

        Returns:
            bytes: Signature over the handshake transcript.
        """
        start = time.perf_counter()
        transcript_hash = self.get_transcript_hash()
        context = CERT_VERIFY_CONTEXT_PADDING + TLS13_CLIENT_CERT_VERIFY_CONTEXT + b"\x00"
        signature_input = context + transcript_hash
        signature = self.cert_private_key.sign(signature_input, ec.ECDSA(hashes.SHA384()))
        duration = time.perf_counter() - start
        self.compute_time += duration
        self.logger.debug(f"Computed CertificateVerify in {duration:.6f}s")
        return signature

    def verify_certificate_verify(self, signature: bytes, server_cert: bytes, transcript: bytes = None) -> bool:
        """
        Verify the server's CertificateVerify signature.

        Args:
            signature: Signature to verify.
            server_cert: Server's certificate bytes.
            transcript: Optional transcript snapshot (defaults to current transcript).

        Returns:
            bool: True if verification succeeds, False otherwise.

        Raises:
            TLSError: If verification fails.
        """
        start = time.perf_counter()
        server_cert_obj = load_der_x509_certificate(server_cert)
        server_public_key = server_cert_obj.public_key()
        transcript_to_use = transcript if transcript is not None else self.handshake_transcript
        context = CERT_VERIFY_CONTEXT_PADDING + TLS13_SERVER_CERT_VERIFY_CONTEXT + b"\x00"
        signature_input = context + get_hash(transcript_to_use)
        try:
            server_public_key.verify(signature, signature_input, ec.ECDSA(hashes.SHA384()))
        except Exception:
            raise TLSError("Server CertificateVerify verification failed", ALERT_BAD_CERTIFICATE, self.logger, self.network)
        duration = time.perf_counter() - start
        self.compute_time += duration
        self.logger.debug(f"Verified CertificateVerify in {duration:.6f}s")
        return True

    def generate_keys(self) -> None:
        """
        Generate ECC and Kyber keys for the client.
        """
        self.logger.debug("Generating client cryptographic keys")
        self.generate_ecc_keys()
        self.kyber_kems = {}
        self.kyber_pks = {}
        for variant in [1, 2, 3]:
            kem, pk = generate_kyber_keys(variant, self.logger)
            self.kyber_kems[variant] = kem
            self.kyber_pks[variant] = pk

    def decapsulate_kyber(self, kyber_ct: bytes) -> bytes:
        """
        Decapsulate the Kyber ciphertext to obtain the shared secret.

        Args:
            kyber_ct: Kyber ciphertext.

        Returns:
            bytes: Shared secret.

        Raises:
            TLSError: If cipher suite is not set or Kyber private key is missing.
        """
        if not self.cipher_suite:
            raise TLSError("Cipher suite not set", ALERT_INTERNAL_ERROR, self.logger, self.network)
        variant = {"TLS_AES_256_GCM_SHA384_Kyber512": 1, "TLS_AES_256_GCM_SHA384_Kyber768": 2, "TLS_AES_256_GCM_SHA384_Kyber1024": 3}.get(self.cipher_suite)
        if variant not in self.kyber_kems:
            raise TLSError(f"No Kyber private key for variant {variant}", ALERT_INTERNAL_ERROR, self.logger, self.network)
        start = time.perf_counter()
        kyber_ss = self.kyber_kems[variant].decap_secret(kyber_ct)
        duration = time.perf_counter() - start
        self.compute_time += duration
        self.logger.debug(f"Decapsulated Kyber shared secret in {duration:.6f}s")
        return kyber_ss

    def derive_handshake_keys(self, server_hello: Dict[str, bytes], use_hybrid: bool) -> None:
        """
        Derive handshake keys from the server's hello message.

        Args:
            server_hello: Dictionary containing server's public keys and ciphertext.
            use_hybrid: Whether to use hybrid key exchange with Kyber.
            nmmmm
        """
        start = time.perf_counter()
        self.server_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), server_hello["ecc_pk"])
        ecc_shared = self.ecc_private_key.exchange(ec.ECDH(), self.server_public_key)
        if use_hybrid:
            self.kyber_ss = self.decapsulate_kyber(server_hello["kyber_ct"])
            combined_secret = ecc_shared + self.kyber_ss
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
        self.logger.debug("Cleared client-specific sensitive data")