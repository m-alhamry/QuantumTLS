import logging
import time
from typing import Dict

from cryptography.hazmat.primitives.asymmetric import ec

from src.utils.crypto import TLSCrypto, generate_kyber_keys, get_hash
from src.utils.errors import TLSError
from src.utils.utils import (
    ALERT_ILLEGAL_PARAMETER, ALERT_INTERNAL_ERROR, KYBER_VARIANTS, 
    TLS13_CLIENT_CERT_VERIFY_CONTEXT, TLS13_SERVER_CERT_VERIFY_CONTEXT
)

class ClientCrypto(TLSCrypto):
    """
    Client-specific cryptographic operations for TLS 1.3 (RFC 8446, Section 7).
    """

    def __init__(self, logger: logging.Logger, network=None):
        """
        Initialize the ClientCrypto instance.

        Args:
            logger (logging.Logger): Logger for cryptographic events.
            network (optional): Network object for sending alerts.
        """
        super().__init__(logger, network)
        self.certificate_verify_context = TLS13_CLIENT_CERT_VERIFY_CONTEXT
        self.peer_certificate_verify_context = TLS13_SERVER_CERT_VERIFY_CONTEXT
        self.kyber_kems = {}  # Kyber private keys
        self.kyber_pks = {}  # Kyber public keys
        self.server_public_key = None  # Server's ECC public key

    def generate_keys(self) -> None:
        """
        Generate ECC and Kyber keys for the client.

        Raises:
            TLSError: If key generation fails.
        """
        try:
            self.generate_ecc_keys()
            for variant in [1, 2, 3]:  # Kyber512, Kyber768, Kyber1024
                kem, pk = generate_kyber_keys(variant, self.logger)
                self.kyber_kems[variant] = kem
                self.kyber_pks[variant] = pk
        except TLSError as e:
            raise
        except Exception as e:
            raise TLSError(f"Key generation failed: {e}", ALERT_INTERNAL_ERROR, self.logger, self.network)

    def decapsulate_kyber(self, kyber_ct: bytes) -> bytes:
        """
        Decapsulate the Kyber ciphertext to obtain the shared secret.

        Args:
            kyber_ct (bytes): Kyber ciphertext from the server.

        Returns:
            bytes: Shared secret.

        Raises:
            TLSError: If cipher suite or Kyber key is missing, or decapsulation fails.
        """
        start = time.perf_counter()
        if not self.cipher_suite:
            raise TLSError("Cipher suite not set", ALERT_INTERNAL_ERROR, self.logger, self.network)
        variant = KYBER_VARIANTS.get(self.cipher_suite)
        if variant not in self.kyber_kems:
            raise TLSError(f"No Kyber private key for variant {variant}", ALERT_INTERNAL_ERROR, self.logger, self.network)
        if len(kyber_ct) != self.get_expected_kyber_ct_size(self.cipher_suite):
            raise TLSError(f"Invalid Kyber cipherText length: Expected {self.get_expected_kyber_ct_size(self.cipher_suite)} got {len(kyber_ct)}", 
                           ALERT_ILLEGAL_PARAMETER, self.logger, self.network)
        try:
            kyber_ss = self.kyber_kems[variant].decap_secret(kyber_ct)
            duration = time.perf_counter() - start
            self.logger.debug(f"Decapsulated Kyber shared secret in {duration:.6f} seconds")
            return kyber_ss
        except Exception as e:
            raise TLSError(f"Kyber decapsulation failed: {e}", ALERT_INTERNAL_ERROR, self.logger, self.network)

    def derive_handshake_keys(self, server_hello: Dict[str, bytes], use_hybrid: bool) -> None:
        """
        Derive handshake keys from the server's hello message.

        Args:
            server_hello (Dict[str, bytes]): Server's ECC public key and Kyber ciphertext.
            use_hybrid (bool): Whether to use hybrid key exchange with Kyber.

        Raises:
            TLSError: If key derivation fails.
        """
        try:
            # Parse server's ECC public key
            self.server_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), server_hello["ecc_pk"])
            # Compute ECC shared secret
            ecc_shared = self.ecc_private_key.exchange(ec.ECDH(), self.server_public_key)
            if use_hybrid:
                # Decapsulate Kyber ciphertext and combine with ECC shared secret
                self.kyber_ss = self.decapsulate_kyber(server_hello["kyber_ct"])
                combined_secret = ecc_shared + self.kyber_ss
                pre_master_secret = get_hash(combined_secret)
            else:
                pre_master_secret = ecc_shared
            super().derive_handshake_keys(pre_master_secret)
        except TLSError as e:
            raise
        except Exception as e:
            raise TLSError(f"Handshake key derivation failed: {e}", ALERT_INTERNAL_ERROR, self.logger, self.network)

    def clear_sensitive_data(self) -> None:
        """
        Clear all sensitive cryptographic data from memory.
        """
        super().clear_sensitive_data()
        self.kyber_ss = None
        self.server_public_key = None