import logging
import time
from typing import Dict, Tuple

from cryptography.hazmat.primitives.asymmetric import ec

from src.utils.crypto import TLSCrypto, generate_kyber_keys, get_hash
from src.utils.errors import TLSError
from src.utils.utils import (
    ALERT_HANDSHAKE_FAILURE, ALERT_ILLEGAL_PARAMETER, ALERT_INTERNAL_ERROR, 
    TLS13_SERVER_CERT_VERIFY_CONTEXT, TLS13_CLIENT_CERT_VERIFY_CONTEXT
)

class ServerCrypto(TLSCrypto):
    """
    Server-specific cryptographic operations for TLS 1.3 (RFC 8446, Section 7).
    """

    def __init__(self, logger: logging.Logger, network=None):
        """
        Initialize the ServerCrypto instance.

        Args:
            logger (logging.Logger): Logger for cryptographic events.
            network (optional): Network object for sending alerts.
        """
        super().__init__(logger, network)
        self.certificate_verify_context = TLS13_SERVER_CERT_VERIFY_CONTEXT
        self.peer_certificate_verify_context = TLS13_CLIENT_CERT_VERIFY_CONTEXT
        self.client_public_key = None  # Client's ECC public key
        self.kyber_kem = None  # Kyber private key

    def generate_keys(self, use_hybrid: bool, kyber_variant: int | None) -> None:
        """
        Generate ECC and optionally Kyber keys for the server.

        Args:
            use_hybrid (bool): Whether to use hybrid key exchange with Kyber.
            kyber_variant (int | None): Kyber variant (1=Kyber512, 2=Kyber768, 3=Kyber1024).

        Raises:
            TLSError: If key generation fails.
        """
        try:
            self.generate_ecc_keys()
            if use_hybrid and kyber_variant:
                self.kyber_kem, _ = generate_kyber_keys(kyber_variant, self.logger)
        except TLSError as e:
            raise
        except Exception as e:
            raise TLSError(f"Key generation failed: {e}", ALERT_INTERNAL_ERROR, self.logger, self.network)

    def encapsulate_kyber(self, client_kyber_pk: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate the client's Kyber public key to generate ciphertext and shared secret.

        Args:
            client_kyber_pk (bytes): Client's Kyber public key.

        Returns:
            Tuple[bytes, bytes]: Kyber ciphertext and shared secret.

        Raises:
            TLSError: If encapsulation fails or Kyber KEM is not initialized.
        """
        start = time.perf_counter()
        if not self.kyber_kem:
            raise TLSError("Kyber KEM not initialized", ALERT_INTERNAL_ERROR, self.logger, self.network)
        if len(client_kyber_pk) != self.get_expected_kyber_pk_size(self.cipher_suite):
            raise TLSError(f"Invalid client Kyber public key length: Expected {self.get_expected_kyber_pk_size(self.cipher_suite)} got {len(client_kyber_pk)}", 
                           ALERT_ILLEGAL_PARAMETER, self.logger, self.network)
        try:
            ct, ss = self.kyber_kem.encap_secret(client_kyber_pk)
            duration = time.perf_counter() - start
            self.logger.debug(f"Encapsulated Kyber shared secret in {duration:.6f} seconds")
            return ct, ss
        except Exception as e:
            raise TLSError(f"Kyber encapsulation failed: {e}", ALERT_INTERNAL_ERROR, self.logger, self.network)

    def derive_handshake_keys(self, client_hello: Dict[str, bytes], use_hybrid: bool, kyber_ss: bytes | None) -> None:
        """
        Derive handshake keys from the client's hello message.

        Args:
            client_hello (Dict[str, bytes]): Client's ECC public key.
            use_hybrid (bool): Whether to use hybrid key exchange with Kyber.
            kyber_ss (bytes | None): Kyber shared secret if hybrid.

        Raises:
            TLSError: If key derivation fails or Kyber SS is missing when required.
        """
        try:
            self.client_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), client_hello["ecc_pk"])
            ecc_shared = self.ecc_private_key.exchange(ec.ECDH(), self.client_public_key)
            if use_hybrid:
                if kyber_ss is None:
                    raise TLSError("Missing Kyber shared secret for hybrid exchange", ALERT_HANDSHAKE_FAILURE, self.logger, self.network)
                combined_secret = ecc_shared + kyber_ss
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
        self.client_public_key = None
        self.logger.debug(f"Cleared server-specific sensitive data")