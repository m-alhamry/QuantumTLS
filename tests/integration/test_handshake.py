import unittest
from client_crypto import ClientCrypto
from errors import TLSError
from server_crypto import ServerCrypto
from cryptography.x509 import load_pem_x509_certificate
import logging
from utils import ALERT_HANDSHAKE_FAILURE, ALERT_BAD_CERTIFICATE

class TestHandshake(unittest.TestCase):
    """
    Integration tests for the TLS handshake process in the QuantumTLS prototype.
    Validates key exchange, certificate handling, and hybrid key exchange mechanisms.
    """

    def setUp(self):
        """
        Initialize the test environment with logger and crypto objects.
        """
        self.logger = logging.getLogger('test')
        with open("ca.crt", "rb") as f:
            self.ca_cert = load_pem_x509_certificate(f.read())
        self.client_crypto = ClientCrypto(self.logger)
        self.server_crypto = ServerCrypto(self.logger)

    def test_kyber_shared_secret_requirement(self):
        """
        Test that the handshake fails if the Kyber shared secret is missing in hybrid mode.
        """
        use_hybrid = True
        kyber_variant = 2  # Kyber768
        self.client_crypto.generate_keys()
        self.server_crypto.generate_keys(use_hybrid, kyber_variant)
        client_hello = {
            "ecc_pk": self.client_crypto.ecc_public_key_bytes,
            "kyber_pk": self.client_crypto.kyber_pks[kyber_variant],
            "transcript": b"client_hello"
        }
        # Attempt handshake without providing Kyber shared secret
        with self.assertRaises(TLSError) as cm:
            self.server_crypto.derive_handshake_keys(client_hello, use_hybrid, None)
        self.assertIn("Missing Kyber shared secret", str(cm.exception))
        self.assertEqual(cm.exception.alert_type, ALERT_HANDSHAKE_FAILURE)

    def test_certificate_validation(self):
        """
        Test that the handshake fails with an invalid certificate.
        """
        use_hybrid = True
        kyber_variant = 2  # Kyber768
        self.client_crypto.generate_keys()
        self.server_crypto.generate_keys(use_hybrid, kyber_variant)
        self.server_crypto.cipher_suite = "TLS_AES_256_GCM_SHA384_Kyber768"
        client_hello = {
            "ecc_pk": self.client_crypto.ecc_public_key_bytes,
            "kyber_pk": self.client_crypto.kyber_pks[kyber_variant],
            "cert": b"invalid_cert",  # Invalid certificate data
            "transcript": b"client_hello"
        }
        kyber_ct, kyber_ss = self.server_crypto.encapsulate_kyber(client_hello["kyber_pk"])
        self.server_crypto.derive_handshake_keys(client_hello, use_hybrid, kyber_ss)
        self.server_crypto.handshake_transcript = bytearray(b"client_hello")
        signature = b"dummy_signature"

        with self.assertRaises(TLSError) as cm:
            self.server_crypto.verify_certificate_verify(signature, client_hello["cert"])
        self.assertIn("CertificateVerify verification failed", str(cm.exception))
        self.assertEqual(cm.exception.alert_type, ALERT_BAD_CERTIFICATE)

    def test_key_derivation_all_kyber_variants(self):
        """
        Test key derivation across all Kyber variants (512, 768, 1024).
        Ensures compatibility and successful key generation.
        """
        for kyber_variant, suite in [
            (1, "TLS_AES_256_GCM_SHA384_Kyber512"),
            (2, "TLS_AES_256_GCM_SHA384_Kyber768"),
            (3, "TLS_AES_256_GCM_SHA384_Kyber1024")
        ]:
            use_hybrid = True
            self.client_crypto.generate_keys()
            self.client_crypto.cipher_suite = suite
            self.server_crypto.generate_keys(use_hybrid, kyber_variant)
            self.server_crypto.cipher_suite = suite
            client_hello = {
                "ecc_pk": self.client_crypto.ecc_public_key_bytes,
                "kyber_pk": self.client_crypto.kyber_pks[kyber_variant],
                "transcript": b"client_hello"
            }
            kyber_ct, kyber_ss = self.server_crypto.encapsulate_kyber(client_hello["kyber_pk"])
            server_hello = {
                "ecc_pk": self.server_crypto.ecc_public_key_bytes,
                "kyber_ct": kyber_ct,
            }
            self.client_crypto.handshake_transcript = bytearray(b"client_hello")
            self.server_crypto.handshake_transcript = bytearray(b"client_hello")
            self.client_crypto.derive_handshake_keys(server_hello, use_hybrid)
            self.server_crypto.derive_handshake_keys(client_hello, use_hybrid, kyber_ss)
            self.assertIsNotNone(self.client_crypto.handshake_secret, f"Client handshake secret failed for {suite}")
            self.assertIsNotNone(self.server_crypto.handshake_secret, f"Server handshake secret failed for {suite}")

    def test_hybrid_key_exchange(self):
        """
        Test hybrid key exchange using ECC and Kyber768.
        Verifies that client and server derive the same handshake secret.
        """
        use_hybrid = True
        kyber_variant = 2  # Kyber768
        self.client_crypto.generate_keys()
        self.server_crypto.generate_keys(use_hybrid, kyber_variant)
        self.server_crypto.cipher_suite = "TLS_AES_256_GCM_SHA384_Kyber768"
        self.client_crypto.cipher_suite = "TLS_AES_256_GCM_SHA384_Kyber768"
        client_hello = {
            "ecc_pk": self.client_crypto.ecc_public_key_bytes,
            "kyber_pk": self.client_crypto.kyber_pks[kyber_variant],
            "transcript": b"client_hello"
        }
        kyber_ct, kyber_ss = self.server_crypto.encapsulate_kyber(client_hello["kyber_pk"])
        server_hello = {
            "ecc_pk": self.server_crypto.ecc_public_key_bytes,
            "kyber_ct": kyber_ct,
        }
        self.client_crypto.handshake_transcript = bytearray(b"client_hello")
        self.server_crypto.handshake_transcript = bytearray(b"client_hello")
        self.client_crypto.derive_handshake_keys(server_hello, use_hybrid)
        self.server_crypto.derive_handshake_keys(client_hello, use_hybrid, kyber_ss)
        self.assertEqual(
            self.client_crypto.handshake_secret,
            self.server_crypto.handshake_secret,
            "Hybrid key exchange failed: client and server secrets differ"
        )

    def test_fallback_to_ecc_only(self):
        """
        Test fallback to ECC-only key exchange when hybrid mode is disabled.
        Ensures handshake succeeds without Kyber.
        """
        use_hybrid = False
        self.client_crypto.generate_keys()
        self.server_crypto.generate_keys(use_hybrid, None)
        client_hello = {
            "ecc_pk": self.client_crypto.ecc_public_key_bytes,
            "kyber_pk": None,  # No Kyber key share
            "transcript": b"client_hello"
        }
        self.server_crypto.cipher_suite = "TLS_AES_256_GCM_SHA384"
        self.server_crypto.derive_handshake_keys(client_hello, use_hybrid, None)
        self.assertIsNotNone(self.server_crypto.handshake_secret, "ECC-only key derivation failed")

if __name__ == '__main__':
    unittest.main()