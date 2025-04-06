import unittest
from client_crypto import ClientCrypto
from errors import TLSError
from server_crypto import ServerCrypto
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import Encoding
import logging
from utils import ALERT_HANDSHAKE_FAILURE, ALERT_BAD_CERTIFICATE

class TestHandshake(unittest.TestCase):
    def setUp(self):
        """Initialize the test environment with logger and crypto objects."""
        self.logger = logging.getLogger('test')
        with open("ca.crt", "rb") as f:
            self.ca_cert = load_pem_x509_certificate(f.read())
        self.client_crypto = ClientCrypto(self.logger, self.ca_cert)
        self.server_crypto = ServerCrypto(self.logger)

    def test_kyber_shared_secret_requirement(self):
        """Test that handshake fails if Kyber shared secret is missing in hybrid mode."""
        use_hybrid = True
        kyber_variant = 2  # Kyber768
        self.client_crypto.generate_keys(use_hybrid, kyber_variant)
        self.server_crypto.generate_keys(use_hybrid, kyber_variant)
        client_hello = {
            "ecc_pk": self.client_crypto.ecc_public_key_bytes,
            "kyber_pk": self.client_crypto.kyber_pk,
            "cert": self.client_crypto.cert.public_bytes(Encoding.PEM),
            "transcript": b"client_hello"
        }
        with self.assertRaises(TLSError) as cm:
            self.server_crypto.derive_handshake_keys(client_hello, use_hybrid, None)
        self.assertEqual(str(cm.exception), "Missing Kyber shared secret for hybrid mode")
        self.assertEqual(cm.exception.alert_type, ALERT_HANDSHAKE_FAILURE)

    def test_certificate_validation(self):
        """Test that handshake fails with an invalid certificate."""
        use_hybrid = True
        kyber_variant = 2  # Kyber768
        self.client_crypto.generate_keys(use_hybrid, kyber_variant)
        self.server_crypto.generate_keys(use_hybrid, kyber_variant)
        client_hello = {
            "ecc_pk": self.client_crypto.ecc_public_key_bytes,
            "kyber_pk": self.client_crypto.kyber_pk,
            "cert": b"invalid_cert",  # Invalid certificate
            "transcript": b"client_hello"
        }
        # Generate and provide a valid Kyber shared secret
        kyber_ct, kyber_ss = self.server_crypto.encapsulate_kyber(client_hello["kyber_pk"])
        self.server_crypto.derive_handshake_keys(client_hello, use_hybrid, kyber_ss)
        self.server_crypto.handshake_transcript = bytearray(b"client_hello")
        signature = b"dummy_signature"  # Signature is not the focus
        with self.assertRaises(TLSError) as cm:
            self.server_crypto.verify_certificate_verify(signature, client_hello["cert"])
        self.assertIn("Failed to parse client certificate", str(cm.exception))
        self.assertEqual(cm.exception.alert_type, ALERT_BAD_CERTIFICATE)

    def test_key_derivation_all_kyber_variants(self):
        """Test key derivation across all Kyber variants (existing test)."""
        for kyber_variant, suite in [(1, "Kyber512"), (2, "Kyber768"), (3, "Kyber1024")]:
            use_hybrid = True
            self.client_crypto.generate_keys(use_hybrid, kyber_variant)
            self.server_crypto.generate_keys(use_hybrid, kyber_variant)
            client_hello = {
                "ecc_pk": self.client_crypto.ecc_public_key_bytes,
                "kyber_pk": self.client_crypto.kyber_pk,
                "cert": self.client_crypto.cert.public_bytes(Encoding.PEM),
                "transcript": b"client_hello"
            }
            kyber_ct, kyber_ss = self.server_crypto.encapsulate_kyber(client_hello["kyber_pk"])
            server_hello = {
                "ecc_pk": self.server_crypto.ecc_public_key_bytes,
                "kyber_ct": kyber_ct,
                "cert": self.server_crypto.cert.public_bytes(Encoding.PEM)
            }
            self.client_crypto.handshake_transcript = bytearray(b"client_hello")
            self.server_crypto.handshake_transcript = bytearray(b"client_hello")
            self.client_crypto.derive_handshake_keys(server_hello, use_hybrid)
            self.server_crypto.derive_handshake_keys(client_hello, use_hybrid, kyber_ss)
            self.assertIsNotNone(self.client_crypto.handshake_secret, f"Failed for {suite}")
            self.assertIsNotNone(self.server_crypto.handshake_secret, f"Failed for {suite}")

if __name__ == '__main__':
    unittest.main()