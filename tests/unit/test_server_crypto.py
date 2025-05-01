import unittest
from unittest.mock import patch
from errors import TLSError
from server_crypto import ServerCrypto
import logging
from crypto import generate_ecc_keys
from utils import ALERT_BAD_CERTIFICATE

class TestServerCrypto(unittest.TestCase):
    """
    Unit tests for the ServerCrypto class in the QuantumTLS prototype.
    Tests certificate loading, signature computation, Kyber encapsulation, and error handling.
    """

    def setUp(self):
        """
        Set up the test environment with a logger and ServerCrypto instance.
        """
        self.logger = logging.getLogger('test')
        self.crypto = ServerCrypto(self.logger)
        self.crypto.load_certificate("server.crt", "server.key")
        self.crypto.generate_keys(use_hybrid=True, kyber_variant=2)  # Kyber768
        self.crypto.cipher_suite = "TLS_AES_256_GCM_SHA384_Kyber768"
        _, _, self.valid_ecc_pk_bytes = generate_ecc_keys(self.logger)

    def test_load_certificate(self):
        """
        Test that the server certificate and private key are loaded correctly.
        """
        self.crypto.load_certificate("server.crt", "server.key")
        self.assertIsNotNone(self.crypto.cert, "Certificate should be loaded")
        self.assertIsNotNone(self.crypto.cert_private_key, "Private key should be loaded")

    def test_compute_certificate_verify(self):
        """
        Test computation of the CertificateVerify signature.
        Ensures a non-empty signature is produced.
        """
        self.crypto.handshake_transcript = b"test data"
        signature = self.crypto.compute_certificate_verify()
        self.assertTrue(len(signature) > 0, "Signature should not be empty")

    def test_encapsulate_kyber(self):
        """
        Test Kyber encapsulation with a dummy client public key.
        Verifies that ciphertext and shared secret are generated.
        """
        self.crypto.generate_keys(use_hybrid=True, kyber_variant=2)
        client_kyber_pk = b'\x00' * 1184  # Dummy Kyber768 public key
        ct, ss = self.crypto.encapsulate_kyber(client_kyber_pk)
        self.assertTrue(len(ct) > 0, "Ciphertext should not be empty")
        self.assertTrue(len(ss) > 0, "Shared secret should not be empty")

    def test_mitm_simulation(self):
        """
        Test handshake key derivation with a tampered certificate.
        Note: This test does not fully simulate MITM as derive_handshake_keys does not verify certs.
        """
        self.crypto.generate_keys(use_hybrid=True, kyber_variant=2)
        client_kyber_pk = b'\x00' * 1184
        client_hello = {
            "ecc_pk": self.valid_ecc_pk_bytes,
            "kyber_pk": client_kyber_pk,
            "transcript": b"client_hello"
        }
        ct, ss = self.crypto.encapsulate_kyber(client_kyber_pk)
        self.crypto.derive_handshake_keys(client_hello, True, ss)
        # Simulate certificate verification with tampered certificate
        tampered_cert = b"tampered_cert"
        signature = b"dummy_signature"  # Dummy signature
        with self.assertRaises(TLSError) as cm:
            self.crypto.verify_certificate_verify(signature, tampered_cert)
        self.assertEqual(cm.exception.alert_type, ALERT_BAD_CERTIFICATE,
                        "Should reject tampered certificate")

    def test_invalid_kyber_key_share(self):
        """
        Test that an invalid Kyber public key length raises an error.
        """
        self.crypto.generate_keys(use_hybrid=True, kyber_variant=2)
        invalid_kyber_pk = b'\xFF' * 1183  # One byte less than expected for Kyber768
        with self.assertRaises(TLSError) as cm:
            self.crypto.encapsulate_kyber(invalid_kyber_pk)
        self.assertIn("Invalid client Kyber public key length", str(cm.exception))

    @patch('oqs.KeyEncapsulation.encap_secret')
    def test_encapsulate_kyber_with_mock(self, mock_encap_secret):
        """
        Test Kyber encapsulation with a mocked encap_secret method.
        Verifies behavior with controlled outputs.
        """
        mock_encap_secret.return_value = (b'fake_ciphertext', b'fake_shared_secret')
        self.crypto.generate_keys(use_hybrid=True, kyber_variant=2)
        client_kyber_pk = b'\x00' * 1184
        ct, ss = self.crypto.encapsulate_kyber(client_kyber_pk)
        self.assertEqual(ct, b'fake_ciphertext', "Ciphertext should match mock")
        self.assertEqual(ss, b'fake_shared_secret', "Shared secret should match mock")

if __name__ == '__main__':
    unittest.main()