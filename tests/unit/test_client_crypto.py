import os
from unittest.mock import Mock, patch
import unittest
from client_crypto import ClientCrypto
from cryptography.x509 import load_pem_x509_certificate
from cryptography import exceptions
import logging

from errors import TLSError

class TestClientCrypto(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger('test')
        with open("ca.crt", "rb") as f:
            self.ca_cert = load_pem_x509_certificate(f.read())
        self.crypto = ClientCrypto(self.logger, self.ca_cert)
        self.crypto.handshake_transcript = b"test data"

    def test_load_certificate(self):
        self.assertIsNotNone(self.crypto.cert)
        self.assertIsNotNone(self.crypto.cert_private_key)

    def test_compute_certificate_verify(self):
        self.crypto.handshake_transcript = b"test data"
        signature = self.crypto.compute_certificate_verify()
        self.assertTrue(len(signature) > 0)

    def test_verify_certificate_verify(self):
        with patch('client_crypto.load_pem_x509_certificate') as mock_load:
            # Create mock objects
            mock_cert = Mock()
            mock_public_key = Mock()
            mock_cert.public_key.return_value = mock_public_key
            mock_load.return_value = mock_cert

            # Use dummy certificate bytes
            server_cert = b'server_cert_bytes'
            signature = b'dummy_signature'

            # Call the method
            result = self.crypto.verify_certificate_verify(signature, server_cert)

            # Assertions
            self.assertTrue(result)
            mock_public_key.verify.assert_called_once()
            mock_load.assert_called_once_with(server_cert)

    def test_server_cert_key_type(self):
        with open("server.crt", "rb") as f:
            server_cert = load_pem_x509_certificate(f.read())
        public_key = server_cert.public_key()
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        self.assertIsInstance(public_key, ec.EllipticCurvePublicKey, f"Expected ECC key, got {type(public_key)}")

    def test_verify_certificate_verify_failure(self):
        with patch('client_crypto.load_pem_x509_certificate') as mock_load:
            # Create mock objects
            mock_cert = Mock()
            mock_public_key = Mock()
            mock_public_key.verify.side_effect = exceptions.InvalidSignature
            mock_cert.public_key.return_value = mock_public_key
            mock_load.return_value = mock_cert

            # Use dummy certificate bytes
            server_cert = b'server_cert_bytes'
            signature = b'dummy_signature'

            # Call the method and check for expected exception
            with self.assertRaises(TLSError) as cm:
                self.crypto.verify_certificate_verify(signature, server_cert)
            self.assertIn("Server CertificateVerify verification failed", str(cm.exception))
            mock_public_key.verify.assert_called_once()

    def test_replay_attack_prevention(self):
        self.crypto.application_key = os.urandom(32)  # Simulate post-handshake
        self.crypto.is_handshake_phase = False
        plaintext = b"Test message"
        seq_bytes, iv, ct = self.crypto.encrypt_message(plaintext)
        # First decryption (should succeed and increment sequence)
        self.crypto.decrypt_message(seq_bytes, iv, ct)
        # Second decryption (replay attempt, should raise TLSError)
        with self.assertRaises(TLSError) as cm:
            self.crypto.decrypt_message(seq_bytes, iv, ct)
        self.assertIn("Replay detected", str(cm.exception))

if __name__ == '__main__':
    unittest.main()