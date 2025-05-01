import os
import unittest
from client_crypto import ClientCrypto
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, load_pem_private_key
import logging
from errors import TLSError
from utils import CERT_VERIFY_CONTEXT_PADDING, TLS13_SERVER_CERT_VERIFY_CONTEXT

class TestClientCrypto(unittest.TestCase):
    """
    Unit tests for the ClientCrypto class in the QuantumTLS prototype.
    Validates certificate loading, signature computation, verification, and replay protection.
    """

    def setUp(self):
        """
        Set up the test environment with logger and crypto instances.
        """
        self.logger = logging.getLogger('test')
        with open("ca.crt", "rb") as f:
            self.ca_cert = load_pem_x509_certificate(f.read())
        with open("server.crt", "rb") as f:
            self.server_cert = load_pem_x509_certificate(f.read())
        with open("server.key", "rb") as f:
            self.server_private_key = load_pem_private_key(f.read(), password=None)
        
        self.crypto = ClientCrypto(self.logger)
        self.crypto.load_certificate("client.crt", "client.key")
        self.crypto.handshake_transcript = b"test data"

    def test_load_certificate(self):
        """
        Test that the client certificate and private key are loaded correctly.
        """
        self.assertIsNotNone(self.crypto.cert, "Certificate should be loaded")
        self.assertIsNotNone(self.crypto.cert_private_key, "Private key should be loaded")

    def test_compute_certificate_verify(self):
        """
        Test computation of the CertificateVerify signature.
        Ensures a non-empty signature is produced.
        """
        signature = self.crypto.compute_certificate_verify()
        self.assertTrue(len(signature) > 0, "Signature should not be empty")

    def test_verify_certificate_verify(self):
        """
        Test verification of a valid server CertificateVerify signature.
        """
        transcript_hash = self.crypto.get_transcript_hash()
        context = CERT_VERIFY_CONTEXT_PADDING + TLS13_SERVER_CERT_VERIFY_CONTEXT + b"\x00"
        signature_input = context + transcript_hash
        signature = self.server_private_key.sign(signature_input, ec.ECDSA(hashes.SHA384()))
        server_cert_bytes = self.server_cert.public_bytes(Encoding.DER)
        result = self.crypto.verify_certificate_verify(signature, server_cert_bytes)
        self.assertTrue(result, "Valid signature should be verified successfully")

    def test_server_cert_key_type(self):
        """
        Test that the server certificate uses an ECC public key.
        """
        public_key = self.server_cert.public_key()
        self.assertIsInstance(public_key, ec.EllipticCurvePublicKey, "Server cert should use ECC key")

    def test_verify_certificate_verify_failure(self):
        """
        Test that an invalid signature fails verification.
        """
        server_cert_bytes = self.server_cert.public_bytes(Encoding.DER)
        invalid_signature = b'\x00' * 64  # Dummy invalid signature
        with self.assertRaises(TLSError) as cm:
            self.crypto.verify_certificate_verify(invalid_signature, server_cert_bytes)
        self.assertIn("CertificateVerify verification failed", str(cm.exception))

    def test_replay_attack_prevention(self):
        """
        Test that replayed messages are detected and rejected in the application phase.
        """
        self.crypto.application_key = os.urandom(32)  # Set a dummy application key
        self.crypto.is_handshake_phase = False  # Switch to application phase
        plaintext = b"Test message"
        seq_bytes, iv, ct = self.crypto.encrypt_message(plaintext)
        self.crypto.decrypt_message(seq_bytes, iv, ct)  # First decryption succeeds
        
        # Attempt to replay the same message
        with self.assertRaises(TLSError) as cm:
            self.crypto.decrypt_message(seq_bytes, iv, ct)
        self.assertIn("Replay detected", str(cm.exception))

if __name__ == '__main__':
    unittest.main()