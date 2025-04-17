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
    def setUp(self):
        self.logger = logging.getLogger('test')
        with open("ca.crt", "rb") as f:
            self.ca_cert = load_pem_x509_certificate(f.read())
        with open("server.crt", "rb") as f:  # Load server certificate for verification tests
            self.server_cert = load_pem_x509_certificate(f.read())
        # Add server private key loading
        with open("server.key", "rb") as f:
            self.server_private_key = load_pem_private_key(f.read(), password=None)
        
        self.crypto = ClientCrypto(self.logger, self.ca_cert)
        self.crypto.load_certificate()  # Load client certificate and key
        self.crypto.handshake_transcript = b"test data"

    def test_load_certificate(self):
        self.assertIsNotNone(self.crypto.cert)
        self.assertIsNotNone(self.crypto.cert_private_key)

    def test_compute_certificate_verify(self):
        signature = self.crypto.compute_certificate_verify()
        self.assertTrue(len(signature) > 0)

    def test_verify_certificate_verify(self):
        # Generate signature using server's private key with server context
        transcript_hash = self.crypto.get_transcript_hash()
        context = CERT_VERIFY_CONTEXT_PADDING + TLS13_SERVER_CERT_VERIFY_CONTEXT + b"\x00"
        signature_input = context + transcript_hash
        signature = self.server_private_key.sign(signature_input, ec.ECDSA(hashes.SHA384()))
        server_cert_bytes = self.server_cert.public_bytes(Encoding.DER)
        result = self.crypto.verify_certificate_verify(signature, server_cert_bytes)
        self.assertTrue(result)

    def test_server_cert_key_type(self):
        public_key = self.server_cert.public_key()
        from cryptography.hazmat.primitives.asymmetric import ec
        self.assertIsInstance(public_key, ec.EllipticCurvePublicKey)

    def test_verify_certificate_verify_failure(self):
        server_cert_bytes = self.server_cert.public_bytes(Encoding.DER)
        invalid_signature = b'\x00' * 64  # Invalid signature to trigger failure
        with self.assertRaises(TLSError) as cm:
            self.crypto.verify_certificate_verify(invalid_signature, server_cert_bytes)
        self.assertIn("Server CertificateVerify verification failed", str(cm.exception))

    def test_replay_attack_prevention(self):
        self.crypto.application_key = os.urandom(32)
        self.crypto.is_handshake_phase = False
        plaintext = b"Test message"
        seq_bytes, iv, ct = self.crypto.encrypt_message(plaintext)
        self.crypto.decrypt_message(seq_bytes, iv, ct)
        with self.assertRaises(TLSError) as cm:
            self.crypto.decrypt_message(seq_bytes, iv, ct)
        self.assertIn("Replay detected", str(cm.exception))

if __name__ == '__main__':
    unittest.main()