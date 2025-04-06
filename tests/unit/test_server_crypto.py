import unittest
from unittest.mock import Mock, patch
from errors import TLSError
from server_crypto import ServerCrypto
from cryptography.x509 import load_pem_x509_certificate
import logging

class TestServerCrypto(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger('test')
        self.crypto = ServerCrypto(self.logger)

    def test_load_certificate(self):
        self.assertIsNotNone(self.crypto.cert)
        self.assertIsNotNone(self.crypto.cert_private_key)

    def test_compute_certificate_verify(self):
        self.crypto.handshake_transcript = b"test data"
        signature = self.crypto.compute_certificate_verify()
        self.assertTrue(len(signature) > 0)

    def test_encapsulate_kyber(self):
        self.crypto.generate_keys(use_hybrid=True, kyber_variant=2)
        client_kyber_pk = b'\x00' * 1184  # Dummy Kyber768 public key
        ct, ss = self.crypto.encapsulate_kyber(client_kyber_pk)
        self.assertTrue(len(ct) > 0)
        self.assertTrue(len(ss) > 0)

    def test_mitm_simulation(self):
        self.crypto.generate_keys(use_hybrid=True, kyber_variant=2)
        client_kyber_pk = b'\x00' * 1184
        ct, ss = self.crypto.encapsulate_kyber(client_kyber_pk)
        # Simulate MITM tampering with certificate
        client_hello = {
            "ecc_pk": b'\x00' * 97,
            "kyber_pk": client_kyber_pk,
            "cert": b"tampered_cert",
            "transcript": b"client_hello"
        }
        with self.assertRaises(TLSError) as cm:
            self.crypto.derive_handshake_keys(client_hello, True, ss)
        self.assertIn("ECDH shared secret computation failed", str(cm.exception))

if __name__ == '__main__':
    unittest.main()