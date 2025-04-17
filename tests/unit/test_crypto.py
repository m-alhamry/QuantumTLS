import unittest
from crypto import generate_ecc_keys, generate_kyber_keys
from errors import TLSError
from cryptography.hazmat.primitives.asymmetric import ec
import oqs
import logging

class TestCrypto(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger('test')

    def test_generate_kyber_invalid_variant(self):
        with self.assertRaises(TLSError) as cm:
            generate_kyber_keys(4, self.logger)
        self.assertEqual(cm.exception.alert_type, 0x2F)
        self.assertIn("Invalid Kyber variant", str(cm.exception))

    def test_generate_ecc_keys(self):
        private_key, public_key, public_key_bytes = generate_ecc_keys(self.logger)
        self.assertIsInstance(private_key, ec.EllipticCurvePrivateKey)
        self.assertIsInstance(public_key, ec.EllipticCurvePublicKey)
        self.assertEqual(len(public_key_bytes), 97)

    def test_generate_kyber_keys(self):
        kem, public_key = generate_kyber_keys(2, self.logger)
        self.assertEqual(kem.details['name'], 'Kyber768')
        self.assertEqual(len(public_key), 1184)

if __name__ == '__main__':
    unittest.main()