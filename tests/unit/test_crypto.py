import unittest
from unittest.mock import patch
from crypto import generate_ecc_keys, generate_kyber_keys, encapsulate_kyber, TLSError  # Import TLSError
from cryptography.hazmat.primitives.asymmetric import ec
import oqs
import logging

class TestCrypto(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger('test')

    def test_generate_kyber_invalid_variant(self):
        with self.assertRaises(TLSError) as cm:
            generate_kyber_keys(4, self.logger)  # Invalid variant
        self.assertEqual(cm.exception.alert_type, 0x2F)  # ALERT_ILLEGAL_PARAMETER
        self.assertIn("Invalid Kyber variant", str(cm.exception))

    def test_generate_ecc_keys(self):
        private_key, public_key, public_key_bytes = generate_ecc_keys(self.logger)
        self.assertIsInstance(private_key, ec.EllipticCurvePrivateKey)
        self.assertIsInstance(public_key, ec.EllipticCurvePublicKey)
        self.assertEqual(len(public_key_bytes), 97)  # SECP384R1 uncompressed

    def test_generate_kyber_keys(self):
        kem, public_key = generate_kyber_keys(2, self.logger)  # Kyber768
        self.assertEqual(kem.details['name'], 'Kyber768')
        self.assertEqual(len(public_key), 1184)  # Kyber768 public key size

    @patch('oqs.KeyEncapsulation.encap_secret')
    def test_encapsulate_kyber(self, mock_encap):
        mock_encap.return_value = (b'ciphertext', b'shared_secret')
        kem = oqs.KeyEncapsulation('Kyber768')
        public_key = b'\x00' * 1184
        ct, ss = encapsulate_kyber(kem, public_key, self.logger)
        self.assertEqual(ct, b'ciphertext')
        self.assertEqual(ss, b'shared_secret')
        mock_encap.assert_called_once_with(public_key)

if __name__ == '__main__':
    unittest.main()