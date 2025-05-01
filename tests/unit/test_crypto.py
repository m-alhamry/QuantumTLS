import os
import unittest
from crypto import generate_ecc_keys, generate_kyber_keys
from errors import TLSError
from cryptography.hazmat.primitives.asymmetric import ec
import logging
from utils import setup_logging  # Import the setup_logging function

class TestCrypto(unittest.TestCase):
    """
    Unit tests for cryptographic utility functions in the QuantumTLS prototype.
    Tests ECC and Kyber key generation.
    """

    @classmethod
    def setUpClass(cls):
        """
        Set up the logger once before all tests.
        """
        cls.logger = setup_logging("test", "test.log", logging.DEBUG)

    @classmethod
    def tearDownClass(cls):
        """
        Clean up by closing logger handlers and removing the log file after all tests.
        """
        for handler in cls.logger.handlers:
            handler.close()  # Close all handlers to release the file
        if os.path.exists("test.log"):
            os.remove("test.log")  # Remove the log file

    def test_generate_kyber_invalid_variant(self):
        """
        Test that an invalid Kyber variant raises an error.
        """
        with self.assertRaises(TLSError) as cm:
            generate_kyber_keys(4, self.logger)  # Invalid variant
        self.assertEqual(cm.exception.alert_type, 0x2F, "Expected ILLEGAL_PARAMETER alert")
        self.assertIn("Invalid Kyber variant", str(cm.exception))

    def test_generate_ecc_keys(self):
        """
        Test ECC key generation with the secp384r1 curve.
        Verifies key types and public key byte length.
        """
        private_key, public_key, public_key_bytes = generate_ecc_keys(self.logger)
        self.assertIsInstance(private_key, ec.EllipticCurvePrivateKey, "Private key should be ECC")
        self.assertIsInstance(public_key, ec.EllipticCurvePublicKey, "Public key should be ECC")
        self.assertEqual(len(public_key_bytes), 97, "Public key bytes should be 97 for secp384r1")

    def test_generate_kyber_keys(self):
        """
        Test Kyber768 key generation.
        Verifies KEM name and public key length.
        """
        kem, public_key = generate_kyber_keys(2, self.logger)  # Kyber768
        self.assertEqual(kem.details['name'], 'Kyber768', "KEM should be Kyber768")
        self.assertEqual(len(public_key), 1184, "Public key length should be 1184 for Kyber768")

if __name__ == '__main__':
    unittest.main()