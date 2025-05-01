import unittest
import logging
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import hashes
from src.server.server_crypto import ServerCrypto
from src.errors import TLSError
from src.crypto import get_hash
from src.utils import ALERT_BAD_CERTIFICATE, CERT_VERIFY_CONTEXT_PADDING, TLS13_CLIENT_CERT_VERIFY_CONTEXT

class TestMitmSimulation(unittest.TestCase):
    """
    Tests to simulate Man-In-The-Middle attacks by tampering with certificate verification
    in the QuantumTLS prototype. Focuses on ServerCrypto's certificate verification logic.
    """

    def setUp(self):
        """
        Set up the test environment with a logger, ServerCrypto instance, and client credentials.
        """
        self.logger = logging.getLogger('test')
        self.crypto = ServerCrypto(self.logger)
        # Load client certificate and private key
        with open("src/client/client.crt", "rb") as f:
            self.client_cert = load_pem_x509_certificate(f.read())
        with open("src/client/client.key", "rb") as f:
            self.client_private_key = load_pem_private_key(f.read(), password=None)
        
        # Validate that the private key matches the certificate
        public_key_from_private = self.client_private_key.public_key()
        cert_public_key = self.client_cert.public_key()
        self.assertEqual(
            public_key_from_private.public_numbers(),
            cert_public_key.public_numbers(),
            "Client private key does not match certificate"
        )
        
        # Ensure the certificate uses the expected curve (secp384r1)
        self.assertIsInstance(self.client_cert.public_key(), ec.EllipticCurvePublicKey)
        self.assertEqual(self.client_cert.public_key().curve.name, "secp384r1",
                         "Certificate must use secp384r1 curve")
        
        # Set a sample handshake transcript for testing
        self.crypto.handshake_transcript = b"sample handshake transcript"

    def compute_signature(self, transcript):
        """
        Helper method to compute a CertificateVerify signature over a transcript.

        Args:
            transcript (bytes): Handshake transcript to sign.

        Returns:
            bytes: ECDSA signature using SHA384.
        """
        transcript_hash = get_hash(transcript)  # Compute SHA384 hash of the transcript
        context = CERT_VERIFY_CONTEXT_PADDING + TLS13_CLIENT_CERT_VERIFY_CONTEXT + b"\x00"
        signature_input = context + transcript_hash
        return self.client_private_key.sign(signature_input, ec.ECDSA(hashes.SHA384()))

    def test_verify_certificate_verify_valid(self):
        """
        Test that a valid CertificateVerify signature is accepted by the server.
        """
        signature = self.compute_signature(self.crypto.handshake_transcript)
        client_cert_bytes = self.client_cert.public_bytes(Encoding.DER)

        # Perform manual verification for comparison
        transcript_hash = get_hash(self.crypto.handshake_transcript)
        context = CERT_VERIFY_CONTEXT_PADDING + TLS13_CLIENT_CERT_VERIFY_CONTEXT + b"\x00"
        signature_input = context + transcript_hash
        client_public_key = self.client_cert.public_key()
        try:
            client_public_key.verify(signature, signature_input, ec.ECDSA(hashes.SHA384()))
        except Exception as e:
            self.fail(f"Manual signature verification failed: {e}")

        # Test ServerCrypto's verification
        result = self.crypto.verify_certificate_verify(signature, client_cert_bytes)
        self.assertTrue(result, "Server should accept a valid signature")

    def test_verify_certificate_verify_tampered_signature(self):
        """
        Test that a tampered CertificateVerify signature is rejected by the server.
        """
        signature = self.compute_signature(self.crypto.handshake_transcript)
        # Tamper with the signature by replacing the last byte
        tampered_signature = signature[:-1] + b'\x00'
        client_cert_bytes = self.client_cert.public_bytes(Encoding.DER)

        with self.assertRaises(TLSError) as cm:
            self.crypto.verify_certificate_verify(tampered_signature, client_cert_bytes)
        self.assertEqual(cm.exception.alert_type, ALERT_BAD_CERTIFICATE,
                         "Server should reject tampered signature with ALERT_BAD_CERTIFICATE")

    def test_verify_certificate_verify_invalid_certificate(self):
        """
        Test that an invalid certificate is rejected during CertificateVerify verification.
        """
        signature = self.compute_signature(self.crypto.handshake_transcript)
        invalid_cert_bytes = b"invalid cert data"  # Malformed certificate data

        with self.assertRaises(TLSError) as cm:
            self.crypto.verify_certificate_verify(signature, invalid_cert_bytes)
        self.assertEqual(cm.exception.alert_type, ALERT_BAD_CERTIFICATE,
                         "Server should reject invalid certificate with ALERT_BAD_CERTIFICATE")
        self.assertIn("CertificateVerify verification failed", str(cm.exception),
                      "Error message should indicate parsing failure")

    def test_verify_certificate_verify_tampered_transcript(self):
        """
        Test that a signature with a tampered handshake transcript is rejected.
        """
        original_transcript = b"original transcript"
        signature = self.compute_signature(original_transcript)
        # Simulate MITM by altering the transcript
        self.crypto.handshake_transcript = b"tampered transcript"
        client_cert_bytes = self.client_cert.public_bytes(Encoding.DER)

        with self.assertRaises(TLSError) as cm:
            self.crypto.verify_certificate_verify(signature, client_cert_bytes)
        self.assertEqual(cm.exception.alert_type, ALERT_BAD_CERTIFICATE,
                         "Server should reject signature with tampered transcript")

if __name__ == '__main__':
    unittest.main()