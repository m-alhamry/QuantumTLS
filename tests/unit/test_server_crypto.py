from src.server.server_crypto import ServerCrypto
from src.utils.errors import TLSError
from src.utils.utils import CIPHER_SUITES, CIPHER_SUITE_CODES
from tests.support import CredentialsTest, LOGGER


class TestServerCrypto(CredentialsTest):
    def test_policy_has_no_ecc_fallback(self):
        crypto = ServerCrypto(LOGGER, cert_dir=self.directory)
        self.addCleanup(crypto.clear_sensitive_data)
        hello = {'cipher_suites': CIPHER_SUITE_CODES[CIPHER_SUITES[0]]}
        with self.assertRaises(TLSError):
            crypto.select_cipher_suite(hello, CIPHER_SUITES[5])
        self.assertEqual(crypto.select_cipher_suite(hello, CIPHER_SUITES[0])[:2], (False, None))

    def test_hybrid_requires_secret(self):
        crypto = ServerCrypto(LOGGER, cert_dir=self.directory)
        self.addCleanup(crypto.clear_sensitive_data)
        with self.assertRaises(TLSError):
            crypto.derive_handshake_keys({}, True, None)
