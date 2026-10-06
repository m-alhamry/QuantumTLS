from unittest.mock import patch
from src.client.client_crypto import ClientCrypto
from src.utils.errors import TLSError
from src.utils.utils import CIPHER_SUITES
from tests.support import CredentialsTest, LOGGER


class TestClientCrypto(CredentialsTest):
    def test_ecc_does_not_generate_kem(self):
        crypto = ClientCrypto(LOGGER, cert_dir=self.directory)
        self.addCleanup(crypto.clear_sensitive_data)
        with patch('src.client.client_crypto.generate_kyber_keys') as kem:
            crypto.generate_keys([CIPHER_SUITES[0]])
        kem.assert_not_called()
        self.assertEqual(crypto.kyber_kems, {})

    def test_only_offered_kem_generated_and_freed(self):
        crypto = ClientCrypto(LOGGER, cert_dir=self.directory)
        self.addCleanup(crypto.clear_sensitive_data)
        crypto.generate_keys([CIPHER_SUITES[5]])
        self.assertEqual(set(crypto.kyber_kems), {5})
        kem = crypto.kyber_kems[5]
        with patch.object(kem, 'free', wraps=kem.free) as free:
            crypto.generate_keys([CIPHER_SUITES[0]])
        free.assert_called_once()

    def test_reject_invalid_offers(self):
        crypto = ClientCrypto(LOGGER, cert_dir=self.directory)
        self.addCleanup(crypto.clear_sensitive_data)
        for suites in ([], ['unknown'], [CIPHER_SUITES[0]] * 2):
            with self.assertRaises(TLSError):
                crypto.generate_keys(suites)
