from src.client.client_crypto import ClientCrypto
from src.server.server_crypto import ServerCrypto
from src.utils.errors import TLSError
from src.utils.hello import encode_client_hello, encode_server_hello, parse_client_hello, parse_server_hello, encode_shares
from src.utils.utils import CIPHER_SUITES, CIPHER_SUITE_CODES, GROUP_SECP384R1, PROTOCOL_VERSION, vector
from tests.support import CredentialsTest, LOGGER


class TestHello(CredentialsTest):
    def setUp(self):
        super().setUp()
        self.client = ClientCrypto(LOGGER, cert_dir=self.directory)
        self.addCleanup(self.client.clear_sensitive_data)
        self.client.generate_keys(CIPHER_SUITES)
        self.hello = encode_client_hello(self.client)

    def test_all_offers_parse_and_every_truncation_rejected(self):
        parsed = parse_client_hello(self.hello)
        self.assertEqual(len(parsed['key_shares']), 7)
        for size in range(len(self.hello)):
            with self.assertRaises(TLSError, msg=f'truncated at {size}'):
                parse_client_hello(self.hello[:size])

    def test_client_invalid_version_lengths_duplicates_missing_extra(self):
        prefix = PROTOCOL_VERSION + bytes(32)
        ecc = CIPHER_SUITE_CODES[CIPHER_SUITES[0]]
        share = {GROUP_SECP384R1: self.client.ecc_public_key_bytes}
        invalid = [self.hello + b'x', b'\x03\x03' + self.hello[2:],
                   prefix + vector(b''), prefix + vector(ecc + ecc) + encode_shares(share),
                   prefix + vector(b'\xff\xff') + encode_shares(share),
                   prefix + vector(ecc) + encode_shares({}),
                   prefix + vector(ecc) + encode_shares({**share, 99: b'unknown'}),
                   prefix + vector(ecc) + vector((GROUP_SECP384R1.to_bytes(2, 'big') + vector(share[GROUP_SECP384R1])) * 2)]
        for body in invalid:
            with self.assertRaises(TLSError):
                parse_client_hello(body)

    def test_server_unoffered_suite_bad_lengths_and_trailing(self):
        server = ServerCrypto(LOGGER, cert_dir=self.directory)
        self.addCleanup(server.clear_sensitive_data)
        server.generate_ecc_keys()
        server.cipher_suite = CIPHER_SUITES[0]
        body = encode_server_hello(server, None)
        self.assertEqual(parse_server_hello(body, CIPHER_SUITES)['ecc_pk'], server.ecc_public_key_bytes)
        for size in range(len(body)):
            with self.assertRaises(TLSError):
                parse_server_hello(body[:size], CIPHER_SUITES)
        with self.assertRaises(TLSError):
            parse_server_hello(body, CIPHER_SUITES[1:])
        with self.assertRaises(TLSError):
            parse_server_hello(body + b'x', CIPHER_SUITES)
