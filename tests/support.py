import logging
from pathlib import Path
import tempfile
import threading
import unittest
from src.utils.certificates import generate_ca, generate_leaf
from src.client.client_crypto import ClientCrypto
from src.server.server_crypto import ServerCrypto
from src.client.client_network import ClientNetwork
from src.server.main_server import QTLServer
from src.utils.handshake import client_handshake
from src.utils.utils import CIPHER_SUITES

LOGGER = logging.getLogger('qtl.tests')
LOGGER.addHandler(logging.NullHandler())


class CredentialsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='qtl-test-')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.ca = generate_ca(self.directory)
        self.server_cert = generate_leaf(self.directory, 'server')
        self.client_cert = generate_leaf(self.directory, 'client')

    def crypto_pair(self, application=True):
        from src.utils.crypto import TLSCrypto
        client = ClientCrypto(LOGGER, cert_dir=self.directory)
        server = ServerCrypto(LOGGER, cert_dir=self.directory)
        for crypto in (client, server):
            self.addCleanup(crypto.clear_sensitive_data)
            TLSCrypto.derive_handshake_keys(crypto, b'shared test secret')
            crypto.append_handshake(1, b'client hello')
            crypto.append_handshake(2, b'server hello')
            crypto.activate_handshake_keys()
            if application:
                crypto.application_transcript = bytes(crypto.handshake_transcript)
                crypto.derive_application_key()
        return client, server

    def start_server(self, **kwargs):
        server = QTLServer(port=0, cert_dir=self.directory, logger=LOGGER, echo=True, **kwargs)
        errors = []
        def run():
            try:
                server.serve_forever()
            except Exception as exc:
                errors.append(exc)
                server.ready.set()
        thread = threading.Thread(target=run)
        thread.start()
        def stop():
            server.stop()
            thread.join(6)
            self.assertFalse(thread.is_alive(), 'Server failed bounded shutdown')
            self.assertEqual(errors, [])
        self.addCleanup(stop)
        self.assertTrue(server.ready.wait(10), 'Server startup timed out')
        if errors:
            raise errors[0]
        return server

    def connect(self, server, *, cipher=6, mutual_auth=False, server_name=None, cert_dir=None):
        network = ClientNetwork('127.0.0.1', server.port, LOGGER, server_name=server_name,
                                handshake_timeout=3, message_timeout=3)
        self.addCleanup(network.close)
        crypto = ClientCrypto(LOGGER, network, cert_dir=cert_dir or self.directory)
        self.addCleanup(crypto.clear_sensitive_data)
        crypto.offered_suites = [CIPHER_SUITES[cipher - 1]]
        network.crypto = crypto
        network.connect()
        try:
            client_handshake(crypto, network, mutual_auth)
        except Exception:
            network.close()
            raise
        return network, crypto
