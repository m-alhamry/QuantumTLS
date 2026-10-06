"""Actual TCP proxy corruption and active impersonation regressions."""
import socket
import threading
from unittest.mock import patch
from cryptography.hazmat.primitives import serialization
from src.server.server_crypto import ServerCrypto
from src.utils.errors import TLSError
from src.utils.network import receive_exact
from src.utils.utils import MAX_RECORD_SIZE, RECORD_HEADER
from tests.support import CredentialsTest


class TestMITM(CredentialsTest):
    def test_tcp_proxy_changes_application_ciphertext(self):
        server = self.start_server()
        listener = socket.socket()
        self.addCleanup(listener.close)
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(3)
        proxy_port = listener.getsockname()[1]
        changed = threading.Event()
        failures = []

        def proxy():
            downstream = upstream = None
            reverse = None
            def forward(source, destination, corrupt):
                try:
                    count = 0
                    while True:
                        header = receive_exact(source, RECORD_HEADER.size)
                        _, _, length = RECORD_HEADER.unpack(header)
                        if length > MAX_RECORD_SIZE:
                            raise ValueError('Unexpected test record length')
                        body = bytearray(receive_exact(source, length))
                        count += 1
                        if corrupt and count == 3:  # ClientHello, Finished, first application record.
                            body[-1] ^= 1
                            changed.set()
                        destination.sendall(header + body)
                except (OSError, TLSError):
                    pass
                except Exception as exc:
                    failures.append(exc)
                finally:
                    try:
                        destination.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
            try:
                downstream, _ = listener.accept()
                upstream = socket.create_connection(('127.0.0.1', server.port), timeout=3)
                downstream.settimeout(3)
                reverse = threading.Thread(target=forward, args=(upstream, downstream, False))
                reverse.start()
                forward(downstream, upstream, True)
            finally:
                for sock in (downstream, upstream):
                    if sock:
                        sock.close()
                if reverse:
                    reverse.join(4)
        thread = threading.Thread(target=proxy)
        thread.start()
        def join():
            thread.join(5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(failures, [])
        self.addCleanup(join)
        from types import SimpleNamespace
        network, crypto = self.connect(SimpleNamespace(port=proxy_port))
        network.send_application_data(crypto, b'authentic message')
        with self.assertRaises((OSError, TLSError)):
            network.receive_application_data(crypto)
        self.assertTrue(changed.is_set())

    def test_client_only_certificate_cannot_impersonate_server(self):
        directory = self.directory
        cert = self.client_cert
        def malicious_identity(crypto):
            crypto.cert = cert
            crypto.cert_private_key = serialization.load_pem_private_key((directory / 'client.key').read_bytes(), None)
        with patch.object(ServerCrypto, 'load_identity', malicious_identity):
            server = self.start_server(cipher=1)
            with self.assertRaisesRegex(TLSError, 'not permitted for server'):
                self.connect(server, cipher=1)
            server.stop()

    def test_unkeyed_finished_forgery_rejected(self):
        with patch.object(ServerCrypto, 'compute_finished_message', lambda crypto: crypto.get_transcript_hash()):
            server = self.start_server(cipher=1)
            with self.assertRaisesRegex(TLSError, 'Finished verification failed'):
                self.connect(server, cipher=1)
            server.stop()

    def test_bad_server_signature_and_nonempty_extensions_rejected(self):
        with patch.object(ServerCrypto, 'compute_certificate_verify', return_value=b'forged signature'):
            server = self.start_server(cipher=1)
            with self.assertRaisesRegex(TLSError, 'CertificateVerify verification failed'):
                self.connect(server, cipher=1)
            server.stop()
        from src.utils import handshake
        original = handshake.send
        def malformed_extensions(network, kind, body=b''):
            return original(network, kind, b'unknown extension' if kind == 8 else body)
        with patch.object(handshake, 'send', malformed_extensions):
            server = self.start_server(cipher=1)
            with self.assertRaisesRegex(TLSError, 'Unexpected handshake message'):
                self.connect(server, cipher=1)
            server.stop()

    def test_server_only_identity_rejected_as_mutual_auth_client(self):
        from src.client.client_crypto import ClientCrypto
        cert, directory = self.server_cert, self.directory
        def malicious_identity(crypto):
            crypto.cert = cert
            crypto.cert_private_key = serialization.load_pem_private_key((directory / 'server.key').read_bytes(), None)
        with patch.object(ClientCrypto, 'load_identity', malicious_identity):
            server = self.start_server(cipher=1, mutual_auth=True)
            with self.assertRaises(TLSError):
                self.connect(server, cipher=1, mutual_auth=True)
            server.stop()
