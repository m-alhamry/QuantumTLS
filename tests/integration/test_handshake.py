import socket
import time
from src.utils.errors import TLSError
from tests.support import CredentialsTest


class TestHandshake(CredentialsTest):
    def test_all_suites_both_auth_modes_exact_round_trip(self):
        payloads = [b'', b'END_SESSION'] + [bytes(range(256)) * (size // 256) + b'x' * (size % 256)
                    for size in (1, 16383, 16384, 16385, 32770, 1048576)]
        for cipher in range(1, 8):
            for mutual in (False, True):
                with self.subTest(cipher=cipher, mutual_auth=mutual):
                    server = self.start_server(cipher=cipher, mutual_auth=mutual)
                    network, crypto = self.connect(server, cipher=cipher, mutual_auth=mutual)
                    self.assertFalse(crypto.is_handshake_phase)
                    self.assertFalse(crypto.kyber_kems)
                    for payload in payloads:
                        network.send_application_data(crypto, payload)
                        self.assertEqual(network.receive_application_data(crypto), payload)
                    network.end_session()
                    self.assertIsNone(network.receive_application_data(crypto))
                    network.close()
                    server.stop()

    def test_hostname_mismatch_rejected(self):
        server = self.start_server()
        with self.assertRaises(TLSError):
            self.connect(server, server_name='attacker.invalid')

    def test_dns_san_match(self):
        server = self.start_server()
        network, crypto = self.connect(server, server_name='localhost')
        network.end_session()
        self.assertIsNone(network.receive_application_data(crypto))

    def test_suite_policy_rejected(self):
        server = self.start_server(cipher=6)
        with self.assertRaises((TLSError, OSError)):
            self.connect(server, cipher=1)

    def test_mutual_auth_policy_mismatch_both_directions(self):
        for mutual in (False, True):
            server = self.start_server(mutual_auth=mutual)
            with self.assertRaises(TLSError):
                self.connect(server, mutual_auth=not mutual)
            server.stop()

    def test_slow_handshake_connection_cap_and_shutdown(self):
        server = self.start_server(max_connections=2, handshake_timeout=0.3)
        first = socket.create_connection(('127.0.0.1', server.port), timeout=2)
        second = socket.create_connection(('127.0.0.1', server.port), timeout=2)
        self.addCleanup(first.close)
        self.addCleanup(second.close)
        until = time.monotonic() + 1
        while server.active_connections < 2 and time.monotonic() < until:
            time.sleep(0.005)
        self.assertEqual(server.active_connections, 2)
        third = socket.create_connection(('127.0.0.1', server.port), timeout=2)
        self.addCleanup(third.close)
        self.assertEqual(third.recv(1), b'')
        self.assertEqual(first.recv(1), b'')
        self.assertEqual(second.recv(1), b'')
        until = time.monotonic() + 1
        while server.active_connections and time.monotonic() < until:
            time.sleep(0.005)
        self.assertEqual(server.active_connections, 0)
        start = time.monotonic()
        server.stop()
        self.assertLess(time.monotonic() - start, 1)

    def test_live_session_repeated_messages(self):
        server = self.start_server(message_timeout=2)
        network, crypto = self.connect(server)
        for i in range(12):
            payload = ('live session ' + str(i)).encode()
            network.send_application_data(crypto, payload)
            self.assertEqual(network.receive_application_data(crypto), payload)
            time.sleep(0.01)
        network.end_session()
        self.assertIsNone(network.receive_application_data(crypto))
