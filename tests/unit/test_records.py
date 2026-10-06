from unittest.mock import patch
from src.utils.network import BaseNetwork
from src.utils.errors import TLSError
from src.utils.utils import (
    ALERT_CLOSE_NOTIFY, ALERT_TYPE, MAX_RECORD_SIZE, MSG_TYPE_APPLICATION,
    RECORD_HEADER, RECORD_MAGIC,
)
from tests.support import CredentialsTest, LOGGER


class MemorySocket:
    def __init__(self, data=b''):
        self.data = bytearray(data)
        self.closed = False
        self.timeout = None

    def sendall(self, data):
        self.data.extend(data)

    def recv(self, count):
        # Deliberate short reads exercise receive_exact on headers and payloads.
        size = min(count, 7, len(self.data))
        data = bytes(self.data[:size])
        del self.data[:size]
        return data

    def settimeout(self, value):
        self.timeout = value

    def shutdown(self, *_):
        pass

    def close(self):
        self.closed = True


class TestRecords(CredentialsTest):
    def pair(self):
        client, server = self.crypto_pair()
        a, b = (BaseNetwork('localhost', 0, LOGGER) for _ in range(2))
        a.crypto, b.crypto = client, server
        a.sock = b.sock = MemorySocket()
        return a, b

    def test_exact_payload_boundaries_empty_and_control_like_data(self):
        a, b = self.pair()
        for data in (b'', b'END_SESSION', b'x' * 16384, b'y' * 16385, b'z' * 32770):
            a.send_application_data(a.crypto, data)
            self.assertEqual(b.receive_application_data(b.crypto), data)
        a.end_session()
        self.assertIsNone(b.receive_application_data(b.crypto))

    def test_record_type_ciphertext_sequence_and_header_tampering(self):
        for index in (0, 4, 8, 9, 17, 25, -1):
            with self.subTest(index=index):
                a, b = self.pair()
                a.send_application_data(a.crypto, b'payload')
                a.sock.data[index] ^= 1
                with self.assertRaises(TLSError):
                    b.receive_application_data(b.crypto)
                self.assertIsNone(b.sock)

    def test_reflected_application_record_rejected(self):
        a, _ = self.pair()
        a.send_application_data(a.crypto, b'payload')
        with self.assertRaises(TLSError):
            a.receive_application_data(a.crypto)

    def test_final_flag_is_authenticated(self):
        a, b = self.pair()
        a.send_application_data(a.crypto, b'x' * 32770)
        # Ciphertext byte corresponding to the final flag, after header, seq, inner type.
        a.sock.data[RECORD_HEADER.size + 8 + 1] ^= 1
        with self.assertRaises(TLSError):
            b.receive_application_data(b.crypto)

    def test_declared_size_bounded_before_body_read(self):
        _, b = self.pair()
        b.sock = MemorySocket(RECORD_HEADER.pack(RECORD_MAGIC, MSG_TYPE_APPLICATION, MAX_RECORD_SIZE + 1))
        with self.assertRaises(TLSError):
            b.receive_application_data(b.crypto)

    def test_unfinished_message_eof_or_close_rejected(self):
        for close in (False, True):
            a, b = self.pair()
            a._send_record(MSG_TYPE_APPLICATION, b'\x00partial')
            if close:
                a.end_session()
            with self.assertRaises(TLSError):
                b.receive_application_data(b.crypto)

    def test_invalid_inner_framing_fails_closed(self):
        for body in (b'', b'\x02x', b'\x00', b'\x01' + b'x' * 16385):
            a, b = self.pair()
            a._send_record(MSG_TYPE_APPLICATION, body)
            with self.assertRaises(TLSError):
                b.receive_application_data(b.crypto)
            self.assertIsNone(b.sock)

    def test_message_size_and_chunk_count_limits(self):
        a, b = self.pair()
        b.max_message_size = 10
        a.send_application_data(a.crypto, b'x' * 11)
        with self.assertRaises(TLSError):
            b.receive_application_data(b.crypto)
        a, b = self.pair()
        for _ in range(3):
            a._send_record(MSG_TYPE_APPLICATION, b'\x00a')
        with patch('src.utils.network.MAX_MESSAGE_CHUNKS', 2), self.assertRaises(TLSError):
            b.receive_application_data(b.crypto)

    def test_legacy_plaintext_alerts_and_records_rejected(self):
        for raw in (b'\x16\x03\x03\x00\x04test', RECORD_HEADER.pack(RECORD_MAGIC, ALERT_TYPE, 1) + bytes([ALERT_CLOSE_NOTIFY])):
            _, b = self.pair()
            b.sock = MemorySocket(raw)
            with self.assertRaises(TLSError):
                b.receive_application_data(b.crypto)

    def test_sendall_failure_is_not_silently_accepted(self):
        a, _ = self.pair()
        with patch.object(a.sock, 'sendall', side_effect=OSError('broken pipe')):
            with self.assertRaises(OSError):
                a.send_application_data(a.crypto, b'a')
        self.assertIsNone(a.sock)

    def test_absolute_deadline_expires_during_slow_partial_reads(self):
        a, b = self.pair()
        a.send_application_data(a.crypto, b'x' * 100)
        clock = iter(i * 0.03 for i in range(1000))
        b.message_timeout = 0.1
        with patch('src.utils.network.time.monotonic', side_effect=lambda: next(clock)):
            with self.assertRaises(TimeoutError):
                b.receive_application_data(b.crypto)
        self.assertIsNone(b.sock)
