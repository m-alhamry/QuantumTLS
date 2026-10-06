"""Bounded QTL2 records. All encrypted metadata is authenticated."""
from contextlib import contextmanager
import socket
import math
import time

from src.utils.errors import TLSError
from src.utils.utils import (
    ALERT_BAD_RECORD_MAC, ALERT_CLOSE_NOTIFY, ALERT_DECODE_ERROR, ALERT_DESCRIPTIONS,
    ALERT_INTERNAL_ERROR, ALERT_PROTOCOL_VERSION, ALERT_RECORD_OVERFLOW, ALERT_TYPE,
    ALERT_UNEXPECTED_MESSAGE, HANDSHAKE_TIMEOUT, MAX_MESSAGE_CHUNKS, MAX_MESSAGE_SIZE,
    MAX_PLAINTEXT_SIZE, MAX_RECORD_SIZE, MESSAGE_TIMEOUT, MSG_TYPE_APPLICATION,
    MSG_TYPE_HANDSHAKE, RECORD_HEADER, RECORD_MAGIC, Reader, SEQ_BYTES_LENGTH,
    SESSION_TIMEOUT, vector,
)


def receive_exact(sock, size, deadline=None):
    data = bytearray()
    while len(data) < size:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Operation deadline exceeded')
            sock.settimeout(remaining)
        packet = sock.recv(size - len(data))
        if not packet:
            # EOF is truncation, not authenticated close_notify.
            raise TLSError('Connection closed without close_notify', ALERT_DECODE_ERROR)
        data.extend(packet)
    return bytes(data)


class BaseNetwork:
    def __init__(self, ip, port, logger, *, max_message_size=MAX_MESSAGE_SIZE,
                 handshake_timeout=HANDSHAKE_TIMEOUT, message_timeout=MESSAGE_TIMEOUT):
        if not 0 < max_message_size <= MAX_MESSAGE_SIZE or not all(math.isfinite(t) and t > 0 for t in (handshake_timeout, message_timeout)):
            raise ValueError('Invalid connection limits')
        self.ip, self.port, self.logger = ip, port, logger
        self.sock = self.crypto = None
        self.max_message_size = max_message_size
        self.handshake_timeout = handshake_timeout
        self.message_timeout = message_timeout
        self._deadline = None
        self.sent_close = self.received_close = False

    @contextmanager
    def deadline(self, seconds):
        previous = self._deadline
        self._deadline = min(previous, time.monotonic() + seconds) if previous else time.monotonic() + seconds
        try:
            yield
        finally:
            self._deadline = previous
            if self.sock is not None:
                try:
                    self.sock.settimeout(SESSION_TIMEOUT)
                except OSError:
                    pass

    def _sendall(self, data):
        if self._deadline is not None:
            remaining = self._deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Operation deadline exceeded')
            self.sock.settimeout(remaining)
        self.sock.sendall(data)

    def _send_record(self, kind, body, *, plaintext=False):
        encrypted = self.crypto is not None and self.crypto.keys_ready
        if plaintext and encrypted:
            raise TLSError('Plaintext record after key establishment', ALERT_UNEXPECTED_MESSAGE)
        try:
            if encrypted:
                inner = bytes([kind]) + body
                size = SEQ_BYTES_LENGTH + len(inner) + 16
                if size > MAX_RECORD_SIZE:
                    raise TLSError('Record too large', ALERT_RECORD_OVERFLOW)
                header = RECORD_HEADER.pack(RECORD_MAGIC, MSG_TYPE_APPLICATION, size)
                seq, _, ct = self.crypto.encrypt_message(inner, header)
                self._sendall(header + seq + ct)
            else:
                if kind not in (MSG_TYPE_HANDSHAKE, ALERT_TYPE) or len(body) > MAX_RECORD_SIZE:
                    raise TLSError('Invalid plaintext record', ALERT_UNEXPECTED_MESSAGE)
                self._sendall(RECORD_HEADER.pack(RECORD_MAGIC, kind, len(body)) + body)
        except (OSError, TLSError):
            self.close()
            raise

    def _receive_record(self):
        try:
            header = receive_exact(self.sock, RECORD_HEADER.size, self._deadline)
            magic, kind, length = RECORD_HEADER.unpack(header)
            if magic != RECORD_MAGIC:
                raise TLSError('Expected QTL2; legacy QTL and TLS are unsupported', ALERT_PROTOCOL_VERSION)
            if not 0 < length <= MAX_RECORD_SIZE:
                raise TLSError('Invalid record length', ALERT_RECORD_OVERFLOW)
            encrypted = self.crypto is not None and self.crypto.keys_ready
            if encrypted and (kind != MSG_TYPE_APPLICATION or length < SEQ_BYTES_LENGTH + 17):
                raise TLSError('Expected protected record', ALERT_BAD_RECORD_MAC)
            if not encrypted and kind not in (MSG_TYPE_HANDSHAKE, ALERT_TYPE):
                raise TLSError('Unexpected plaintext record type', ALERT_UNEXPECTED_MESSAGE)
            data = receive_exact(self.sock, length, self._deadline)
            if encrypted:
                seq, ct = data[:SEQ_BYTES_LENGTH], data[SEQ_BYTES_LENGTH:]
                iv = self.crypto.nonce(self.crypto.recv_iv, self.crypto.recv_seq)
                data = self.crypto.decrypt_message(seq, iv, ct, header)
                kind, data = data[0], data[1:]
            if kind == ALERT_TYPE:
                if len(data) != 1 or data[0] not in ALERT_DESCRIPTIONS:
                    raise TLSError('Malformed alert', ALERT_DECODE_ERROR)
                if data[0] == ALERT_CLOSE_NOTIFY:
                    if not encrypted or self.crypto.is_handshake_phase:
                        raise TLSError('Premature close_notify', ALERT_UNEXPECTED_MESSAGE)
                    self.received_close = True
                    return kind, data
                raise TLSError('Peer alert: ' + ALERT_DESCRIPTIONS[data[0]], data[0])
            if kind not in (MSG_TYPE_HANDSHAKE, MSG_TYPE_APPLICATION):
                raise TLSError('Invalid content type', ALERT_UNEXPECTED_MESSAGE)
            return kind, data
        except (OSError, TLSError):
            self.close()
            raise

    def send_handshake_message(self, handshake_type, body):
        self._send_record(MSG_TYPE_HANDSHAKE, bytes([handshake_type]) + vector(body, 3), plaintext=True)
        self.crypto.append_handshake(handshake_type, body)

    def receive_handshake_message(self, *, encrypted):
        if bool(self.crypto and self.crypto.keys_ready) != encrypted:
            raise TLSError('Invalid handshake encryption state', ALERT_UNEXPECTED_MESSAGE)
        kind, data = self._receive_record()
        if kind != MSG_TYPE_HANDSHAKE:
            raise TLSError('Expected handshake message', ALERT_UNEXPECTED_MESSAGE)
        try:
            reader = Reader(data)
            handshake_type, body = reader.uint(1), reader.vector(3)
            reader.finish()
            return handshake_type, body
        except ValueError as exc:
            raise TLSError('Invalid handshake length', ALERT_DECODE_ERROR) from exc

    def send_encrypted_handshake_message(self, crypto, handshake_type, body):
        if not crypto.keys_ready or not crypto.is_handshake_phase:
            raise TLSError('Handshake keys unavailable', ALERT_INTERNAL_ERROR)
        self._send_record(MSG_TYPE_HANDSHAKE, bytes([handshake_type]) + vector(body, 3))
        crypto.append_handshake(handshake_type, body)

    def receive_encrypted_handshake_message(self, crypto):
        return self.receive_handshake_message(encrypted=True)

    def _check_application(self):
        if self.crypto is None or self.crypto.is_handshake_phase or not self.crypto.keys_ready:
            raise TLSError('Handshake incomplete', ALERT_UNEXPECTED_MESSAGE)

    def _send_application_data(self, crypto, plaintext):
        self._check_application()
        if self.sent_close or self.received_close:
            raise TLSError('Connection closing', ALERT_UNEXPECTED_MESSAGE)
        if len(plaintext) > self.max_message_size:
            raise TLSError('Message exceeds size limit', ALERT_RECORD_OVERFLOW)
        with self.deadline(self.message_timeout):
            for offset in range(0, max(1, len(plaintext)), MAX_PLAINTEXT_SIZE):
                chunk = plaintext[offset:offset + MAX_PLAINTEXT_SIZE]
                final = int(offset + MAX_PLAINTEXT_SIZE >= len(plaintext))
                self._send_record(MSG_TYPE_APPLICATION, bytes([final]) + chunk)
        self.logger.debug('Sent application message (%d bytes)', len(plaintext))

    def _receive_encrypted_data(self, crypto):
        self._check_application()
        if self.received_close:
            raise TLSError('Connection already closed by peer', ALERT_UNEXPECTED_MESSAGE)
        data = bytearray()
        with self.deadline(self.message_timeout):
            for count in range(MAX_MESSAGE_CHUNKS):
                kind, body = self._receive_record()
                if kind == ALERT_TYPE:
                    if count:
                        raise TLSError('Truncated application message', ALERT_DECODE_ERROR)
                    return None
                if self.sent_close or kind != MSG_TYPE_APPLICATION or not body or body[0] not in (0, 1):
                    raise TLSError('Invalid application framing', ALERT_DECODE_ERROR)
                if len(body) - 1 > MAX_PLAINTEXT_SIZE or len(data) + len(body) - 1 > self.max_message_size:
                    raise TLSError('Message exceeds size limit', ALERT_RECORD_OVERFLOW)
                if len(body) == 1 and body[0] == 0:
                    raise TLSError('Empty non-final chunk', ALERT_DECODE_ERROR)
                data.extend(body[1:])
                if body[0] == 1:
                    self.logger.debug('Received application message (%d bytes)', len(data))
                    return bytes(data)
            raise TLSError('Too many message chunks', ALERT_RECORD_OVERFLOW)

    def send_application_data(self, crypto, plaintext):
        return self._send_application_data(crypto, plaintext)

    def receive_application_data(self, crypto):
        try:
            return self._receive_encrypted_data(crypto)
        except Exception:
            self.close()
            raise

    def send_alert(self, alert_type, description='', encrypt=None):
        if self.sock is None:
            return
        # Never trust a caller to downgrade an alert to plaintext after key setup.
        with self.deadline(min(1.0, self.message_timeout)):
            self._send_record(ALERT_TYPE, bytes([alert_type]))
        self.logger.debug('Sent alert %s', ALERT_DESCRIPTIONS.get(alert_type, 'unknown'))

    def end_session(self, log_message='Session complete'):
        if not self.sent_close:
            self.send_alert(ALERT_CLOSE_NOTIFY)
            self.sent_close = True

    def close(self):
        sock, self.sock = self.sock, None
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
