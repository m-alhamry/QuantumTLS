"""Bounded QTL2 demonstration server. Importing this module has no side effects."""
import argparse
import logging
import math
from pathlib import Path
import signal
import socket
import threading
import time

from src.server.server_crypto import ServerCrypto
from src.server.server_network import ServerNetwork
from src.utils.errors import TLSError
from src.utils.handshake import server_handshake as client_server_handshake
from src.utils.utils import (
    CIPHER_SUITES, DEFAULT_CERT_DIR, DEFAULT_CIPHER, DEFAULT_IP, DEFAULT_PORT,
    HANDSHAKE_TIMEOUT, MAX_CONNECTIONS, MESSAGE_TIMEOUT, SHUTDOWN_TIMEOUT,
    close_logging, setup_logging,
)

ACKNOWLEDGEMENT = b'Message received successfully'


class QTLServer:
    def __init__(self, ip=DEFAULT_IP, port=DEFAULT_PORT, *, cert_dir=DEFAULT_CERT_DIR,
                 cipher=DEFAULT_CIPHER, mutual_auth=False, max_connections=MAX_CONNECTIONS,
                 handshake_timeout=HANDSHAKE_TIMEOUT, message_timeout=MESSAGE_TIMEOUT,
                 shutdown_timeout=SHUTDOWN_TIMEOUT, logger=None, echo=False, test_interrupt=False):
        if cipher not in range(1, len(CIPHER_SUITES) + 1) or max_connections < 1:
            raise ValueError('Invalid server policy')
        if not all(math.isfinite(t) and t > 0 for t in (handshake_timeout, message_timeout, shutdown_timeout)):
            raise ValueError('Timeouts must be positive')
        self.ip, self.port, self.cert_dir = ip, port, cert_dir
        self.suite, self.mutual_auth = CIPHER_SUITES[cipher - 1], mutual_auth
        self.max_connections = max_connections
        self.handshake_timeout, self.message_timeout = handshake_timeout, message_timeout
        self.shutdown_timeout = shutdown_timeout
        self.logger = logger or logging.getLogger('qtl.server')
        self.echo, self.test_interrupt = echo, test_interrupt
        self.ready = threading.Event()
        self.stopped = threading.Event()
        self._lock = threading.Lock()
        self._connections = {}
        self.listener = None

    @property
    def active_connections(self):
        with self._lock:
            return len(self._connections)

    def serve_forever(self):
        # Fail before accepting connections when local credentials are unusable.
        probe = ServerCrypto(self.logger, cert_dir=self.cert_dir)
        try:
            probe.load_identity()
            if self.suite != CIPHER_SUITES[0]:
                from src.utils.crypto import create_kem
                from src.utils.utils import KYBER_VARIANTS
                kem = create_kem(KYBER_VARIANTS[self.suite])
                kem.free()
        finally:
            probe.clear_sensitive_data()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener = listener
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((self.ip, self.port))
            listener.listen(self.max_connections)
            listener.settimeout(0.2)
            self.port = listener.getsockname()[1]
            self.logger.info('Listening on %s:%d', self.ip, self.port)
            self.ready.set()
            while not self.stopped.is_set():
                try:
                    sock, address = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self.stopped.is_set():
                        break
                    raise
                with self._lock:
                    if self.stopped.is_set() or len(self._connections) >= self.max_connections:
                        sock.close()
                        continue
                    worker = threading.Thread(target=self._handle, args=(sock, address), daemon=True)
                    self._connections[worker] = sock
                try:
                    worker.start()
                except Exception:
                    with self._lock:
                        self._connections.pop(worker, None)
                    sock.close()
                    raise
        finally:
            self.stop()
            until = time.monotonic() + self.shutdown_timeout
            with self._lock:
                workers = list(self._connections)
            for worker in workers:
                worker.join(max(0, until - time.monotonic()))

    def stop(self):
        self.stopped.set()
        if self.listener is not None:
            self.listener.close()
        with self._lock:
            sockets = list(self._connections.values())
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()

    def _handle(self, sock, address):
        network = ServerNetwork(address[0], address[1], self.logger,
                                handshake_timeout=self.handshake_timeout, message_timeout=self.message_timeout)
        network.sock = sock
        crypto = None
        try:
            crypto = ServerCrypto(self.logger, network, cert_dir=self.cert_dir)
            network.crypto = crypto
            client_server_handshake(crypto, network, self.mutual_auth, self.suite)
            while not self.stopped.is_set():
                message = network.receive_application_data(crypto)
                if message is None:
                    network.end_session()
                    break
                if self.test_interrupt:
                    break
                network.send_application_data(crypto, message if self.echo else ACKNOWLEDGEMENT)
        except (OSError, TLSError, ValueError) as exc:
            self.logger.info('Connection ended: %s', exc)
            if isinstance(exc, TLSError):
                try:
                    network.send_alert(exc.alert_type)
                except (OSError, TLSError):
                    pass
        except Exception:
            self.logger.exception('Unexpected connection failure')
        finally:
            network.close()
            if crypto is not None:
                crypto.clear_sensitive_data()
            with self._lock:
                self._connections.pop(threading.current_thread(), None)


def main(argv=None):
    parser = argparse.ArgumentParser(description='QTL2 prototype server (not TLS)')
    parser.add_argument('--ip', default=DEFAULT_IP)
    parser.add_argument('--port', type=int, default=DEFAULT_PORT)
    parser.add_argument('--cert-dir', type=Path, default=DEFAULT_CERT_DIR)
    parser.add_argument('--log-dir', type=Path, default=Path('logs'))
    parser.add_argument('--cipher', type=int, choices=range(1, 8), default=DEFAULT_CIPHER)
    parser.add_argument('--mutual-auth', choices=['enable', 'disable'], default='disable')
    parser.add_argument('--max-connections', type=int, default=MAX_CONNECTIONS)
    parser.add_argument('--handshake-timeout', type=float, default=HANDSHAKE_TIMEOUT)
    parser.add_argument('--message-timeout', type=float, default=MESSAGE_TIMEOUT)
    parser.add_argument('--echo', action='store_true', help='Echo received payloads for exact round-trip checks')
    parser.add_argument('--test-mode', action='store_true')
    parser.add_argument('--test-interrupt', action='store_true')
    args = parser.parse_args(argv)
    if args.test_interrupt and not args.test_mode:
        parser.error('--test-interrupt requires --test-mode')
    logger = setup_logging('qtl.server', str(args.log_dir / 'server.log'))
    server = None
    handlers = {}
    try:
        server = QTLServer(args.ip, args.port, cert_dir=args.cert_dir, cipher=args.cipher,
                           mutual_auth=args.mutual_auth == 'enable', max_connections=args.max_connections,
                           handshake_timeout=args.handshake_timeout, message_timeout=args.message_timeout,
                           logger=logger, echo=args.echo, test_interrupt=args.test_interrupt)
        if threading.current_thread() is threading.main_thread():
            for sig in (signal.SIGINT, signal.SIGTERM):
                handlers[sig] = signal.signal(sig, lambda *_: server.stopped.set())
        server.serve_forever()
        return 0
    except (OSError, TLSError, ValueError) as exc:
        logger.error('Server failed: %s', exc)
        return 1
    finally:
        if server is not None:
            server.stop()
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
        close_logging(logger)


if __name__ == '__main__':
    raise SystemExit(main())
