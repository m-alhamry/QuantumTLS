"""QTL2 client with explicit identity and algorithm policy."""
import argparse
import os
from pathlib import Path
import select
import sys
import time

from src.client.client_crypto import ClientCrypto
from src.client.client_network import ClientNetwork
from src.utils.errors import TLSError
from src.utils.handshake import client_handshake as client_server_handshake
from src.utils.utils import (
    CIPHER_SUITES, DEFAULT_CERT_DIR, DEFAULT_CIPHER, DEFAULT_IP, DEFAULT_JSON_FILE,
    DEFAULT_PORT, HANDSHAKE_TIMEOUT, MAX_MESSAGE_SIZE, MESSAGE_TIMEOUT, SESSION_TIMEOUT,
    close_logging, setup_logging,
)


def timed_input(prompt):
    print(prompt, end='', flush=True)
    deadline = time.monotonic() + SESSION_TIMEOUT
    data = bytearray()
    while len(data) <= MAX_MESSAGE_SIZE:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([sys.stdin], [], [], remaining)[0]:
            raise TimeoutError('User input deadline exceeded')
        # Read only ready bytes; readline() could block forever on a partial pipe.
        value = os.read(sys.stdin.fileno(), 1)
        if not value:
            if not data:
                raise EOFError('Input ended')
            break
        if value == b'\n':
            break
        data.extend(value)
    if len(data) > MAX_MESSAGE_SIZE:
        raise ValueError('Input too large')
    return data.decode('utf-8').rstrip('\r')


def _get_message(message_type, message):
    if message_type == '1':
        data = message.encode('utf-8')
    elif message_type == '2':
        with open(message or DEFAULT_JSON_FILE, 'rb') as source:
            data = source.read(MAX_MESSAGE_SIZE + 1)
    else:
        raise ValueError('Invalid message type')
    if len(data) > MAX_MESSAGE_SIZE:
        raise ValueError('Message exceeds size limit')
    return data


def message_exchange(crypto, network, *, test_mode=False, message_type=None, message=None, expect_echo=False):
    while True:
        kind = message_type if test_mode else timed_input('Text (1), file (2), or exit (3): ').strip()
        if kind == '3':
            break
        content = message if test_mode else timed_input('Message or file path: ')
        data = _get_message(kind, content)
        network.send_application_data(crypto, data)
        response = network.receive_application_data(crypto)
        expected = data if expect_echo else b'Message received successfully'
        if response != expected:
            raise ValueError('Unexpected server response')
        network.logger.info('Verified response for %d-byte message', len(data))
        if test_mode:
            break
    network.end_session()
    if network.receive_application_data(crypto) is not None:
        raise ValueError('Expected authenticated server closure')


def main(argv=None):
    parser = argparse.ArgumentParser(description='QTL2 prototype client (not TLS)')
    parser.add_argument('--ip', default=DEFAULT_IP)
    parser.add_argument('--port', type=int, default=DEFAULT_PORT)
    parser.add_argument('--server-name', help='Expected exact DNS/IP SAN; defaults to --ip')
    parser.add_argument('--cert-dir', type=Path, default=DEFAULT_CERT_DIR)
    parser.add_argument('--log-dir', type=Path, default=Path('logs'))
    parser.add_argument('--cipher', type=int, choices=range(1, 8), action='append', help='Explicit allowed suite; repeat to offer several (default: 6)')
    parser.add_argument('--mutual-auth', choices=['enable', 'disable'], default='disable')
    parser.add_argument('--handshake-timeout', type=float, default=HANDSHAKE_TIMEOUT)
    parser.add_argument('--message-timeout', type=float, default=MESSAGE_TIMEOUT)
    parser.add_argument('--test-mode', action='store_true')
    parser.add_argument('--message-type', choices=['1', '2', '3'])
    parser.add_argument('--message', default='')
    parser.add_argument('--expect-echo', action='store_true')
    args = parser.parse_args(argv)
    if args.test_mode and args.message_type is None:
        parser.error('--test-mode requires --message-type')
    logger = setup_logging('qtl.client', str(args.log_dir / 'client.log'))
    network = crypto = None
    try:
        network = ClientNetwork(args.ip, args.port, logger, server_name=args.server_name,
                                handshake_timeout=args.handshake_timeout, message_timeout=args.message_timeout)
        crypto = ClientCrypto(logger, network, cert_dir=args.cert_dir)
        crypto.offered_suites = [CIPHER_SUITES[i - 1] for i in (args.cipher or [DEFAULT_CIPHER])]
        network.crypto = crypto
        network.connect()
        client_server_handshake(crypto, network, args.mutual_auth == 'enable')
        message_exchange(crypto, network, test_mode=args.test_mode, message_type=args.message_type,
                         message=args.message, expect_echo=args.expect_echo)
        return 0
    except (OSError, TLSError, ValueError, EOFError) as exc:
        logger.error('Client failed: %s', exc)
        if network is not None and isinstance(exc, TLSError):
            try:
                network.send_alert(exc.alert_type)
            except (OSError, TLSError):
                pass
        return 1
    finally:
        if network is not None:
            network.close()
        if crypto is not None:
            crypto.clear_sensitive_data()
        close_logging(logger)


if __name__ == '__main__':
    raise SystemExit(main())
