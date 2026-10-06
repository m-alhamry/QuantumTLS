"""Ordered, transcript-authenticated QTL2 handshakes."""
from src.utils.crypto import encode_certificate, parse_and_validate_certificate, validate_and_verify_certificate_verify
from src.utils.errors import TLSError
from src.utils.hello import encode_client_hello, encode_server_hello, parse_client_hello, parse_server_hello
from src.utils.utils import (
    ALERT_CERTIFICATE_REQUIRED, ALERT_HANDSHAKE_FAILURE, ALERT_UNEXPECTED_MESSAGE,
    HANDSHAKE_TYPE_ACK, HANDSHAKE_TYPE_CERTIFICATE, HANDSHAKE_TYPE_CERTIFICATE_REQUEST,
    HANDSHAKE_TYPE_CERTIFICATE_VERIFY, HANDSHAKE_TYPE_CLIENT_HELLO,
    HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, HANDSHAKE_TYPE_FINISHED, HANDSHAKE_TYPE_SERVER_HELLO,
    KYBER_VARIANTS, SIGNATURE_ECDSA_SECP384R1_SHA384, vector,
)


def receive(network, expected, *, encrypted=True, empty=False, append=True):
    kind, body = network.receive_handshake_message(encrypted=encrypted)
    if kind != expected or (empty and body):
        raise TLSError('Unexpected handshake message', ALERT_UNEXPECTED_MESSAGE)
    if append:
        network.crypto.append_handshake(kind, body)
    return body


def send(network, kind, body=b''):
    network.send_encrypted_handshake_message(network.crypto, kind, body)


def send_identity(network):
    crypto = network.crypto
    if crypto.cert is None:
        crypto.load_identity()
    send(network, HANDSHAKE_TYPE_CERTIFICATE, encode_certificate(crypto.cert))
    send(network, HANDSHAKE_TYPE_CERTIFICATE_VERIFY,
         SIGNATURE_ECDSA_SECP384R1_SHA384 + vector(crypto.compute_certificate_verify()))


def receive_identity(network, role, certificate_body=None):
    crypto = network.crypto
    body = receive(network, HANDSHAKE_TYPE_CERTIFICATE, append=False) if certificate_body is None else certificate_body
    cert = parse_and_validate_certificate(body, network, role)
    crypto.append_handshake(HANDSHAKE_TYPE_CERTIFICATE, body)
    body = receive(network, HANDSHAKE_TYPE_CERTIFICATE_VERIFY, append=False)
    validate_and_verify_certificate_verify(body, cert, network, crypto, network.logger)
    crypto.append_handshake(HANDSHAKE_TYPE_CERTIFICATE_VERIFY, body)


def receive_finished(network, kind=HANDSHAKE_TYPE_FINISHED):
    body = receive(network, kind, append=False)
    if not network.crypto.verify_finished_message(body):
        raise TLSError('Finished verification failed', ALERT_HANDSHAKE_FAILURE)
    network.crypto.append_handshake(kind, body)


def client_handshake(crypto, network, mutual_auth=False):
    network.crypto = crypto
    with network.deadline(network.handshake_timeout):
        crypto.generate_keys()
        network.send_handshake_message(HANDSHAKE_TYPE_CLIENT_HELLO, encode_client_hello(crypto))
        hello = parse_server_hello(receive(network, HANDSHAKE_TYPE_SERVER_HELLO, encrypted=False), crypto.offered_suites)
        crypto.cipher_suite = hello['cipher_suite']
        crypto.derive_handshake_keys(hello, crypto.cipher_suite in KYBER_VARIANTS)
        crypto.activate_handshake_keys()
        receive(network, HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, empty=True)
        kind, body = network.receive_handshake_message(encrypted=True)
        requested = kind == HANDSHAKE_TYPE_CERTIFICATE_REQUEST
        if requested:
            if body:
                raise TLSError('Nonempty CertificateRequest', ALERT_UNEXPECTED_MESSAGE)
            crypto.append_handshake(kind, body)
            kind, body = network.receive_handshake_message(encrypted=True)
        if kind != HANDSHAKE_TYPE_CERTIFICATE:
            raise TLSError('Expected server certificate', ALERT_UNEXPECTED_MESSAGE)
        receive_identity(network, 'Server', body)
        receive_finished(network)
        crypto.application_transcript = bytes(crypto.handshake_transcript)
        if requested != mutual_auth:
            raise TLSError('Client and server mutual-auth policies differ', ALERT_CERTIFICATE_REQUIRED)
        if requested:
            send_identity(network)
        send(network, HANDSHAKE_TYPE_FINISHED, crypto.compute_finished_message())
        # Explicit server acceptance eliminates the old timing-based mTLS race.
        receive_finished(network, HANDSHAKE_TYPE_ACK)
        crypto.derive_application_key()
    network.logger.info('Handshake completed: %s; mutual authentication=%s', crypto.cipher_suite, mutual_auth)


def server_handshake(crypto, network, mutual_auth=False, preferred_cipher_suite=None):
    network.crypto = crypto
    with network.deadline(network.handshake_timeout):
        hello = parse_client_hello(receive(network, HANDSHAKE_TYPE_CLIENT_HELLO, encrypted=False))
        hybrid, variant, _ = crypto.select_cipher_suite(hello, preferred_cipher_suite)
        ciphertext = crypto.generate_derive_handshake_keys(hello, hybrid, variant)
        network.send_handshake_message(HANDSHAKE_TYPE_SERVER_HELLO, encode_server_hello(crypto, ciphertext))
        crypto.activate_handshake_keys()
        send(network, HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS)
        if mutual_auth:
            send(network, HANDSHAKE_TYPE_CERTIFICATE_REQUEST)
        send_identity(network)
        send(network, HANDSHAKE_TYPE_FINISHED, crypto.compute_finished_message())
        crypto.application_transcript = bytes(crypto.handshake_transcript)
        if mutual_auth:
            receive_identity(network, 'Client')
        receive_finished(network)
        send(network, HANDSHAKE_TYPE_ACK, crypto.compute_finished_message())
        crypto.derive_application_key()
    network.logger.info('Handshake completed: %s; mutual authentication=%s', crypto.cipher_suite, mutual_auth)
