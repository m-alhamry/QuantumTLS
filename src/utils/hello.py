"""Strict QTL2 hello encodings; no TLS compatibility or implicit negotiation."""
import os
from cryptography.hazmat.primitives.asymmetric import ec
from src.utils.errors import TLSError
from src.utils.utils import (
    ALERT_DECODE_ERROR, CIPHER_SUITE_CODES, CIPHER_SUITE_NAMES, GROUP_SECP384R1,
    KYBER_CT_SIZES, KYBER_GROUPS, KYBER_PK_SIZES, KYBER_VARIANTS, PROTOCOL_VERSION, Reader, vector,
)


def encode_shares(shares):
    return vector(b''.join(group.to_bytes(2, 'big') + vector(key) for group, key in shares.items()))


def read_shares(reader, expected):
    nested = Reader(reader.vector())
    shares = {}
    while nested.pos < len(nested.data):
        group, key = nested.uint(2), nested.vector()
        if group in shares or group not in expected or len(key) != expected[group]:
            raise ValueError('Invalid, duplicate, or unexpected key share')
        shares[group] = key
    if shares.keys() != expected.keys():
        raise ValueError('Missing key share')
    ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), shares[GROUP_SECP384R1])
    return shares


def encode_client_hello(crypto):
    shares = {GROUP_SECP384R1: crypto.ecc_public_key_bytes}
    shares.update({KYBER_GROUPS[s]: crypto.kyber_pks[KYBER_VARIANTS[s]]
                   for s in crypto.offered_suites if s in KYBER_VARIANTS})
    return PROTOCOL_VERSION + os.urandom(32) + vector(b''.join(CIPHER_SUITE_CODES[s] for s in crypto.offered_suites)) + encode_shares(shares)


def parse_client_hello(body):
    try:
        reader = Reader(body)
        if reader.take(2) != PROTOCOL_VERSION:
            raise ValueError('Unsupported protocol version')
        random = reader.take(32)
        codes = reader.vector()
        suites = [CIPHER_SUITE_NAMES[codes[i:i + 2]] for i in range(0, len(codes), 2)]
        if not suites or len(suites) != len(set(suites)):
            raise ValueError('Empty or duplicate cipher suites')
        expected = {GROUP_SECP384R1: 97}
        expected.update({KYBER_GROUPS[s]: KYBER_PK_SIZES[s] for s in suites if s in KYBER_VARIANTS})
        shares = read_shares(reader, expected)
        reader.finish()
        return {'random': random, 'cipher_suites': codes, 'key_shares': shares, 'ecc_pk': shares[GROUP_SECP384R1]}
    except (ValueError, KeyError) as exc:
        raise TLSError('Malformed ClientHello', ALERT_DECODE_ERROR) from exc


def encode_server_hello(crypto, ciphertext):
    shares = {GROUP_SECP384R1: crypto.ecc_public_key_bytes}
    if crypto.cipher_suite in KYBER_VARIANTS:
        shares[KYBER_GROUPS[crypto.cipher_suite]] = ciphertext
    return PROTOCOL_VERSION + os.urandom(32) + CIPHER_SUITE_CODES[crypto.cipher_suite] + encode_shares(shares)


def parse_server_hello(body, offered_suites):
    try:
        reader = Reader(body)
        if reader.take(2) != PROTOCOL_VERSION:
            raise ValueError('Unsupported protocol version')
        random, suite = reader.take(32), CIPHER_SUITE_NAMES[reader.take(2)]
        if suite not in offered_suites:
            raise ValueError('Server selected unoffered suite')
        expected = {GROUP_SECP384R1: 97}
        if suite in KYBER_VARIANTS:
            expected[KYBER_GROUPS[suite]] = KYBER_CT_SIZES[suite]
        shares = read_shares(reader, expected)
        reader.finish()
        return {'random': random, 'cipher_suite': suite, 'ecc_pk': shares[GROUP_SECP384R1],
                'kyber_ct': shares.get(KYBER_GROUPS.get(suite))}
    except (ValueError, KeyError) as exc:
        raise TLSError('Malformed ServerHello', ALERT_DECODE_ERROR) from exc
