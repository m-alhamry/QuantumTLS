from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, ObjectIdentifier
from src.client.client_crypto import ClientCrypto
from src.utils.certificates import generate_ca, generate_leaf, public_key_fingerprint, validate_ca, validate_certificate
from src.utils.crypto import encode_certificate, parse_and_validate_certificate
from src.utils.errors import TLSError
from src.client.client_network import ClientNetwork
from tests.support import CredentialsTest, LOGGER


class TestCertificates(CredentialsTest):
    def altered(self, cert=None, *, replace=None, omit=(), extra=(), before=None, after=None, issuer_key=None):
        cert = cert or self.server_cert
        builder = (x509.CertificateBuilder().subject_name(cert.subject).issuer_name(cert.issuer)
                   .public_key(cert.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(before or cert.not_valid_before_utc)
                   .not_valid_after(after or cert.not_valid_after_utc))
        for ext in cert.extensions:
            if ext.oid not in omit:
                builder = builder.add_extension((replace or {}).get(ext.oid, ext.value), ext.critical)
        for value in extra:
            builder = builder.add_extension(value, True)
        ca_key = issuer_key or serialization.load_pem_private_key((self.directory / 'ca.key').read_bytes(), None)
        return builder.sign(ca_key, hashes.SHA384())

    def test_valid_roles_dns_and_ip(self):
        for name in ('localhost', 'LOCALHOST.', '127.0.0.1', '::1'):
            validate_certificate(self.server_cert, self.ca, 'server', name)
        validate_certificate(self.client_cert, self.ca, 'client')

    def test_wrong_identity_and_client_only_server_certificate(self):
        for cert, name in ((self.server_cert, 'other.example'), (self.server_cert, '127.0.0.2'), (self.client_cert, 'localhost')):
            with self.assertRaises(TLSError):
                validate_certificate(cert, self.ca, 'server', name)
        with self.assertRaises(TLSError):
            validate_certificate(self.server_cert, self.ca, 'client')

    def test_expired_and_future_certificates(self):
        now = datetime.now(timezone.utc)
        expired = generate_leaf(self.directory, 'client', expired=True)
        future = self.altered(before=now + timedelta(days=1), after=now + timedelta(days=2))
        for cert, role in ((expired, 'client'), (future, 'server')):
            with self.assertRaises(TLSError):
                validate_certificate(cert, self.ca, role)

    def test_missing_and_invalid_constraints(self):
        for cls in (x509.BasicConstraints, x509.KeyUsage, x509.ExtendedKeyUsage, x509.SubjectAlternativeName):
            oid = self.server_cert.extensions.get_extension_for_class(cls).oid
            cert = self.altered(omit=(oid,))
            with self.assertRaises(TLSError):
                validate_certificate(cert, self.ca, 'server', 'localhost')
        for value in (x509.BasicConstraints(True, 0),
                      x509.KeyUsage(False, False, False, False, False, False, False, False, False),
                      x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])):
            oid = self.server_cert.extensions.get_extension_for_class(type(value)).oid
            with self.assertRaises(TLSError):
                validate_certificate(self.altered(replace={oid: value}), self.ca, 'server', 'localhost')

    def test_unknown_critical_and_wrong_signer(self):
        unknown = x509.UnrecognizedExtension(ObjectIdentifier('1.2.3.4.5'), b'\x05\x00')
        for cert in (self.altered(extra=[unknown]), self.altered(issuer_key=ec.generate_private_key(ec.SECP384R1()))):
            with self.assertRaises(TLSError):
                validate_certificate(cert, self.ca, 'server', 'localhost')

    def test_bad_ca_and_unsupported_ca_constraints(self):
        with self.assertRaises(TLSError):
            validate_ca(self.client_cert)
        cert = self.altered(self.ca, extra=[x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])])
        with self.assertRaises(TLSError):
            validate_ca(cert)

    def test_compromised_key_denylist(self):
        fingerprint = public_key_fingerprint(self.ca.public_key())
        with patch('src.utils.certificates.COMPROMISED_CA_KEYS', {fingerprint}), self.assertRaises(TLSError):
            validate_ca(self.ca)
        from src.utils.certificates import COMPROMISED_CA_KEYS
        self.assertEqual(len(COMPROMISED_CA_KEYS), 6)
        self.assertTrue(all(len(value) == 64 for value in COMPROMISED_CA_KEYS))

    def test_key_mismatch_rejected(self):
        client = ClientCrypto(LOGGER, cert_dir=self.directory)
        self.addCleanup(client.clear_sensitive_data)
        with self.assertRaises(TLSError):
            client.load_certificate(self.directory / 'client.crt', self.directory / 'server.key')
        self.assertIsNone(client.cert_private_key)

    def test_generation_never_overwrites_and_private_modes(self):
        original = {p.name: p.read_bytes() for p in self.directory.iterdir()}
        for action in (lambda: generate_ca(self.directory), lambda: generate_leaf(self.directory, 'server')):
            with self.assertRaises(FileExistsError):
                action()
        self.assertEqual(original, {p.name: p.read_bytes() for p in self.directory.iterdir()})
        for name in ('ca.key', 'client.key', 'server.key'):
            self.assertEqual((self.directory / name).stat().st_mode & 0o777, 0o600)

    def test_certificate_message_strict_encoding(self):
        network = ClientNetwork('localhost', 0, LOGGER)
        network.crypto = ClientCrypto(LOGGER, cert_dir=self.directory)
        self.addCleanup(network.crypto.clear_sensitive_data)
        body = encode_certificate(self.server_cert)
        self.assertEqual(parse_and_validate_certificate(body, network, 'Server'), self.server_cert.public_bytes(serialization.Encoding.DER))
        for invalid in (body + b'extra', body[:-1], b'\x00\x00\x00\x00', b'\x01x' + body[1:]):
            with self.assertRaises(TLSError):
                parse_and_validate_certificate(invalid, network, 'Server')
