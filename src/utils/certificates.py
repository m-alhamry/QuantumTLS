"""Strict direct-CA certificate profile and non-overwriting development issuance."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from src.utils.errors import TLSError
from src.utils.utils import ALERT_BAD_CERTIFICATE, ALERT_CERTIFICATE_EXPIRED, DEFAULT_CERT_DIR

COMPROMISED_CA_KEYS = frozenset(json.loads(Path(__file__).with_name('compromised_ca_keys.json').read_text()))
SUPPORTED_EXTENSIONS = (x509.BasicConstraints, x509.KeyUsage, x509.ExtendedKeyUsage,
                        x509.SubjectAlternativeName, x509.SubjectKeyIdentifier,
                        x509.AuthorityKeyIdentifier)


def public_key_fingerprint(key):
    return hashlib.sha256(key.public_bytes(serialization.Encoding.DER,
                         serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def _profile(cert):
    now = datetime.now(timezone.utc)
    if now < cert.not_valid_before_utc:
        raise TLSError('Certificate not yet valid', ALERT_BAD_CERTIFICATE)
    if now > cert.not_valid_after_utc:
        raise TLSError('Certificate expired', ALERT_CERTIFICATE_EXPIRED)
    key = cert.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP384R1):
        raise ValueError('Certificate requires a P-384 key')
    if not isinstance(cert.signature_hash_algorithm, hashes.SHA384):
        raise ValueError('Certificate requires an ECDSA/SHA384 signature')
    for ext in cert.extensions:
        if ext.critical and not isinstance(ext.value, SUPPORTED_EXTENSIONS):
            raise ValueError('Unsupported critical certificate extension')


def validate_ca(cert):
    try:
        _profile(cert)
        if public_key_fingerprint(cert.public_key()) in COMPROMISED_CA_KEYS:
            raise ValueError('CA key exposed in project history; replace the trust root')
        # CA policy constraints are deliberately unsupported, even when noncritical.
        for ext in cert.extensions:
            if isinstance(ext.value, (x509.ExtendedKeyUsage, x509.NameConstraints, x509.PolicyConstraints,
                                      x509.InhibitAnyPolicy, x509.CertificatePolicies)):
                raise ValueError('Constrained roots are outside the direct-CA profile')
        if cert.subject != cert.issuer:
            raise ValueError('Only a self-signed direct trust root is supported')
        if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError('Trust root is not a CA')
        if not cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign:
            raise ValueError('CA cannot sign certificates')
        cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA384()))
    except TLSError:
        raise
    except Exception as exc:
        raise TLSError(f'Invalid trust root: {exc}', ALERT_BAD_CERTIFICATE) from exc


def validate_certificate(cert, ca, role, expected_name=None):
    try:
        validate_ca(ca)
        _profile(cert)
        if role not in ('server', 'client'):
            raise ValueError('Unknown certificate role')
        if cert.issuer != ca.subject:
            raise ValueError('Unexpected certificate issuer')
        ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA384()))
        if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError('CA certificate cannot act as an endpoint')
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        if not usage.digital_signature or usage.key_cert_sign:
            raise ValueError('Invalid endpoint key usage')
        purpose = ExtendedKeyUsageOID.SERVER_AUTH if role == 'server' else ExtendedKeyUsageOID.CLIENT_AUTH
        if purpose not in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
            raise ValueError(f'Certificate not permitted for {role} authentication')
        if role == 'server' and expected_name is not None:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            try:
                address = ipaddress.ip_address(expected_name)
            except ValueError:
                name = expected_name.encode('idna').decode('ascii').lower().rstrip('.')
                names = [n.lower().rstrip('.') for n in san.get_values_for_type(x509.DNSName)]
                if name not in names:
                    raise ValueError('Server DNS identity mismatch (exact SAN required)')
            else:
                if address not in san.get_values_for_type(x509.IPAddress):
                    raise ValueError('Server IP identity mismatch')
    except TLSError:
        raise
    except Exception as exc:
        raise TLSError(f'Invalid {role} certificate: {exc}', ALERT_BAD_CERTIFICATE) from exc


def _write_pair(directory, name, key, cert):
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    targets = [(directory / (name + '.key'), key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())),
        (directory / (name + '.crt'), cert.public_bytes(serialization.Encoding.PEM))]
    if any(path.exists() or path.is_symlink() for path, _ in targets):
        raise FileExistsError(f'Refusing to overwrite {name} credentials')
    created = []
    try:
        for path, data in targets:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created.append(path)
            with os.fdopen(fd, 'wb') as output:
                output.write(data)
    except BaseException:
        for path in created:
            path.unlink(missing_ok=True)
        raise


def generate_ca(directory=DEFAULT_CERT_DIR):
    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'QTL2 Development CA')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .sign(key, hashes.SHA384()))
    _write_pair(directory, 'ca', key, cert)
    return cert


def generate_leaf(directory=DEFAULT_CERT_DIR, role='server', *, expired=False, dns_names=None, ip_addresses=None):
    directory = Path(directory)
    ca = x509.load_pem_x509_certificate((directory / 'ca.crt').read_bytes())
    validate_ca(ca)
    ca_key = serialization.load_pem_private_key((directory / 'ca.key').read_bytes(), password=None)
    if ca_key.public_key().public_numbers() != ca.public_key().public_numbers():
        raise ValueError('CA private key does not match its certificate')
    if role not in ('client', 'server'):
        raise ValueError('Unknown role')
    key = ec.generate_private_key(ec.SECP384R1())
    now = datetime.now(timezone.utc)
    purpose = ExtendedKeyUsageOID.SERVER_AUTH if role == 'server' else ExtendedKeyUsageOID.CLIENT_AUTH
    builder = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'QTL2 ' + role)]))
               .issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(days=2) if expired else now - timedelta(minutes=1))
               .not_valid_after(now - timedelta(days=1) if expired else now + timedelta(days=365))
               .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
               .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
               .add_extension(x509.ExtendedKeyUsage([purpose]), critical=True))
    if role == 'server':
        names = [x509.DNSName(n.encode('idna').decode('ascii')) for n in (dns_names if dns_names is not None else ['localhost'])]
        names += [x509.IPAddress(ipaddress.ip_address(n)) for n in (ip_addresses if ip_addresses is not None else ['127.0.0.1', '::1'])]
        if not names:
            raise ValueError('At least one server SAN is required')
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    cert = builder.sign(ca_key, hashes.SHA384())
    _write_pair(directory, ('expired_' if expired else '') + role, key, cert)
    return cert


def certificate_cli(role, expired=False):
    parser = argparse.ArgumentParser(description='Generate new QTL2 development credentials; never overwrites files')
    parser.add_argument('--directory', type=Path, default=DEFAULT_CERT_DIR)
    if role == 'server':
        parser.add_argument('--dns', action='append', help='Exact DNS SAN; repeat for multiple names')
        parser.add_argument('--ip', action='append', help='IP SAN; repeat for multiple addresses')
    args = parser.parse_args()
    try:
        if role == 'ca':
            generate_ca(args.directory)
        else:
            generate_leaf(args.directory, role, expired=expired,
                          dns_names=getattr(args, 'dns', None), ip_addresses=getattr(args, 'ip', None))
    except (OSError, ValueError, TLSError) as exc:
        parser.exit(1, f'Credential generation failed: {exc}\n')
    print(f'Generated {role} credentials in {args.directory}')
