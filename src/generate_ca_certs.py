from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import datetime

"""run this scripts only once to generate CA certificate"""
# Generate ECC private key for the CA
ca_private_key = ec.generate_private_key(ec.SECP384R1())
ca_public_key = ca_private_key.public_key()

# Define CA subject
ca_subject = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "My Test CA"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organization"),
])

# Create CA certificate
ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_subject)
    .issuer_name(ca_subject)  # Self-signed
    .public_key(ca_public_key)
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))  # 10 years
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    )
    .add_extension(
        x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False
        ),
        critical=True
    )
    .sign(ca_private_key, hashes.SHA384())
)

# Save CA certificate and private key
with open("src/ca.crt", "wb") as f:
    f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
with open("src/ca.key", "wb") as f:
    f.write(ca_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

print("Generated ca.crt and ca.key")