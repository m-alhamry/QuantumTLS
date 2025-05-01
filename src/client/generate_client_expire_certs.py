from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import datetime

"""run this scripts only once to generate client certificate"""
# Load CA certificate and private key
with open("src/ca.crt", "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())
with open("src/ca.key", "rb") as f:
    ca_private_key = serialization.load_pem_private_key(f.read(), password=None)

# Generate ECC private key for the client
client_private_key = ec.generate_private_key(ec.SECP384R1())
client_public_key = client_private_key.public_key()

# Define client subject
client_subject = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
])

# Create client certificate signed by CA
client_cert = (
    x509.CertificateBuilder()
    .subject_name(client_subject)
    .issuer_name(ca_cert.subject)  # CA as issuer
    .public_key(client_public_key)
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=365))
    .not_valid_after(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
    .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
    .sign(ca_private_key, hashes.SHA384())
)

# Save client certificate and private key
with open("src/client/expired_client.crt", "wb") as f:
    f.write(client_cert.public_bytes(serialization.Encoding.PEM))
with open("src/client/expired_client.key", "wb") as f:
    f.write(client_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

print("Generated expired_client.crt and expired_client.key signed by CA")