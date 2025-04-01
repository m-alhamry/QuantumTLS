from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import datetime

"""run this scripts only once to generate server certificate"""
# Load CA certificate and private key
with open("ca.crt", "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())
with open("ca.key", "rb") as f:
    ca_private_key = serialization.load_pem_private_key(f.read(), password=None)

# Generate ECC private key for the server
server_private_key = ec.generate_private_key(ec.SECP384R1())
server_public_key = server_private_key.public_key()

# Define server subject
server_subject = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
])

# Create server certificate signed by CA
server_cert = (
    x509.CertificateBuilder()
    .subject_name(server_subject)
    .issuer_name(ca_cert.subject)  # CA as issuer
    .public_key(server_public_key)
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
    .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
    .sign(ca_private_key, hashes.SHA384())
)

# Save server certificate and private key
with open("server.crt", "wb") as f:
    f.write(server_cert.public_bytes(serialization.Encoding.PEM))
with open("server.key", "wb") as f:
    f.write(server_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

print("Generated server.crt and server.key signed by CA")