from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate

with open("client.key", "rb") as f:
    private_key = load_pem_private_key(f.read(), password=None)
with open("client.crt", "rb") as f:
    cert = load_pem_x509_certificate(f.read())

public_key_from_private = private_key.public_key()
cert_public_key = cert.public_key()

assert public_key_from_private.public_numbers() == cert_public_key.public_numbers(), "Key and certificate do not match"
print("Key and certificate match successfully.")