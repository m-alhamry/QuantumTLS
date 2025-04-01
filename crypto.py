# Imports modules for timing and logging
import time
import logging
from typing import Tuple

# Imports cryptographic primitives for ECC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Imports Open Quantum Safe library for Kyber
import oqs

def generate_ecc_keys(logger: logging.Logger) -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey, bytes]:
    """
    Generate an ECC key pair using the SECP384R1 curve.

    Args:
        logger: Logger for performance and debug information.

    Returns:
        Tuple containing private key, public key, and serialized public key bytes.
    """
    start = time.perf_counter()
    # Generate ECC private key
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    # Serialize public key in uncompressed X962 format
    public_key_bytes = public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    duration = time.perf_counter() - start
    logger.debug(f"ECC key generation took {duration:.6f} seconds")
    return private_key, public_key, public_key_bytes

def generate_kyber_keys(variant: int | None, logger: logging.Logger) -> Tuple[oqs.KeyEncapsulation, bytes]:
    """
    Generate a Kyber key pair for post-quantum key exchange.

    Args:
        variant: Kyber variant (1=Kyber512, 2=Kyber768, 3=Kyber1024) or None for default (Kyber768).
        logger: Logger for performance and debug information.

    Returns:
        Tuple containing Kyber KEM instance and public key bytes.
    """
    start = time.perf_counter()
    # Map variant to Kyber algorithm
    kem_map = {1: "Kyber512", 2: "Kyber768", 3: "Kyber1024"}
    kem_alg = kem_map.get(variant, "Kyber768")
    # Initialize Kyber KEM
    kem = oqs.KeyEncapsulation(kem_alg)
    # Generate key pair
    public_key = kem.generate_keypair()
    duration = time.perf_counter() - start
    logger.debug(f"Kyber key generation ({kem_alg}) took {duration:.6f} seconds")
    return kem, public_key

def encapsulate_kyber(kem: oqs.KeyEncapsulation, public_key: bytes, logger: logging.Logger) -> Tuple[bytes, bytes]:
    """
    Encapsulate a Kyber shared secret using the recipient's public key.

    Args:
        kem: Kyber KEM instance.
        public_key: Recipient's Kyber public key.
        logger: Logger for performance and debug information.

    Returns:
        Tuple containing ciphertext and shared secret.
    """
    start = time.perf_counter()
    # Encapsulate shared secret
    ciphertext, shared_secret = kem.encap_secret(public_key)
    duration = time.perf_counter() - start
    logger.debug(f"Kyber encapsulation took {duration:.6f} seconds")
    return ciphertext, shared_secret