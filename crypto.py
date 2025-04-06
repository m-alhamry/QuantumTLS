import time
import logging
from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import oqs

from errors import TLSError
from utils import ALERT_ILLEGAL_PARAMETER, ALERT_INTERNAL_ERROR

def generate_ecc_keys(logger: logging.Logger) -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey, bytes]:
    """
    Generate an ECC key pair using the SECP384R1 curve.

    Args:
        logger (logging.Logger): Logger for performance and debug information.

    Returns:
        Tuple containing private key, public key, and serialized public key bytes.

    Raises:
        TLSError: If ECC key generation fails.
    """
    start = time.perf_counter()
    try:
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()
        public_key_bytes = public_key.public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
    except Exception as e:
        raise TLSError(f"ECC key generation failed: {e}", ALERT_INTERNAL_ERROR, logger)

    duration = time.perf_counter() - start
    logger.debug(f"Generated ECC keys in {duration:.6f} seconds")
    return private_key, public_key, public_key_bytes

def generate_kyber_keys(variant: int | None, logger: logging.Logger) -> Tuple[oqs.KeyEncapsulation, bytes]:
    """
    Generate a Kyber key pair for post-quantum key exchange.

    Args:
        variant (int | None): Kyber variant (1=Kyber512, 2=Kyber768, 3=Kyber1024) or None for default (Kyber768).
        logger (logging.Logger): Logger for performance and debug information.

    Returns:
        Tuple containing Kyber KEM instance and public key bytes.

    Raises:
        TLSError: If Kyber variant is invalid or key generation fails.
    """
    start = time.perf_counter()
    kem_map = {1: "Kyber512", 2: "Kyber768", 3: "Kyber1024"}
    if variant not in kem_map and variant is not None:
        raise TLSError(f"Invalid Kyber variant: {variant}", ALERT_ILLEGAL_PARAMETER, logger)

    kem_alg = kem_map.get(variant, "Kyber768")
    try:
        kem = oqs.KeyEncapsulation(kem_alg)
        public_key = kem.generate_keypair()
    except Exception as e:
        raise TLSError(f"Failed to generate {kem_alg} keypair: {e}", ALERT_INTERNAL_ERROR, logger)

    duration = time.perf_counter() - start
    logger.debug(f"Generated {kem_alg} keys in {duration:.6f} seconds")
    return kem, public_key

def encapsulate_kyber(kem: oqs.KeyEncapsulation, public_key: bytes, logger: logging.Logger) -> Tuple[bytes, bytes]:
    """
    Encapsulate a Kyber shared secret using the recipient's public key.

    Args:
        kem (oqs.KeyEncapsulation): Kyber KEM instance.
        public_key (bytes): Recipient's Kyber public key.
        logger (logging.Logger): Logger for performance and debug information.

    Returns:
        Tuple containing ciphertext and shared secret.

    Raises:
        TLSError: If Kyber encapsulation fails.
    """
    start = time.perf_counter()
    try:
        ciphertext, shared_secret = kem.encap_secret(public_key)
    except Exception as e:
        raise TLSError(f"Kyber encapsulation failed: {e}", ALERT_INTERNAL_ERROR, logger)

    duration = time.perf_counter() - start
    logger.debug(f"Encapsulated Kyber shared secret in {duration:.6f} seconds")
    return ciphertext, shared_secret