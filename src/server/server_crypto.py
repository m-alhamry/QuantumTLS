"""Server key establishment with an enforced suite policy; no implicit fallback."""
from cryptography.hazmat.primitives.asymmetric import ec
from src.utils.crypto import TLSCrypto, create_kem
from src.utils.errors import TLSError
from src.utils.utils import (ALERT_HANDSHAKE_FAILURE, ALERT_ILLEGAL_PARAMETER,
                             CIPHER_SUITE_CODES, CIPHER_SUITE_NAMES, GROUP_SECP384R1,
                             KYBER_GROUPS, KYBER_VARIANTS, vector)


class ServerCrypto(TLSCrypto):
    def __init__(self, logger, network=None, **kwargs):
        super().__init__(logger, network, role='server', **kwargs)
        self.kyber_kem = None

    def generate_keys(self, use_hybrid, kyber_variant):
        self.release_kem()
        self.generate_ecc_keys()
        if use_hybrid:
            self.kyber_kem = create_kem(kyber_variant)  # Encapsulation needs no server keypair.

    def release_kem(self):
        if self.kyber_kem is not None:
            kem, self.kyber_kem = self.kyber_kem, None
            kem.free()

    def encapsulate_kyber(self, public):
        if len(public) != self.get_expected_kyber_pk_size(self.cipher_suite):
            raise TLSError('Invalid client KEM public key length', ALERT_ILLEGAL_PARAMETER)
        try:
            return self.kyber_kem.encap_secret(public)
        except Exception as exc:
            raise TLSError('Invalid client KEM public key', ALERT_ILLEGAL_PARAMETER) from exc

    def derive_handshake_keys(self, client_hello, use_hybrid, kyber_ss):
        if use_hybrid and (kyber_ss is None or len(kyber_ss) != 32):
            raise TLSError('Missing KEM shared secret for hybrid exchange', ALERT_HANDSHAKE_FAILURE)
        try:
            public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), client_hello['ecc_pk'])
            ecc = self.ecc_private_key.exchange(ec.ECDH(), public)
            super().derive_handshake_keys(vector(ecc) + vector(kyber_ss if use_hybrid else b''))
        except ValueError as exc:
            raise TLSError('Invalid client ECC key share', ALERT_ILLEGAL_PARAMETER) from exc

    def select_cipher_suite(self, client_hello, preferred_cipher_suite):
        offered = client_hello['cipher_suites']
        preferred = CIPHER_SUITE_CODES.get(preferred_cipher_suite)
        if preferred is None or len(offered) % 2 or preferred not in [offered[i:i + 2] for i in range(0, len(offered), 2)]:
            raise TLSError('Client does not offer the required cipher suite', ALERT_HANDSHAKE_FAILURE)
        self.cipher_suite = CIPHER_SUITE_NAMES[preferred]
        variant = KYBER_VARIANTS.get(self.cipher_suite)
        return variant is not None, variant, preferred

    def generate_derive_handshake_keys(self, client_hello, use_hybrid, kyber_variant):
        shares = client_hello['key_shares']
        if GROUP_SECP384R1 not in shares:
            raise TLSError('Missing ECC key share', ALERT_HANDSHAKE_FAILURE)
        ciphertext = secret = None
        try:
            self.generate_keys(use_hybrid, kyber_variant)
            if use_hybrid:
                group = KYBER_GROUPS[self.cipher_suite]
                if group not in shares:
                    raise TLSError('Missing KEM key share', ALERT_HANDSHAKE_FAILURE)
                ciphertext, secret = self.encapsulate_kyber(shares[group])
            self.derive_handshake_keys({'ecc_pk': shares[GROUP_SECP384R1]}, use_hybrid, secret)
            return ciphertext
        finally:
            self.release_kem()

    def clear_sensitive_data(self):
        self.release_kem()
        super().clear_sensitive_data()
