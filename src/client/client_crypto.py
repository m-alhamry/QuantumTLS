"""Client key establishment for explicitly offered QTL2 suites."""
from cryptography.hazmat.primitives.asymmetric import ec
from src.utils.crypto import TLSCrypto, generate_kyber_keys
from src.utils.errors import TLSError
from src.utils.utils import (ALERT_ILLEGAL_PARAMETER, ALERT_INTERNAL_ERROR,
                             CIPHER_SUITES, DEFAULT_CIPHER, KYBER_VARIANTS, vector)


class ClientCrypto(TLSCrypto):
    def __init__(self, logger, network=None, **kwargs):
        super().__init__(logger, network, role='client', **kwargs)
        self.kyber_kems = {}
        self.kyber_pks = {}
        self.offered_suites = [CIPHER_SUITES[DEFAULT_CIPHER - 1]]

    def release_kems(self):
        for variant in list(self.kyber_kems):
            self.kyber_kems.pop(variant).free()
        self.kyber_pks.clear()

    def generate_keys(self, suites=None):
        if suites is not None:
            self.offered_suites = list(suites)
        if not self.offered_suites or len(set(self.offered_suites)) != len(self.offered_suites) or any(s not in CIPHER_SUITES for s in self.offered_suites):
            raise TLSError('Invalid offered suites', ALERT_ILLEGAL_PARAMETER)
        self.release_kems()
        try:
            self.generate_ecc_keys()
            for suite in self.offered_suites:
                variant = KYBER_VARIANTS.get(suite)
                if variant is not None:
                    kem, public = generate_kyber_keys(variant, self.logger)
                    self.kyber_kems[variant] = kem
                    self.kyber_pks[variant] = public
        except Exception:
            self.release_kems()
            raise

    def decapsulate_kyber(self, ciphertext):
        variant = KYBER_VARIANTS.get(self.cipher_suite)
        if variant not in self.kyber_kems or len(ciphertext) != self.get_expected_kyber_ct_size(self.cipher_suite):
            raise TLSError('Invalid KEM ciphertext', ALERT_ILLEGAL_PARAMETER)
        try:
            return self.kyber_kems[variant].decap_secret(ciphertext)
        except Exception as exc:
            raise TLSError('KEM decapsulation failed', ALERT_INTERNAL_ERROR) from exc

    def derive_handshake_keys(self, server_hello, use_hybrid):
        try:
            public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), server_hello['ecc_pk'])
            ecc = self.ecc_private_key.exchange(ec.ECDH(), public)
            kem = self.decapsulate_kyber(server_hello['kyber_ct']) if use_hybrid else b''
            super().derive_handshake_keys(vector(ecc) + vector(kem))
        except TLSError:
            raise
        except ValueError as exc:
            raise TLSError('Invalid server key share', ALERT_ILLEGAL_PARAMETER) from exc
        finally:
            self.release_kems()

    def clear_sensitive_data(self):
        self.release_kems()
        super().clear_sensitive_data()
