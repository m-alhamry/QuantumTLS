from unittest.mock import patch
from src.utils.crypto import TLSCrypto, generate_ecc_keys, generate_kyber_keys, get_hash
from src.utils.errors import TLSError
from src.utils.utils import MAX_RECORDS_PER_KEY
from tests.support import CredentialsTest, LOGGER


class TestCrypto(CredentialsTest):
    def test_ecc_key_generation(self):
        a, _, public = generate_ecc_keys(LOGGER)
        self.assertEqual(len(public), 97)
        self.assertEqual(a.curve.name, 'secp384r1')

    def test_all_kem_variants_round_trip(self):
        from src.utils.crypto import create_kem
        for variant in range(1, 7):
            with self.subTest(variant=variant):
                client, public = generate_kyber_keys(variant, LOGGER)
                server = create_kem(variant)
                try:
                    ciphertext, secret = server.encap_secret(public)
                    self.assertEqual(client.decap_secret(ciphertext), secret)
                finally:
                    client.free()
                    server.free()

    def test_invalid_kem(self):
        with self.assertRaises(TLSError):
            generate_kyber_keys(7, LOGGER)

    def test_directional_keys_and_reflection(self):
        client, server = self.crypto_pair()
        self.assertEqual(client.send_key, server.recv_key)
        self.assertEqual(server.send_key, client.recv_key)
        self.assertNotEqual(client.send_key, client.recv_key)
        seq, iv, ct = client.encrypt_message(b'secret', b'header')
        with self.assertRaises(TLSError):
            client.decrypt_message(seq, client.nonce(client.recv_iv, 0), ct, b'header')
        self.assertEqual(server.decrypt_message(seq, iv, ct, b'header'), b'secret')

    def test_replay_reorder_and_aad_tampering(self):
        client, server = self.crypto_pair()
        first = client.encrypt_message(b'first', b'header')
        second = client.encrypt_message(b'second', b'header')
        for record, aad in ((second, b'header'), (first, b'tampered')):
            with self.assertRaises(TLSError):
                server.decrypt_message(*record, aad)
            self.assertEqual(server.recv_seq, 0)
        self.assertEqual(server.decrypt_message(*first, b'header'), b'first')
        with self.assertRaises(TLSError):
            server.decrypt_message(*first, b'header')
        self.assertEqual(server.decrypt_message(*second, b'header'), b'second')

    def test_finished_is_keyed_role_and_transcript_bound(self):
        client, server = self.crypto_pair(False)
        finished = client.compute_finished_message()
        self.assertTrue(server.verify_finished_message(finished))
        self.assertFalse(client.verify_finished_message(finished))
        self.assertFalse(server.verify_finished_message(get_hash(server.handshake_transcript)))
        server.append_handshake(11, b'changed')
        self.assertFalse(server.verify_finished_message(finished))

    def test_traffic_keys_depend_on_transcript(self):
        client, _ = self.crypto_pair(False)
        from src.client.client_crypto import ClientCrypto
        other = ClientCrypto(LOGGER, cert_dir=self.directory)
        self.addCleanup(other.clear_sensitive_data)
        TLSCrypto.derive_handshake_keys(other, b'shared test secret')
        other.append_handshake(1, b'different hello')
        other.activate_handshake_keys()
        self.assertNotEqual(client.send_key, other.send_key)

    def test_nonce_key_epoch_and_limits(self):
        client, server = self.crypto_pair(False)
        old_key = client.send_key
        first = client.encrypt_message(b'a')
        second = client.encrypt_message(b'a')
        self.assertNotEqual(first[1], second[1])
        client.application_transcript = bytes(client.handshake_transcript)
        client.derive_application_key()
        self.assertNotEqual(old_key, client.send_key)
        self.assertEqual(client.send_seq, 0)
        client.send_seq = MAX_RECORDS_PER_KEY
        with self.assertRaises(TLSError):
            client.encrypt_message(b'a')
        server.recv_seq = MAX_RECORDS_PER_KEY
        with self.assertRaises(TLSError):
            server.decrypt_message(*first)

    def test_cleanup_drops_sensitive_references(self):
        client, _ = self.crypto_pair(False)
        client.generate_keys()
        client.load_identity()
        with patch.object(next(iter(client.kyber_kems.values())), 'free', wraps=next(iter(client.kyber_kems.values())).free) as free:
            client.clear_sensitive_data()
            free.assert_called_once()
        client.clear_sensitive_data()
        for name in ('send_key', 'recv_key', 'handshake_secret', 'ecc_private_key', 'cert_private_key'):
            self.assertIsNone(getattr(client, name))
        self.assertFalse(client.kyber_kems)
