import os
import socket
import logging
import struct
import time
from typing import Dict, Tuple

from cryptography.hazmat.primitives.serialization import Encoding
from server_crypto import ServerCrypto
from errors import TLSError
from utils import (
    ALERT_BAD_CERTIFICATE, ALERT_DECODE_ERROR, ALERT_DESCRIPTIONS,
    ALERT_HANDSHAKE_FAILURE, ALERT_ILLEGAL_PARAMETER, ALERT_PROTOCOL_VERSION, ALERT_UNEXPECTED_MESSAGE,
    ALERT_CLOSE_NOTIFY, ALERT_INTERNAL_ERROR, EXTENSION_KEY_SHARE, EXTENSION_SIGNATURE_ALGORITHMS,
    EXTENSION_SUPPORTED_VERSIONS, GROUP_SECP384R1, GROUP_KYBER512, GROUP_KYBER768, GROUP_KYBER1024,
    LEGACY_VERSION, MAX_PLAINTEXT_SIZE, STATE_SERVER_APPLICATION, STATE_SERVER_INIT,
    STATE_SERVER_RECEIVED_CLIENT_HELLO, STATE_SERVER_SENT_HELLO, STATE_SERVER_SENT_CERT_VERIFY,
    STATE_SERVER_RECEIVED_CLIENT_CERT_VERIFY, STATE_SERVER_RECEIVED_CLIENT_FINISHED, STATE_SERVER_SENT_FINISHED,
    TLS_VERSION_1_3, BaseNetwork, encode_key_share_server_hello, prompt_cipher_suite,
    receive_exact, encode_extension, decode_extensions
)

class ServerNetwork(BaseNetwork):
    """
    Manages server-side network communication for a TLS 1.3-like protocol.

    Attributes:
        ip (str): IP address to bind the server to.
        port (int): Port number to listen on.
        server_socket (socket.socket, optional): Listening socket for incoming connections.
        conn (socket.socket, optional): Socket for a specific client connection.
        addr (tuple[str, int], optional): Client's address (IP, port).
        cipher_suite (str, optional): Negotiated cipher suite with the client.
        crypto (ServerCrypto, optional): Cryptographic object (set during operations).
        logger (logging.Logger): Logger inherited from BaseNetwork.
        handshake_state (int): Current state of the handshake process.
    """
    def __init__(self, ip: str, port: int, logger: logging.Logger):
        super().__init__(logger)
        self.ip = ip
        self.port = port
        self.server_socket = None
        self.conn = None
        self.addr = None
        self.cipher_suite = None
        self.crypto = None
        self.handshake_state = STATE_SERVER_INIT

    def setup(self) -> None:
        """
        Set up the server socket to listen for incoming connections.

        Raises:
            TLSError: If socket setup fails due to binding or listening errors.
        """
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16384)
            self.server_socket.bind((self.ip, self.port))
            self.server_socket.listen(5)
            self.logger.info(f"Server listening on {self.ip}:{self.port}")
        except socket.error as e:
            raise TLSError(f"Failed to set up server socket: {e}", ALERT_INTERNAL_ERROR, self.logger, None)

    def negotiate_cipher_suite_test(self, server_choice: str) -> str:
        """
        Negotiate the cipher suite in test mode by receiving client's supported suites and using the provided choice.

        Args:
            server_choice (str): Pre-selected cipher suite for testing.

        Returns:
            str: Selected cipher suite.

        Raises:
            TLSError: If negotiation fails due to invalid input or network errors.
        """
        start = time.perf_counter()
        try:
            header = receive_exact(self.conn, 1)
            if header[0] != self.MSG_TYPE_HANDSHAKE:
                raise TLSError(f"Expected handshake, got {header[0]:02x}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
            receive_exact(self.conn, 2)  # Skip version
            length = int.from_bytes(receive_exact(self.conn, 4), 'big')
            supported_str = receive_exact(self.conn, length).decode('utf-8')
            supported_suites = supported_str.split(',')
            if server_choice not in supported_suites:
                raise TLSError(f"Test cipher suite {server_choice} not in client supported suites", ALERT_ILLEGAL_PARAMETER, self.logger, self)
            self.cipher_suite = server_choice
            self.conn.send(bytes([self.MSG_TYPE_HANDSHAKE]) + LEGACY_VERSION + len(server_choice).to_bytes(4, 'big') + server_choice.encode('utf-8'))
            self.logger.info(f"Negotiated cipher suite (test mode): {server_choice} in {time.perf_counter() - start:.6f} seconds")
            return server_choice
        except ConnectionError as e:
            raise TLSError(f"Connection closed during cipher suite negotiation: {e}", ALERT_CLOSE_NOTIFY, self.logger, self)
        except socket.error as e:
            raise TLSError(f"Socket error during cipher suite negotiation: {e}", ALERT_INTERNAL_ERROR, self.logger, self)
        except UnicodeDecodeError as e:
            raise TLSError(f"Failed to decode client supported suites: {e}", ALERT_DECODE_ERROR, self.logger, self)

    def negotiate_cipher_suite(self) -> str:
        """
        Negotiate the cipher suite by receiving the client's supported suites, prompting the user to choose one, and sending it back.

        Returns:
            str: Selected cipher suite.

        Raises:
            TLSError: If negotiation fails due to invalid input or network errors.
        """
        start = time.perf_counter()
        self.logger.debug("Receiving supported cipher suites")
        try:
            header = receive_exact(self.conn, 1)
            if header[0] == self.ALERT_TYPE:
                alert_type, desc = self.receive_alert()
                raise TLSError(f"Client alert: {desc}", alert_type, self.logger, self)
            if header[0] != self.MSG_TYPE_HANDSHAKE:
                raise TLSError(f"Expected handshake, got {header[0]:02x}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
            receive_exact(self.conn, 2)  # Skip version
            length = int.from_bytes(receive_exact(self.conn, 4), 'big')
            supported_str = receive_exact(self.conn, length).decode('utf-8')
            supported_suites = supported_str.split(',')
            if not supported_suites:
                raise TLSError("No cipher suites provided by client", ALERT_ILLEGAL_PARAMETER, self.logger, self)
            self.logger.debug(f"Received supported cipher suites: {supported_suites}")
            server_choice = prompt_cipher_suite(supported_suites)
            if server_choice not in supported_suites:
                raise TLSError(f"Server chose an unsupported suite: {server_choice}", ALERT_ILLEGAL_PARAMETER, self.logger, self)
            self.cipher_suite = server_choice
            self.logger.debug(f"Chose cipher suite: {server_choice}")
            self.conn.send(bytes([self.MSG_TYPE_HANDSHAKE]) + LEGACY_VERSION + len(server_choice).to_bytes(4, 'big') + server_choice.encode('utf-8'))
            self.logger.info(f"Negotiated cipher suite: {server_choice} in {time.perf_counter() - start:.6f} seconds")
            return server_choice
        except ConnectionError as e:
            raise TLSError(f"Connection closed during cipher suite negotiation: {e}", ALERT_CLOSE_NOTIFY, self.logger, self)
        except socket.error as e:
            raise TLSError(f"Socket error during cipher suite negotiation: {e}", ALERT_INTERNAL_ERROR, self.logger, self)
        except UnicodeDecodeError as e:
            raise TLSError(f"Failed to decode client supported suites: {e}", ALERT_DECODE_ERROR, self.logger, self)

    def receive_client_hello(self, use_hybrid: bool) -> Dict[str, bytes]:
        """
        Receive and process the ClientHello message.

        Args:
            use_hybrid (bool): True to expect a Kyber public key.

        Returns:
            Dict[str, bytes]: Client's handshake data (random, ecc_pk, kyber_pk, cert, transcript).

        Raises:
            TLSError: If message is invalid, state is incorrect, or client does not support TLS 1.3.
        """
        if self.handshake_state != STATE_SERVER_INIT:
            raise TLSError("Received ClientHello out of order", ALERT_UNEXPECTED_MESSAGE, self.logger, self)

        start = time.perf_counter()
        self.logger.debug("Receiving ClientHello")
        try:
            header = receive_exact(self.conn, 1)
        except ConnectionError as e:
            raise TLSError(f"Client closed connection unexpectedly: {e}", ALERT_CLOSE_NOTIFY, self.logger, self)
        except socket.error as e:
            raise TLSError(f"Socket error receiving ClientHello header: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

        if header[0] == self.ALERT_TYPE:
            alert_type, desc = self.receive_alert()
            raise TLSError(f"Client alert: {desc}", alert_type, self.logger, self)
        if header[0] != self.MSG_TYPE_HANDSHAKE:
            raise TLSError(f"Expected ClientHello, got {header[0]:02x}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)

        try:
            version = receive_exact(self.conn, 2)
            if version != LEGACY_VERSION:
                raise TLSError(f"Expected legacy version 0x0303, got {version.hex()}", ALERT_PROTOCOL_VERSION, self.logger, self)
            length = int.from_bytes(receive_exact(self.conn, 4), 'big')
            data = receive_exact(self.conn, length)
        except ConnectionError as e:
            raise TLSError(f"Connection closed during ClientHello: {e}", ALERT_CLOSE_NOTIFY, self.logger, self)
        except socket.error as e:
            raise TLSError(f"Socket error receiving ClientHello: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

        transcript = data

        # Parse ClientHello data
        try:
            random = data[:32]
            pos = 32
            cert_len = int.from_bytes(data[pos:pos + 4], 'big')
            pos += 4
            cert_bytes = data[pos:pos + cert_len]
            pos += cert_len
            ext_len = int.from_bytes(data[pos:pos + 2], 'big')
            pos += 2
            ext_data = data[pos:pos + ext_len]
            extensions = decode_extensions(ext_data)
        except Exception as e:
            raise TLSError(f"Failed to parse ClientHello: {e}", ALERT_DECODE_ERROR, self.logger, self)

        # Extract Signature Algorithms extension
        sig_algs = None
        for ext_type, ext_value in extensions:
            if ext_type == EXTENSION_SIGNATURE_ALGORITHMS:
                sig_algs_len = struct.unpack("!H", ext_value[:2])[0]
                sig_algs = [ext_value[i:i+2] for i in range(2, 2 + sig_algs_len, 2)]
                break
        if not sig_algs:
            raise TLSError("Client did not provide Signature Algorithms extension", ALERT_HANDSHAKE_FAILURE, self.logger, self)

        # Select the first supported algorithm (hardcoded to ECDSA_SHA384)
        selected_sig_alg = b"\x05\x03"  # SIGNATURE_ECDSA_SECP384R1_SHA384
        if selected_sig_alg not in sig_algs:
            raise TLSError("No compatible signature algorithm found", ALERT_HANDSHAKE_FAILURE, self.logger, self)

        # Extract Key Share extension
        client_key_shares = {}
        for ext_type, ext_value in extensions:
            if ext_type == EXTENSION_KEY_SHARE:
                offset = 2
                while offset < len(ext_value):
                    group, key_len = struct.unpack("!HH", ext_value[offset:offset+4])
                    key_exchange = ext_value[offset+4:offset+4+key_len]
                    client_key_shares[group] = key_exchange
                    offset += 4 + key_len
                break
        if not client_key_shares:
            raise TLSError("Client did not provide Key Share extension", ALERT_HANDSHAKE_FAILURE, self.logger, self)

        # Process key shares
        ecc_pk = kyber_pk = b""
        kyber_group = {
            "TLS_AES_256_GCM_SHA384_Kyber512": GROUP_KYBER512,
            "TLS_AES_256_GCM_SHA384_Kyber768": GROUP_KYBER768,
            "TLS_AES_256_GCM_SHA384_Kyber1024": GROUP_KYBER1024,
        }.get(self.cipher_suite)
        if use_hybrid:
            if GROUP_SECP384R1 not in client_key_shares or kyber_group not in client_key_shares:
                raise TLSError("Client missing required key shares for hybrid mode", ALERT_HANDSHAKE_FAILURE, self.logger, self)
            ecc_pk = client_key_shares[GROUP_SECP384R1]
            kyber_pk = client_key_shares[kyber_group]
        else:
            if GROUP_SECP384R1 not in client_key_shares:
                raise TLSError("Client did not provide ECC key share", ALERT_HANDSHAKE_FAILURE, self.logger, self)
            ecc_pk = client_key_shares[GROUP_SECP384R1]

        # Verify TLS 1.3 support
        supports_tls_1_3 = False
        for ext_type, ext_value in extensions:
            if ext_type == EXTENSION_SUPPORTED_VERSIONS:
                versions_len = ext_value[0]
                versions = ext_value[1:1 + versions_len]
                if TLS_VERSION_1_3 in [versions[i:i+2] for i in range(0, len(versions), 2)]:
                    supports_tls_1_3 = True
        if not supports_tls_1_3:
            raise TLSError("Client does not support TLS 1.3", ALERT_PROTOCOL_VERSION, self.logger, self)

        self.handshake_state = STATE_SERVER_RECEIVED_CLIENT_HELLO
        self.logger.info(f"Received ClientHello in {time.perf_counter() - start:.6f} seconds")
        return {"random": random, "ecc_pk": ecc_pk, "kyber_pk": kyber_pk, "cert": cert_bytes, "transcript": transcript}

    def send_server_hello(self, crypto: ServerCrypto, client_hello: Dict[str, bytes], use_hybrid: bool, kyber_ct: bytes | None) -> None:
        """
        Send the ServerHello message to the client.

        Args:
            crypto (ServerCrypto): Provides keys and certificate.
            client_hello (Dict[str, bytes]): Client's handshake data (unused here).
            use_hybrid (bool): True to include Kyber ciphertext.
            kyber_ct (bytes | None): Kyber ciphertext if hybrid.

        Raises:
            TLSError: If state is invalid or sending fails.
        """
        if self.handshake_state != STATE_SERVER_RECEIVED_CLIENT_HELLO:
            raise TLSError("Attempted to send ServerHello out of order", ALERT_UNEXPECTED_MESSAGE, self.logger, self)

        start = time.perf_counter()
        self.logger.debug("Sending ServerHello")
        random = os.urandom(32)
        cert_bytes = crypto.cert.public_bytes(Encoding.PEM)

        # Build extensions
        extensions = bytearray()
        try:
            extensions.extend(encode_extension(EXTENSION_SUPPORTED_VERSIONS, TLS_VERSION_1_3))
            key_shares = [(GROUP_SECP384R1, crypto.ecc_public_key_bytes)]
            if use_hybrid:
                kyber_group = {
                    "TLS_AES_256_GCM_SHA384_Kyber512": GROUP_KYBER512,
                    "TLS_AES_256_GCM_SHA384_Kyber768": GROUP_KYBER768,
                    "TLS_AES_256_GCM_SHA384_Kyber1024": GROUP_KYBER1024,
                }.get(self.cipher_suite)
                if kyber_ct is None:
                    raise TLSError("Missing Kyber ciphertext for hybrid mode", ALERT_INTERNAL_ERROR, self.logger, self)
                key_shares.append((kyber_group, kyber_ct))
            key_share_extension = encode_key_share_server_hello(key_shares)
            extensions.extend(key_share_extension)
        except Exception as e:
            raise TLSError(f"Failed to build ServerHello extensions: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

        # Combine data
        ext_length = len(extensions).to_bytes(2, 'big')
        data = random + len(cert_bytes).to_bytes(4, 'big') + cert_bytes + ext_length + extensions
        message = bytes([self.MSG_TYPE_HANDSHAKE]) + LEGACY_VERSION + len(data).to_bytes(4, 'big') + data

        try:
            self.conn.send(message)
        except socket.error as e:
            raise TLSError(f"Failed to send ServerHello: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

        crypto.handshake_transcript.extend(data)
        self.handshake_state = STATE_SERVER_SENT_HELLO
        self.logger.info(f"Sent ServerHello in {time.perf_counter() - start:.6f} seconds")

    def send_certificate_verify(self, crypto: ServerCrypto) -> None:
        """
        Send the CertificateVerify message to the client.

        Args:
            crypto (ServerCrypto): Provides the signature.

        Raises:
            TLSError: If state is invalid or sending fails.
        """
        if self.handshake_state != STATE_SERVER_SENT_HELLO:
            raise TLSError("Attempted to send CertificateVerify out of order", ALERT_UNEXPECTED_MESSAGE, self.logger, self)

        start = time.perf_counter()
        self.logger.debug("Sending CertificateVerify")
        try:
            signature = crypto.compute_certificate_verify()
        except TLSError as e:
            raise  # Propagate TLSError from compute_certificate_verify

        data = len(signature).to_bytes(2, 'big') + signature
        message = bytes([self.MSG_TYPE_HANDSHAKE]) + LEGACY_VERSION + len(data).to_bytes(4, 'big') + data

        try:
            self.conn.send(message)
        except socket.error as e:
            raise TLSError(f"Failed to send CertificateVerify: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

        crypto.handshake_transcript.extend(message)
        self.handshake_state = STATE_SERVER_SENT_CERT_VERIFY
        self.logger.info(f"Sent CertificateVerify in {time.perf_counter() - start:.6f} seconds")

    def receive_client_certificate_verify(self, crypto: ServerCrypto, client_cert: bytes) -> None:
        """
        Receive and verify the client's CertificateVerify message.

        Args:
            crypto (ServerCrypto): Verifies the signature.
            client_cert (bytes): Client's certificate for verification.

        Raises:
            TLSError: If message is invalid or verification fails.
        """
        if self.handshake_state != STATE_SERVER_SENT_CERT_VERIFY:
            raise TLSError("Received CertificateVerify out of order", ALERT_UNEXPECTED_MESSAGE, self.logger, self)

        start = time.perf_counter()
        self.logger.debug("Receiving CertificateVerify")
        try:
            header = receive_exact(self.conn, 1)
        except ConnectionError as e:
            raise TLSError(f"Connection closed receiving CertificateVerify: {e}", ALERT_CLOSE_NOTIFY, self.logger, self)
        except socket.error as e:
            raise TLSError(f"Socket error receiving CertificateVerify: {e}", ALERT_INTERNAL_ERROR, self.logger, self)
        
        if header[0] == self.ALERT_TYPE:
            alert_type, desc = self.receive_alert()
            raise TLSError(f"Client alert: {desc}", alert_type, self.logger, self)
        
        if header[0] != self.MSG_TYPE_HANDSHAKE:
            raise TLSError(f"Expected CertificateVerify, got {header[0]:02x}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)
        
        try:
            receive_exact(self.conn, 2)  # Skip version
            length = int.from_bytes(receive_exact(self.conn, 4), 'big')
            data = receive_exact(self.conn, length)
            sig_len = int.from_bytes(data[:2], 'big')
            signature = data[2:2 + sig_len]
        except ConnectionError as e:
            raise TLSError(f"Connection closed during CertificateVerify: {e}", ALERT_CLOSE_NOTIFY, self.logger, self)
        except socket.error as e:
            raise TLSError(f"Socket error receiving CertificateVerify data: {e}", ALERT_INTERNAL_ERROR, self.logger, self)
        except ValueError as e:
            raise TLSError(f"Malformed CertificateVerify message: {e}", ALERT_DECODE_ERROR, self.logger, self)
        
        transcript_snapshot = bytes(crypto.handshake_transcript)
        message = header + LEGACY_VERSION + len(data).to_bytes(4, 'big') + data
        crypto.handshake_transcript.extend(message)

        try:
            if not crypto.verify_certificate_verify(signature, client_cert, transcript_snapshot):
                raise TLSError("Client CertificateVerify verification failed", ALERT_BAD_CERTIFICATE, self.logger, self)
        except TLSError as e:
            raise  # Propagate TLSError from verify_certificate_verify

        self.handshake_state = STATE_SERVER_RECEIVED_CLIENT_CERT_VERIFY
        self.logger.info(f"Received and verified Client CertificateVerify in {time.perf_counter() - start:.6f} seconds")

    def receive_client_finished(self, crypto: ServerCrypto) -> None:
        """
        Receive and verify the client's Finished message.

        Args:
            crypto (ServerCrypto): Decrypts and verifies the message.

        Raises:
            TLSError: If message is invalid or verification fails.
        """
        if self.handshake_state != STATE_SERVER_RECEIVED_CLIENT_CERT_VERIFY:
            raise TLSError("Received Client Finished out of order", ALERT_UNEXPECTED_MESSAGE, self.logger, self)

        start = time.perf_counter()
        self.logger.debug("Receiving Finished")
        try:
            header = receive_exact(self.conn, 1)
        except ConnectionError as e:
            raise TLSError(f"Connection closed receiving Finished: {e}", ALERT_CLOSE_NOTIFY, self.logger, self)
        except socket.error as e:
            raise TLSError(f"Socket error receiving Finished: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

        if header[0] == self.ALERT_TYPE:
            alert_type, desc = self.receive_alert()
            raise TLSError(f"Client alert: {desc}", alert_type, self.logger, self)
        if header[0] != self.MSG_TYPE_HANDSHAKE:
            raise TLSError(f"Expected ClientFinished, got {header[0]:02x}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)

        try:
            receive_exact(self.conn, 2)  # Skip version
            length = int.from_bytes(receive_exact(self.conn, 4), 'big')
            data = receive_exact(self.conn, length)
            iv, ct = data[:12], data[12:]
        except ConnectionError as e:
            raise TLSError(f"Connection closed during Finished: {e}", ALERT_CLOSE_NOTIFY, self.logger, self)
        except socket.error as e:
            raise TLSError(f"Socket error receiving Finished data: {e}", ALERT_INTERNAL_ERROR, self.logger, self)
        except ValueError as e:
            raise TLSError(f"Malformed Finished message: {e}", ALERT_DECODE_ERROR, self.logger, self)

        try:
            decrypted = crypto.decrypt_message(b'', iv, ct)
            if not crypto.verify_finished_message(decrypted):
                raise TLSError("Client Finished verification failed", ALERT_HANDSHAKE_FAILURE, self.logger, self)
        except TLSError as e:
            raise  # Propagate TLSError from decrypt_message or verify_finished_message

        crypto.handshake_transcript.extend(header + LEGACY_VERSION + len(data).to_bytes(4, 'big') + data)
        self.handshake_state = STATE_SERVER_RECEIVED_CLIENT_FINISHED
        self.logger.info(f"Received and verified Client Finished in {time.perf_counter() - start:.6f} seconds")

    def send_finished(self, crypto: ServerCrypto) -> None:
        """
        Send the encrypted Server Finished message to the client.

        Args:
            crypto (ServerCrypto): Provides the Finished message and encryption.

        Raises:
            TLSError: If state is invalid or sending fails.
        """
        if self.handshake_state != STATE_SERVER_RECEIVED_CLIENT_FINISHED:
            raise TLSError("Attempted to send Server Finished out of order", ALERT_UNEXPECTED_MESSAGE, self.logger, self)

        start = time.perf_counter()
        self.logger.debug("Sending Finished")
        try:
            finished = crypto.compute_finished_message()
            _, iv, ct = crypto.encrypt_message(finished)
        except TLSError as e:
            raise  # Propagate TLSError from crypto methods

        message = bytes([self.MSG_TYPE_HANDSHAKE]) + LEGACY_VERSION + len(iv + ct).to_bytes(4, 'big') + iv + ct

        try:
            self.conn.send(message)
        except socket.error as e:
            raise TLSError(f"Failed to send Finished message: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

        crypto.handshake_transcript.extend(message)
        self.handshake_state = STATE_SERVER_SENT_FINISHED
        crypto.is_handshake_phase = False
        self.logger.info(f"Sent Finished in {time.perf_counter() - start:.6f} seconds")

    def receive_application_data(self, crypto: ServerCrypto) -> Dict[str, bytes]:
        """
        Receive and decrypt application data from the client.

        Args:
            crypto (ServerCrypto): Decrypts the data.

        Returns:
            Dict[str, bytes]: Dictionary with 'type' ('application' or 'end_session') and optionally 'data'.

        Raises:
            TLSError: If message is invalid or decryption fails.
            ConnectionError: If connection closes unexpectedly.
        """
        if self.handshake_state != STATE_SERVER_APPLICATION:
            raise TLSError("Received application data before handshake completion", ALERT_UNEXPECTED_MESSAGE, self.logger, self)

        start = time.perf_counter()
        full_plaintext = bytearray()
        while True:
            try:
                header = receive_exact(self.conn, 1)
            except ConnectionError as e:
                raise TLSError(f"Client closed connection unexpectedly: {e}", ALERT_CLOSE_NOTIFY, self.logger, self)
            except socket.error as e:
                raise TLSError(f"Socket error receiving application data: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

            if header[0] == self.ALERT_TYPE:
                alert_type, desc = self._receive_alert_with_header(header)
                if alert_type == ALERT_CLOSE_NOTIFY:
                    return {"type": "end_session"}
                raise TLSError(f"Client alert: {desc}", alert_type, self.logger, self)
            if header[0] != self.MSG_TYPE_APPLICATION:
                raise TLSError(f"Expected application data, got {header[0]:02x}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)

            try:
                receive_exact(self.conn, 2)  # Skip version
                length = int.from_bytes(receive_exact(self.conn, 2), 'big')
                data = receive_exact(self.conn, length)
                seq_bytes = data[:8]
                iv = data[8:20]
                flag = data[-1:]
                ct = data[20:-1]
            except ConnectionError as e:
                raise TLSError(f"Connection closed during application data: {e}", ALERT_CLOSE_NOTIFY, self.logger, self)
            except socket.error as e:
                raise TLSError(f"Socket error receiving application data: {e}", ALERT_INTERNAL_ERROR, self.logger, self)
            except ValueError as e:
                raise TLSError(f"Malformed application data: {e}", ALERT_DECODE_ERROR, self.logger, self)

            try:
                plaintext_chunk = crypto.decrypt_message(seq_bytes, iv, ct)
            except TLSError as e:
                raise  # Propagate TLSError from decrypt_message

            full_plaintext.extend(plaintext_chunk)
            if flag == b"\x01":
                break

        plaintext = bytes(full_plaintext)
        self.logger.info(f"Received application data (length: {len(plaintext)} bytes) in {time.perf_counter() - start:.6f} seconds")
        if plaintext == b"END_SESSION":
            return {"type": "end_session"}
        return {"type": "application", "data": plaintext}

    def send_application_data(self, crypto: ServerCrypto, plaintext: bytes) -> None:
        """
        Send encrypted application data to the client.

        Args:
            crypto (ServerCrypto): Encrypts the data.
            plaintext (bytes): Data to send.

        Raises:
            TLSError: If state is invalid or sending fails.
        """
        if self.handshake_state != STATE_SERVER_APPLICATION:
            raise TLSError("Attempted to send application data before handshake completion", ALERT_UNEXPECTED_MESSAGE, self.logger, self)

        self.logger.debug(f"Sending application data (length: {len(plaintext)} bytes)")
        chunks = [plaintext[i:i + MAX_PLAINTEXT_SIZE] for i in range(0, len(plaintext), MAX_PLAINTEXT_SIZE)]
        for i, chunk in enumerate(chunks):
            is_last = 1 if i == len(chunks) - 1 else 0
            try:
                seq_bytes, iv, ct = crypto.encrypt_message(chunk)
            except TLSError as e:
                raise  # Propagate TLSError from encrypt_message

            flag = bytes([is_last])
            data = seq_bytes + iv + ct + flag
            try:
                self.conn.send(bytes([self.MSG_TYPE_APPLICATION]) + LEGACY_VERSION + len(data).to_bytes(2, 'big') + data)
            except socket.error as e:
                raise TLSError(f"Failed to send application data: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

    def _receive_alert_with_header(self, header: bytes) -> Tuple[int, str]:
        """
        Helper method to receive an alert when the header is already read.

        Args:
            header (bytes): Pre-read alert header.

        Returns:
            Tuple[int, str]: Alert type and description.

        Raises:
            TLSError: If alert is malformed or decryption fails.
        """
        if header[0] != self.ALERT_TYPE:
            raise TLSError(f"Expected alert, got {header[0]:02x}", ALERT_UNEXPECTED_MESSAGE, self.logger, self)

        try:
            version = receive_exact(self.conn, 2)
            if version != LEGACY_VERSION:
                raise TLSError(f"Invalid alert version: {version.hex()}", ALERT_PROTOCOL_VERSION, self.logger, self)
            length = int.from_bytes(receive_exact(self.conn, 4), 'big')
            data = receive_exact(self.conn, length)
        except ConnectionError as e:
            self.logger.info("Connection closed during alert")
            return ALERT_CLOSE_NOTIFY, "Connection closed"
        except socket.error as e:
            raise TLSError(f"Socket error receiving alert: {e}", ALERT_INTERNAL_ERROR, self.logger, self)

        try:
            if self.crypto and not self.crypto.is_handshake_phase:
                if length < 8 + 12:
                    raise TLSError("Encrypted alert too short", ALERT_DECODE_ERROR, self.logger, self)
                seq_bytes = data[:8]
                iv = data[8:20]
                ct = data[20:]
                alert_data = self.crypto.decrypt_message(seq_bytes, iv, ct)
                self.logger.debug(f"Decrypted alert with seq_bytes: {seq_bytes.hex()}")
            else:
                alert_data = data
                self.logger.debug(f"Received unencrypted alert: {alert_data.hex()}")
            alert_type = alert_data[0]
            description = alert_data[1:].decode('utf-8', errors='ignore')
        except TLSError as e:
            raise  # Propagate TLSError from decrypt_message
        except Exception as e:
            raise TLSError(f"Failed to process alert: {e}", ALERT_DECODE_ERROR, self.logger, self)

        self.logger.info(f"Received alert: {ALERT_DESCRIPTIONS.get(alert_type, 'Unknown')} ({alert_type:02x}) - {description}")
        return alert_type, description

    def close(self) -> None:
        """Close the server connection and listening socket."""
        if self.conn:
            try:
                self.conn.close()
            except socket.error as e:
                self.logger.warning(f"Error closing client connection: {e}")
        if self.server_socket:
            try:
                self.server_socket.close()
            except socket.error as e:
                self.logger.warning(f"Error closing server socket: {e}")
        self.logger.info("Server connection closed")