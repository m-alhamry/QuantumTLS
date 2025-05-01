import argparse
import logging
import threading
import signal
import socket
import time
from typing import Dict, Optional, Tuple

from src.crypto import parse_and_validate_certificate, validate_and_verify_certificate_verify
from src.network import handle_session_timeout
from src.server.server_network import ServerNetwork
from src.server.server_crypto import ServerCrypto
from src.errors import TLSError
from src.utils import (
    ALERT_CLOSE_NOTIFY, ALERT_DECODE_ERROR, ALERT_HANDSHAKE_FAILURE, ALERT_INTERNAL_ERROR,
    ALERT_UNEXPECTED_MESSAGE, CIPHER_SUITE_CODES, CIPHER_SUITE_NAMES, CIPHER_SUITES,
    DEFAULT_SERVER_CERT, DEFAULT_SERVER_KEY, GROUP_KYBER1024, GROUP_KYBER512,
    GROUP_KYBER768, GROUP_SECP384R1, HANDSHAKE_TYPE_CERTIFICATE, HANDSHAKE_TYPE_CERTIFICATE_VERIFY,
    HANDSHAKE_TYPE_FINISHED, KYBER_GROUPS, KYBER_VARIANTS, SESSION_TIMEOUT, STATE_SERVER_APPLICATION, DEFAULT_IP, DEFAULT_PORT,
    setup_logging
)

# Global variables for server state and thread management
logger = setup_logging("server", "server.log", logging.DEBUG)
SHUTDOWN = False
ACTIVE_THREADS = []
SHUTDOWN_LOCK = threading.Lock()

def handle_client(conn: socket.socket, addr: tuple[str, int], mutual_auth: bool, preferred_cipher_suite: str) -> None:
    """
    Handle a client connection in a separate thread.

    Args:
        conn (socket.socket): Client connection socket.
        addr (tuple[str, int]): Client address (IP, port).
        mutual_auth (bool): Whether to perform mutual authentication.
        preferred_cipher_suite (str): Server's preferred cipher suite.

    Raises:
        TLSError: Propagated from handshake or message exchange on failure.
    """
    client_logger = setup_logging(f"server_client_{addr[1]}", f"logs/server_client_{addr[1]}.log", logging.DEBUG)
    network = ServerNetwork("", 0, client_logger)
    network.sock = conn
    crypto = ServerCrypto(client_logger, network)
    network.crypto = crypto

    try:
        client_logger.info(f"Connected by {addr}")
        client_logger.info("Starting server-client handshake")
        client_server_handshake(crypto, network, mutual_auth, preferred_cipher_suite)
        network.sock.settimeout(SESSION_TIMEOUT)
        client_logger.info("starting message exchange")
        message_exchange(crypto, network)
    except TLSError as e:
        client_logger.error(f"TLS error with {addr}: {e}")
    except socket.error as e:
        client_logger.error(f"Network error with {addr}: {e}")
        network.send_alert(ALERT_CLOSE_NOTIFY, f"Network error: {e}")
    except ValueError as e:
        client_logger.error(f"Data error with {addr}: {e}")
        network.send_alert(ALERT_HANDSHAKE_FAILURE, str(e))
    except Exception as e:
        client_logger.error(f"Unexpected error with {addr}: {e}", exc_info=True)
        network.send_alert(ALERT_INTERNAL_ERROR, f"Unexpected error: {e}")
    finally:
        crypto.clear_sensitive_data()
        network.close()
        with SHUTDOWN_LOCK:
            ACTIVE_THREADS.remove(threading.current_thread())
        
def main(ip: Optional[str] = None, port: Optional[int] = None, mutual_auth: Optional[bool] = None, cipher: Optional[int] = None, server_sock: Optional[socket.socket] = None) -> None:
    """
    Main function to run the TLS 1.3 server.

    Args:
        ip (str, optional): IP address to bind.
        port (int, optional): Port number to bind.
        mutual_auth (bool, optional): Enable mutual authentication.
        cipher (int, optional): Preferred cipher suite index (1-4).
        server_sock (socket.socket, optional): Pre-configured socket for testing.
    """
    global SHUTDOWN
    
    # Parse command-line arguments or use defaults/provided values
    parser = argparse.ArgumentParser(description="TLS 1.3 Server")
    parser.add_argument("--ip", type=str, default=DEFAULT_IP, help="IP address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port (default: 65432)")
    parser.add_argument("--mutual-auth", type=str, choices=["enable", "disable"], default="disable", help="Mutual auth (default: disable)")
    parser.add_argument("--cipher", type=int, choices=[1, 2, 3, 4], default=2, help="Cipher suite: 1=AES_256_GCM_SHA384, 2=Kyber512, 3=Kyber768, 4=Kyber1024 (default: 2)")
    parser.add_argument("--test-mode", action="store_true", help="Run in test mode")
    args = parser.parse_args() if not server_sock else None

    ip = ip if ip else (args.ip if args else DEFAULT_IP)
    port = port if port else (args.port if args else DEFAULT_PORT)
    mutual_auth = mutual_auth if mutual_auth is not None else (args.mutual_auth == "enable" if args else False)
    cipher = cipher if cipher is not None else (args.cipher if args else 2)
    cipher_suite = CIPHER_SUITES[cipher - 1]

    logger.info(f"Starting server with IP: {ip}, Port: {port}, Mutual Auth: {mutual_auth}, Cipher: {cipher_suite}")
    network = ServerNetwork(ip, port, logger)
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    try:
        if server_sock:
            network.server_socket = server_sock
        else:
            network.setup()
            logger.info(f"Server listening on {ip}:{port}")
        logger.info("Server started, awaiting connections")
        
        while not SHUTDOWN:
            try:
                network.server_socket.settimeout(1.0)
                conn, addr = network.server_socket.accept()
                thread = threading.Thread(target=handle_client, args=(conn, addr, mutual_auth, cipher_suite))
                with SHUTDOWN_LOCK:
                    ACTIVE_THREADS.append(thread)
                thread.start()
                logger.info(f"Spawned thread for client {addr}")
            except socket.timeout:
                continue
            except socket.error as e:
                if not SHUTDOWN:
                    logger.error(f"Accept failed: {e}")
    except TLSError as e:
        logger.error(f"Server setup failed: {e}")
    except Exception as e:
        logger.error(f"Server failed: {e}", exc_info=True)
    finally:
        shutdown_server(network)

def shutdown_handler(signum: int, _) -> None:
    """
    Handle shutdown signals (SIGINT, SIGTERM).

    Args:
        signum (int): Signal number.
    """
    global SHUTDOWN
    logger.info(f"Received signal {signum}, initiating shutdown")
    SHUTDOWN = True

def shutdown_server(network: ServerNetwork) -> None:
    """
    Gracefully shut down the server.

    Args:
        network (ServerNetwork): Server network instance.
    """
    logger.info("Shutting down server...")
    with SHUTDOWN_LOCK:
        threads = ACTIVE_THREADS.copy()
    for thread in threads:
        thread.join()
    network.close()
    logger.info("Server shut down cleanly")

def client_server_handshake(crypto: ServerCrypto, network: ServerNetwork, mutual_auth: bool, preferred_cipher_suite: str) -> None:
    """
    Perform the TLS 1.3 handshake with the client.

    Args:
        crypto (ServerCrypto): Crypto instance for cryptographic operations.
        network (ServerNetwork): Network instance for communication.
        mutual_auth (bool): Whether to request client authentication.
        preferred_cipher_suite (str): Server's preferred cipher suite.

    Raises:
        TLSError: If handshake fails at any step.
    """
    try:
        start = time.perf_counter()
        # Receive and process ClientHello
        client_hello = network.receive_client_hello(crypto)
        suites_len = len(client_hello["cipher_suites"])//2
        network.logger.debug(f"Received ClientHello with {suites_len} cipher suites")
        # Select cipher suite and determine hybrid key exchange
        use_hybrid, kyber_variant, selected_code = select_cipher_suite(client_hello, preferred_cipher_suite, network, crypto)
        network.logger.debug(f"Selected cipher suite {crypto.cipher_suite}")
        # Validate key shares and generate handshake keys
        kyber_ct = _generate_derive_handshake_keys(client_hello, use_hybrid, kyber_variant, network, crypto)
        # Send ServerHello and subsequent handshake messages
        network.send_server_hello(crypto, client_hello, selected_code, kyber_ct)
        network.logger.debug("Sent ServerHello")
        # Send encrypted extensions
        network.send_encrypted_extensions(crypto)
        network.logger.debug("Sent EncryptedExtensions")
        # Send Certificate Request if Mutual auth enabled
        if mutual_auth:
            network.send_certificate_request(crypto)
            network.logger.debug("Sent CertificateRequest")
        # Load and send server certificate if not already loaded
        if crypto.cert is None:
            crypto.load_certificate(DEFAULT_SERVER_CERT, DEFAULT_SERVER_KEY)
        network.send_certificate(crypto)
        network.logger.debug("Sent server Certificate")
        # Send certificate verify
        network.send_certificate_verify(crypto)
        network.logger.debug("Sent server CertificateVerify")
        # Send server Finished
        network.send_finished(crypto)
        network.logger.debug("Sent server Finished")
        # Handle mutual authentication if enabled
        if mutual_auth:
            # Receive Client Certificate
            handshake_type, body = network.receive_encrypted_handshake_message(crypto)
            if handshake_type != HANDSHAKE_TYPE_CERTIFICATE:
                raise TLSError(f"Expected client Certificate (0x0b), got {handshake_type:02x}", ALERT_UNEXPECTED_MESSAGE, network.logger, network)
            network.logger.debug("Received client Certificate")
            handshake_message = bytes([handshake_type]) + len(body).to_bytes(3, 'big') + body
            crypto.handshake_transcript.extend(handshake_message)
            # Validate clinet certificate
            client_cert_bytes = parse_and_validate_certificate(body, network, "Client")
            # Receive Client Certificate Verify
            handshake_type, body = network.receive_encrypted_handshake_message(crypto)
            if handshake_type != HANDSHAKE_TYPE_CERTIFICATE_VERIFY:
                raise TLSError(f"Expected client CertificateVerify (0x0f), got {handshake_type:02x}", ALERT_UNEXPECTED_MESSAGE, network.logger, network)
            network.logger.debug("Received client Certificate Verify")
            # Validate clinet certificate Verify
            validate_and_verify_certificate_verify(body, client_cert_bytes, network, crypto, network.logger)
            network.logger.debug("Verified client CertificateVerify")
            handshake_message = bytes([handshake_type]) + len(body).to_bytes(3, 'big') + body
            crypto.handshake_transcript.extend(handshake_message)

        # Receive client Finished
        handshake_type, body = network.receive_encrypted_handshake_message(crypto)
        if handshake_type != HANDSHAKE_TYPE_FINISHED:
            raise TLSError(f"Expected client Finished (0x14), got {handshake_type:02x}", ALERT_UNEXPECTED_MESSAGE, network.logger, network)
        network.logger.debug("Received client Finished")
        # Verify client Finished
        if not crypto.verify_finished_message(body):
            raise TLSError("Client Finished verification failed", ALERT_HANDSHAKE_FAILURE, network.logger, network)
        handshake_message = bytes([handshake_type]) + len(body).to_bytes(3, 'big') + body
        crypto.handshake_transcript.extend(handshake_message)

        # Derive application keys
        crypto.derive_application_key()
        # Be ready for message exchange phase
        network.handshake_state = STATE_SERVER_APPLICATION
        duration = time.perf_counter() - start
        network.logger.debug(f"Handshake completed in {duration:.6f} seconds")
    except TLSError as e:
        raise
    except Exception as e:
        raise TLSError(f"Handshake failed: {e}", ALERT_INTERNAL_ERROR, network.logger, network)

def message_exchange(crypto: ServerCrypto, network: ServerNetwork) -> None:
    """
    Handle message exchange with the client after handshake.

    Args:
        crypto (ServerCrypto): Crypto instance for cryptographic operations.
        network (ServerNetwork): Network instance for communication.

    Raises:
        TLSError: If message exchange fails.
    """
    global SHUTDOWN
    last_activity = time.time()
    while not SHUTDOWN:
        try:
            if handle_session_timeout(network, last_activity, SESSION_TIMEOUT):
                network.send_alert(ALERT_CLOSE_NOTIFY, "Session timeout")
                break
            message_data = network.receive_application_data(crypto)
            if message_data["type"] == "end_session":
                network.end_session("Client terminated session")
                break
            plaintext = message_data["data"]
            response = b"Message received successfully"
            network.send_application_data(crypto, response)
            last_activity = time.time()
        except TLSError as e:
            network.logger.error(f"TLS error: {e}")
            break
        except socket.timeout:
            network.logger.error("Socket timeout")
            network.send_alert(ALERT_CLOSE_NOTIFY, "Socket timeout")
            break
        except ValueError as e:
            network.logger.error(f"Invalid message data: {e}")
            network.send_alert(ALERT_DECODE_ERROR, str(e))
            break
        except Exception as e:
            network.logger.error(f"Message exchange failed: {e}", exc_info=True)
            network.send_alert(ALERT_INTERNAL_ERROR, str(e))
            break

def select_cipher_suite(client_hello: Dict[str, bytes], preferred_cipher_suite: str, network: ServerNetwork, crypto: ServerCrypto) -> Tuple[bool, int | None, bytes]:
    """
    Select a cipher suite based on client and server preferences.

    Args:
        client_hello (Dict[str, bytes]): Parsed ClientHello data.
        preferred_cipher_suite (str): Server's preferred cipher suite.
        network (ServerNetwork): Network instance for logging.
        crypto (ServerCrypto): Crypto instance for cipher suite selection.

    Returns:
        Tuple[bool, int | None, bytes]: (use_hybrid, kyber_variant, selected_code)

    Raises:
        TLSError: If no supported cipher suite is found.
    """
    client_cipher_suites = [client_hello["cipher_suites"][i:i+2] for i in range(0, len(client_hello["cipher_suites"]), 2)]
    preferred_code = CIPHER_SUITE_CODES.get(preferred_cipher_suite)
    if preferred_code in client_cipher_suites:
        selected_code = preferred_code
    else:
        for code in client_cipher_suites:
            if code in CIPHER_SUITE_NAMES:
                selected_code = code
                break
        else:
            raise TLSError("No supported cipher suite found", ALERT_HANDSHAKE_FAILURE, network.logger, network)
    crypto.cipher_suite = CIPHER_SUITE_NAMES[selected_code]
    use_hybrid = "Kyber" in crypto.cipher_suite
    kyber_variant = KYBER_VARIANTS.get(crypto.cipher_suite)
    return use_hybrid, kyber_variant, selected_code

def _generate_derive_handshake_keys(client_hello: Dict[str, bytes], use_hybrid: bool, kyber_variant: int | None, network: ServerNetwork, crypto: ServerCrypto) -> bytes | None:
    """
    Validate client key shares, generate server keys, and derive handshake keys.

    Args:
        client_hello (Dict[str, bytes]): Parsed ClientHello data.
        use_hybrid (bool): Whether to use hybrid key exchange.
        kyber_variant (int | None): Kyber variant if hybrid.
        network (ServerNetwork): Network instance for logging.
        crypto (ServerCrypto): Crypto instance for key operations.

    Returns:
        bytes | None: Kyber ciphertext if hybrid, else None.

    Raises:
        TLSError: If required key shares are missing or key derivation fails.
    """
    if GROUP_SECP384R1 not in client_hello["key_shares"]:
        raise TLSError("Client did not provide ECC key share", ALERT_HANDSHAKE_FAILURE, network.logger, network)
    ecc_pk = client_hello["key_shares"][GROUP_SECP384R1]
    kyber_pk = None
    if use_hybrid:
        kyber_group = KYBER_GROUPS.get(crypto.cipher_suite)
        if kyber_group not in client_hello["key_shares"]:
            raise TLSError(f"Client did not provide key share for {crypto.cipher_suite}", ALERT_HANDSHAKE_FAILURE, network.logger, network)
        kyber_pk = client_hello["key_shares"][kyber_group]

    crypto.generate_keys(use_hybrid, kyber_variant)
    kyber_ct, kyber_ss = None, None
    if use_hybrid:
        kyber_ct, kyber_ss = crypto.encapsulate_kyber(kyber_pk)
    crypto.derive_handshake_keys({"ecc_pk": ecc_pk}, use_hybrid, kyber_ss)
    return kyber_ct

if __name__ == "__main__":
    main()