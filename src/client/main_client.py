import argparse
import logging
import select
import socket
import time
from typing import Optional
from unittest.mock import patch

from src.client.client_network import ClientNetwork
from src.client.client_crypto import ClientCrypto
from src.utils.crypto import parse_and_validate_certificate, validate_and_verify_certificate_verify
from src.utils.errors import TLSError
from src.utils.network import handle_session_timeout
from src.utils.utils import (
    ALERT_CERTIFICATE_REQUIRED, ALERT_CLOSE_NOTIFY, ALERT_DECODE_ERROR, ALERT_HANDSHAKE_FAILURE,
    ALERT_ILLEGAL_PARAMETER, ALERT_INTERNAL_ERROR, ALERT_TYPE, ALERT_UNEXPECTED_MESSAGE, CIPHER_SUITES,
    CLIENT_CERT_FILE, CLIENT_CERT_KEY_FILE, DEFAULT_IP, DEFAULT_JSON_FILE, DEFAULT_PORT,
    HANDSHAKE_TYPE_CERTIFICATE, HANDSHAKE_TYPE_CERTIFICATE_REQUEST, HANDSHAKE_TYPE_CERTIFICATE_VERIFY,
    HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, HANDSHAKE_TYPE_FINISHED, SESSION_TIMEOUT, STATE_CLIENT_APPLICATION, 
    setup_logging
)

logger = setup_logging("client", "client.log", logging.DEBUG)

def main(ip: str = None, port: int = None, mutual_auth: Optional[bool] = None, test_inputs: list = None) -> None:
    """
    Main function to run the TLS 1.3 client.

    Args:
        ip (str, optional): Server IP address (overrides CLI).
        port (int, optional): Server port number (overrides CLI).
        mutual_auth (bool, optional): Enable mutual authentication.
        test_inputs (list, optional): Inputs for test mode.

    Raises:
        TLSError: Propagated from handshake or message exchange.
    """
    parser = argparse.ArgumentParser(description="TLS 1.3 Client")
    parser.add_argument("--ip", type=str, default=DEFAULT_IP, help=f"Server IP address (default: {DEFAULT_IP})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Server port number (default: {DEFAULT_PORT})")
    parser.add_argument("--mutual-auth", type=str, choices=["enable", "disable"], default="disable", help="Mutual auth (default: disable)")
    parser.add_argument("--test-mode", action="store_true", help="Run in test mode")
    parser.add_argument("--message-type", type=str, choices=["1", "2", "3"], help="Message type (1: text, 2: JSON, 3: exit)")
    parser.add_argument("--message", type=str, help="Message content or file path")
    args = parser.parse_args() if not test_inputs else None

    if args and args.test_mode:
        ip, port = args.ip, args.port
        test_inputs = [args.message_type, args.message] if args.message_type else None
        mutual_auth = mutual_auth if mutual_auth is not None else args.mutual_auth == "enable"
        test_mode = True
    else:
        ip = ip if ip else (args.ip if args else DEFAULT_IP)
        port = port if port else (args.port if args else DEFAULT_PORT)
        mutual_auth = mutual_auth if mutual_auth is not None else (args.mutual_auth == "enable" if args else False)
        test_mode = False

    logger.info(f"Starting client with (--ip): {ip}, (--port): {port}, (--mutual-auth): {mutual_auth}")
    logger.info(f"Client cipher suites: {CIPHER_SUITES}")
    try:
        network = ClientNetwork(ip, port, logger)
        crypto = ClientCrypto(logger, network)
        network.crypto = crypto

        network.connect()
        logger.info(f"Connected to server ({ip}:{port})")

        logger.info("Starting client-server handshake")
        client_server_handshake(crypto, network, mutual_auth)
        network.sock.settimeout(SESSION_TIMEOUT)
        logger.info("starting message exchange")
        if test_inputs:
            with patch('builtins.input', side_effect=test_inputs):
                message_exchange(crypto, network, test_mode)
        else:
            message_exchange(crypto, network, test_mode)
    except TLSError as e:
        logger.error(f"TLS error: {e}")
    except socket.error as e:
        logger.error(f"Socket error: {e}")
        network.send_alert(ALERT_CLOSE_NOTIFY, f"Socket error: {e}")
    except ValueError as e:
        logger.error(f"Invalid data: {e}")
        network.send_alert(ALERT_ILLEGAL_PARAMETER, f"Invalid data: {e}")
    except ConnectionAbortedError as e:
        logger.error(f"ConnectionAborted error: {e}")
        network.send_alert(ALERT_CLOSE_NOTIFY, f"ConnectionAborted error: {e}")
    except ConnectionError as e:
        logger.error(f"Connection error: {e}")
        network.send_alert(ALERT_CLOSE_NOTIFY, f"Connection error: {e}",)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        network.send_alert(ALERT_INTERNAL_ERROR, f"Unexpected error: {e}")
    finally:
        crypto.clear_sensitive_data()
        network.close()

def client_server_handshake(crypto: ClientCrypto, network: ClientNetwork, mutual_auth: bool = False) -> None:
    """
    Perform the TLS 1.3 handshake with the server.

    Args:
        crypto (ClientCrypto): Crypto instance for operations.
        network (ClientNetwork): Network instance for communication.
        send_cert (bool): Whether to send client certificate.

    Raises:
        TLSError: If handshake fails at any step.
    """
    try:
        start = time.perf_counter()
        # Generate ECC and all Kyber variants keys
        crypto.generate_keys()
        # Send ClientHello
        network.send_client_hello(crypto)
        logger.debug(f"Sent ClientHello with {len(CIPHER_SUITES)} cipher suites and key shares")
        # Receive ServerHello
        server_hello = network.receive_server_hello(crypto)
        logger.debug(f"Received ServerHello. Selected cipher suite: {crypto.cipher_suite}")
        # Set use_hybred: True when Kyber there, False otherwise
        use_hybrid = "Kyber" in crypto.cipher_suite
        # Derive handshake keys
        crypto.derive_handshake_keys(server_hello, use_hybrid)
        # Receive EncryptedExtensions
        handshake_type, body = network.receive_encrypted_handshake_message(crypto)
        if handshake_type != HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS:
            raise TLSError(f"Expected EncryptedExtensions (0x08), got {handshake_type:02x}", ALERT_UNEXPECTED_MESSAGE, logger, network)
        handshake_message = bytes([handshake_type]) + len(body).to_bytes(3, 'big') + body
        crypto.handshake_transcript.extend(handshake_message)
        # Check for CertificateRequest
        handshake_type, body = network.receive_encrypted_handshake_message(crypto)
        handshake_message = bytes([handshake_type]) + len(body).to_bytes(3, 'big') + body
        crypto.handshake_transcript.extend(handshake_message)
        server_mutual_auth = False
        if handshake_type == HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
            server_mutual_auth = True
            handshake_type, body = network.receive_encrypted_handshake_message(crypto)
            handshake_message = bytes([handshake_type]) + len(body).to_bytes(3, 'big') + body
            crypto.handshake_transcript.extend(handshake_message)
        # Receive & Handle server's Certificate
        if handshake_type != HANDSHAKE_TYPE_CERTIFICATE:
            raise TLSError(f"Expected Certificate (0x0b), got {handshake_type:02x}", ALERT_UNEXPECTED_MESSAGE, logger, network)
        server_cert_bytes = parse_and_validate_certificate(body, network, "Server")
        # Receive & Handle server's Certificate Verify
        handshake_type, body = network.receive_encrypted_handshake_message(crypto)
        if handshake_type != HANDSHAKE_TYPE_CERTIFICATE_VERIFY:
            raise TLSError(f"Expected CertificateVerify (0x0f), got {handshake_type:02x}", ALERT_UNEXPECTED_MESSAGE, logger, network)
        validate_and_verify_certificate_verify(body, server_cert_bytes, network, crypto, logger)
        handshake_message = bytes([handshake_type]) + len(body).to_bytes(3, 'big') + body
        crypto.handshake_transcript.extend(handshake_message)
        # Receive & Verify server's Finished
        handshake_type, body = network.receive_encrypted_handshake_message(crypto)
        if handshake_type != HANDSHAKE_TYPE_FINISHED:
            raise TLSError(f"Expected Finished (0x14), got {handshake_type:02x}", ALERT_UNEXPECTED_MESSAGE, logger, network)
        if not crypto.verify_finished_message(body):
            raise TLSError("Server Finished verification failed", ALERT_HANDSHAKE_FAILURE, logger, network)
        serverCertReq = " CertificateRequest, " if server_mutual_auth else " "
        logger.debug(f"Received and verified server handshake messages: EncryptedExtensions,{serverCertReq}Certificate, CertificateVerify, and Finished")
        handshake_message = bytes([handshake_type]) + len(body).to_bytes(3, 'big') + body
        crypto.handshake_transcript.extend(handshake_message)
        # Send Client Certificat if Mutual auth enabled
        if server_mutual_auth:
            if mutual_auth:
                if crypto.cert is None:
                    crypto.load_certificate(CLIENT_CERT_FILE, CLIENT_CERT_KEY_FILE)
                # Send client certificate
                network.send_client_certificate(crypto)
                # Send client certificate verify
                network.send_client_certificate_verify(crypto)
            else:
                network.send_empty_certificate(crypto)
                raise TLSError("Certificate required but not provided", ALERT_CERTIFICATE_REQUIRED, logger, network)
            
            try:
                # Wait for server responce if client cert not acceptable 
                ready = select.select([network.sock], [], [], 0.1)
                if ready[0]:
                    header = network.sock.recv(1, socket.MSG_PEEK)
                    if not header:
                        raise TLSError("Server closed connection unexpectedly", ALERT_CLOSE_NOTIFY, logger, network)
                    elif header[0] == ALERT_TYPE:
                        alert_type, desc = network.receive_alert()
                        raise TLSError(f"Server sent alert: {desc}", alert_type, logger, network)
            except socket.error as e:
                raise TLSError(f"Server connection error: {e}", ALERT_INTERNAL_ERROR, logger, network)
        # Send Client Finished
        network.send_finished(crypto)
        certSend = " Certificate, CertificateVerify, and " if server_mutual_auth and mutual_auth else (" empty Certificate" if server_mutual_auth else " ")
        logger.debug(f"Sent client{certSend}Finished")
        # Dereive app keys
        crypto.derive_application_key()
        # Be ready for message exchange phase
        network.handshake_state = STATE_CLIENT_APPLICATION
        duration = time.perf_counter() - start
        logger.debug(f"Handshake completed in {duration:.6f} seconds")
    except TLSError as e:
        raise
    except Exception as e:
        raise TLSError(f"Handshake failed: {e}", ALERT_INTERNAL_ERROR, logger, network)

def message_exchange(crypto: ClientCrypto, network: ClientNetwork, test_mode: bool = False) -> None:
    """
    Handle message exchange with the server after handshake.

    Args:
        crypto (ClientCrypto): Crypto instance for operations.
        network (ClientNetwork): Network instance for communication.
        test_mode (bool): If True, use test inputs.

    Raises:
        TLSError: If message exchange fails.
    """
    last_activity = time.time()
    if test_mode:
        message_type = input("Type message (1), load from JSON (2), or exit (3): ").strip()
        if message_type == "3":
            network.end_session("Session terminated by user")
            response = network.receive_application_data(crypto)
            if response == b"END_SESSION":
                logger.info("Received server termination confirmation")
            return
        plaintext = _get_message(message_type)
        if not plaintext:
            logger.warning("Message cannot be empty")
            return
        try:
            network.send_application_data(crypto, plaintext)
            response = network.receive_application_data(crypto)
            return
        except Exception as e:
            raise

    while True:
        if handle_session_timeout(network, last_activity, SESSION_TIMEOUT):
            network.send_alert(ALERT_CLOSE_NOTIFY, "Session timeout")
            break
        try:
            message_type = input("Type message (1), load from JSON (2), or exit (3): ").strip()
        except EOFError:
            network.end_session("Input terminated")
            break
        if message_type == "3":
            network.end_session("Session terminated by user")
            response = network.receive_application_data(crypto)
            break
        plaintext = _get_message(message_type)
        if not plaintext:
            logger.warning("Message cannot be empty")
            continue
        try:
            network.send_application_data(crypto, plaintext)
            response = network.receive_application_data(crypto)
            last_activity = time.time()
        except TLSError as e:
            logger.error(f"TLS error: {e}")
            break
        except socket.timeout:
            logger.error("Socket timeout")
            network.send_alert(ALERT_CLOSE_NOTIFY, "Socket timeout")
            break
        except ValueError as e:
            logger.error(f"Invalid message data: {e}")
            network.send_alert(ALERT_DECODE_ERROR, str(e))
            break
        except ConnectionAbortedError as e:
            logger.warning(f"ConnectionAborted error by server: {e}. Closing gracefully.")
            network.send_alert(ALERT_CLOSE_NOTIFY, "ConnectionAborted error")
            break
        except Exception as e:
            logger.error(f"Message exchange failed: {e}", exc_info=True)
            raise

def _get_message(message_type: str) -> Optional[bytes]:
    """
    Retrieve message content based on type.

    Args:
        message_type (str): "1" for text, "2" for JSON file.

    Returns:
        Optional[bytes]: Message content or None if invalid/empty.

    Raises:
        ValueError: If file reading fails (caught externally).
    """
    if message_type == "1":
        try:
            message = input("Enter message: ").strip()
            return message.encode('utf-8') if message else None
        except EOFError:
            logger.warning("Input terminated")
            return None
    if message_type == "2":
        file_path = input("Enter JSON file path [default: large_data.json]: ").strip() or DEFAULT_JSON_FILE
        try:
            with open(file_path, 'rb') as f:
                return f.read()
        except FileNotFoundError:
            logger.warning(f"File not found: {file_path}")
            return None
        except Exception as e:
            logger.warning(f"Failed to read file {file_path}: {e}")
            return None
    logger.warning(f"Invalid message type: {message_type}")
    return None

if __name__ == "__main__":
    main()