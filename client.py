import argparse
import logging
import socket
import time
from typing import Optional
from unittest.mock import patch

from cryptography.x509 import load_pem_x509_certificate
from client_network import ClientNetwork
from client_crypto import ClientCrypto
from errors import TLSError
from utils import (
    ALERT_BAD_CERTIFICATE, ALERT_CERTIFICATE_REQUIRED, ALERT_CLOSE_NOTIFY, ALERT_DECODE_ERROR, ALERT_HANDSHAKE_FAILURE,
    ALERT_ILLEGAL_PARAMETER, ALERT_INTERNAL_ERROR, ALERT_UNEXPECTED_MESSAGE,
    DEFAULT_CA_CERT, DEFAULT_IP, DEFAULT_JSON_FILE, DEFAULT_PORT, HANDSHAKE_TYPE_CERTIFICATE,
    HANDSHAKE_TYPE_CERTIFICATE_REQUEST, HANDSHAKE_TYPE_CERTIFICATE_VERIFY, HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS,
    HANDSHAKE_TYPE_FINISHED, SIGNATURE_ECDSA_SECP384R1_SHA384, SESSION_TIMEOUT, STATE_CLIENT_APPLICATION,
    setup_logging, prompt_ip_port, handle_session_timeout
)

logger = setup_logging("client", "client.log", logging.DEBUG)

def main(ip: str = None, port: int = None, send_cert: Optional[bool] = None, test_inputs: list = None) -> None:
    """
    Main function to run the TLS 1.3 client.

    Args:
        ip: Server IP address (overrides command-line argument).
        port: Server port number (overrides command-line argument).
        send_cert: Whether to send client certificate for mutual authentication.
        test_inputs: List of inputs for test mode (overrides user input).
    """
    parser = argparse.ArgumentParser(description="TLS 1.3 Client")
    parser.add_argument("--ip", type=str, default=DEFAULT_IP, help="Server IP address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Server port number (default: 65432)")
    parser.add_argument("--send-cert", type=str, choices=["enable", "disable"], default="disable", help="Send Client Cert for Mutual Auth (default: disable)")
    parser.add_argument("--test-mode", action="store_true", help="Run in test mode")
    parser.add_argument("--message-type", type=str, choices=["1", "2", "3"], help="Message type (1: text, 2: JSON, 3: exit)")
    parser.add_argument("--message", type=str, help="Message content or file path")
    args = parser.parse_args() if not test_inputs else None

    if args and args.test_mode:
        ip, port = args.ip, args.port
        test_inputs = [args.message_type, args.message] if args.message_type else None
        send_cert = send_cert if send_cert is not None else args.send_cert == "enable"
        test_mode = True
    else:
        ip = ip if ip else (args.ip if args else DEFAULT_IP)
        port = port if port else (args.port if args else DEFAULT_PORT)
        send_cert = send_cert if send_cert is not None else (args.send_cert == "enable" if args else False)
        test_mode = False
        if not args:
            ip, port = prompt_ip_port(logger=logger)

    try:
        with open(DEFAULT_CA_CERT, "rb") as f:
            ca_cert = load_pem_x509_certificate(f.read())
        logger.info("Loaded CA certificate")

        network = ClientNetwork(ip, port, logger, ca_cert)
        crypto = ClientCrypto(logger, ca_cert, network)
        network.crypto = crypto

        logger.debug("Connecting to server")
        network.connect()
        
        client_server_handshake(crypto, network, send_cert)
        network.sock.settimeout(SESSION_TIMEOUT)
        logger.info("Handshake completed, starting message exchange")

        if test_inputs:
            with patch('builtins.input', side_effect=test_inputs):
                message_exchange(crypto, network, test_mode)
        else:
            message_exchange(crypto, network, test_mode)

    except TLSError as e:
        logger.error(f"TLS error: {e}")
    except ConnectionAbortedError as e:
        logger.error(e)
    except ConnectionError as e:
        logger.error(f"Connection failed: {e}")
        network.send_alert(ALERT_CLOSE_NOTIFY, f"Connection error: {e}")
        raise
    except ValueError as e:
        logger.error(f"Invalid data: {e}")
        network.send_alert(ALERT_ILLEGAL_PARAMETER, str(e))
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        network.send_alert(ALERT_INTERNAL_ERROR, f"Unexpected error: {e}")
        raise
    finally:
        crypto.clear_sensitive_data()
        network.close()

def client_server_handshake(crypto: ClientCrypto, network: ClientNetwork, send_cert: bool = False) -> None:
    """
    Perform the TLS 1.3 handshake with the server.

    Args:
        crypto: ClientCrypto instance for cryptographic operations.
        network: ClientNetwork instance for network operations.
        send_cert: Whether to send client certificate for mutual authentication.
    """
    logger.debug("Starting client-server handshake")
    handshake_start_time = time.perf_counter()

    # Send ClientHello
    crypto.generate_keys()
    network.send_client_hello(crypto)

    # Receive ServerHello
    server_hello = network.receive_server_hello(crypto)
    logger.debug("Received ServerHello")
    logger.debug(f"selected cipher suite: {crypto.cipher_suite}")
    use_hybrid = "Kyber" in crypto.cipher_suite

    crypto.derive_handshake_keys(server_hello, use_hybrid)
    
    network.is_handshake_encrypted = True

    # Receive EncryptedExtensions
    handshake_type, body = network.receive_encrypted_handshake_message(crypto)
    if handshake_type != HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS:
        raise TLSError(f"Expected EncryptedExtensions (0x08), got {handshake_type:02x}", ALERT_UNEXPECTED_MESSAGE, logger, network)
    handshake_message = bytes([handshake_type]) + len(body).to_bytes(3, 'big') + body
    crypto.handshake_transcript.extend(handshake_message)
    logger.debug("Received and decrypted EncryptedExtensions")

    # Check for CertificateRequest
    handshake_type, body = network.receive_encrypted_handshake_message(crypto)
    handshake_message = bytes([handshake_type]) + len(body).to_bytes(3, 'big') + body
    crypto.handshake_transcript.extend(handshake_message)
    
    mutual_auth = False
    if handshake_type == HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
        mutual_auth = True
        logger.debug("Received CertificateRequest")
        handshake_type, body = network.receive_encrypted_handshake_message(crypto)
        handshake_message = bytes([handshake_type]) + len(body).to_bytes(3, 'big') + body
        crypto.handshake_transcript.extend(handshake_message)
    else:
        logger.debug("No CertificateRequest received")
    
    # Handle server's Certificate
    logger.debug("Received server Certificate")
    if handshake_type != HANDSHAKE_TYPE_CERTIFICATE:
        raise TLSError(f"Expected Certificate (0x0b), got {handshake_type:02x}", ALERT_UNEXPECTED_MESSAGE, logger, network)
    
    server_cert_bytes = parse_server_certificate(body)

    # Receive CertificateVerify
    logger.debug("Received Server CertificateVerify")
    handshake_type, body = network.receive_encrypted_handshake_message(crypto)
    if handshake_type != HANDSHAKE_TYPE_CERTIFICATE_VERIFY:
        raise TLSError(f"Expected CertificateVerify (0x0f), got {handshake_type:02x}", ALERT_UNEXPECTED_MESSAGE, logger, network)

    parse_and_validate_server_certificate_verify(body, server_cert_bytes, network, crypto)

    # Update transcript after verification
    handshake_message = bytes([handshake_type]) + len(body).to_bytes(3, 'big') + body
    crypto.handshake_transcript.extend(handshake_message)

    # Receive server's Finished
    handshake_type, body = network.receive_encrypted_handshake_message(crypto)
    if handshake_type != HANDSHAKE_TYPE_FINISHED:
        raise TLSError(f"Expected Finished (0x14), got {handshake_type:02x}", ALERT_UNEXPECTED_MESSAGE, logger, network)
    
    # Verify Finished using the current transcript (before extending)
    if not crypto.verify_finished_message(body):
        raise TLSError("Server Finished verification failed", ALERT_HANDSHAKE_FAILURE, logger, network)
    logger.debug("Verified server Finished")
    
    # Extend the transcript with the Finished message
    handshake_message = bytes([handshake_type]) + len(body).to_bytes(3, 'big') + body
    crypto.handshake_transcript.extend(handshake_message)

    if mutual_auth:
        if send_cert:
            if crypto.cert is None:
                crypto.load_certificate()
            # Send client certificate
            network.send_client_certificate(crypto)
            logger.debug("Sent client Certificate")
            # Send client certificate verify
            network.send_client_certificate_verify(crypto)
            logger.debug("Sent client CertificateVerify")
        else:
            network.send_empty_certificate(crypto)
            raise TLSError("CertificateRequest received but no client certificate available", ALERT_CERTIFICATE_REQUIRED, logger, network)

    # Send finished
    network.send_finished(crypto)
    logger.debug("Sent client Finished")

    # Derive application key
    crypto.derive_application_key()

    network.handshake_state = STATE_CLIENT_APPLICATION

    duration = time.perf_counter() - handshake_start_time
    logger.info(f"Handshake completed in {duration:.6f} seconds")

def message_exchange(crypto: ClientCrypto, network: ClientNetwork, test_mode: bool = False) -> None:
    """
    Handle message exchange with the server after the handshake.

    Args:
        crypto: ClientCrypto instance for cryptographic operations.
        network: ClientNetwork instance for network operations.
        test_mode: If True, run in test mode with predefined inputs.
    """
    last_activity = time.time()
    logger.debug("Starting message exchange loop")

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
            logger.info(f"Received response: {response.decode('utf-8')[:50]}... (length: {len(response)} bytes)")
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
            if response == b"END_SESSION":
                logger.info("Received server termination confirmation")
            break
        plaintext = _get_message(message_type)
        if not plaintext:
            logger.warning("Message cannot be empty")
            continue
        try:
            network.send_application_data(crypto, plaintext)
            response = network.receive_application_data(crypto)
            logger.info(f"Received response: {response.decode('utf-8')[:50]}... (length: {len(response)} bytes)")
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
            logger.warning(f"Connection aborted by server: {e}. Closing gracefully.")
            network.send_alert(ALERT_CLOSE_NOTIFY, "Connection aborted")
            break
        except Exception as e:
            logger.error(f"Message exchange failed: {e}", exc_info=True)
            raise

def _get_message(message_type: str) -> Optional[bytes]:
    """
    Retrieve the message content based on the message type.

    Args:
        message_type: Type of message ("1" for text, "2" for JSON file).

    Returns:
        Optional[bytes]: Message content or None if invalid.
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

def parse_server_certificate(body: bytes) -> bytes:
    cert_len = int.from_bytes(body[1:4], 'big')
    server_cert_bytes = body[4:4 + cert_len]
    return server_cert_bytes

def parse_and_validate_server_certificate_verify(body: bytes, server_cert_bytes: bytes, network: ClientNetwork, crypto: ClientCrypto,) -> None:
    # Validate message length
    if len(body) < 4:
        raise TLSError("Invalid CertificateVerify message", ALERT_DECODE_ERROR, logger, network)

    # Parse CertificateVerify: algorithm (2 bytes), sig_len (2 bytes), signature
    algorithm = body[0:2]
    sig_len = int.from_bytes(body[2:4], 'big')
    if len(body) != 4 + sig_len:
        raise TLSError("Invalid signature length in CertificateVerify", ALERT_DECODE_ERROR, logger, network)
    signature = body[4:4 + sig_len]

    # Verify the algorithm matches the expected value
    if algorithm != SIGNATURE_ECDSA_SECP384R1_SHA384:
        raise TLSError("Unsupported signature algorithm", ALERT_HANDSHAKE_FAILURE, logger, network)

    # Verify the signature using the transcript snapshot
    transcript_snapshot = bytes(crypto.handshake_transcript)
    if not crypto.verify_certificate_verify(signature, server_cert_bytes, transcript_snapshot):
        raise TLSError("Server CertificateVerify verification failed", ALERT_BAD_CERTIFICATE, logger, network)

if __name__ == "__main__":
    main()