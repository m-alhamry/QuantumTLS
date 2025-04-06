# Imports necessary modules for logging, timing, and type hinting
import argparse
import logging
import socket
import time
from typing import Optional
from unittest.mock import patch

from cryptography.x509 import load_pem_x509_certificate

# Imports custom modules for network and cryptographic operations
from client_network import ClientNetwork
from client_crypto import ClientCrypto
from errors import TLSError

# Imports utility functions and constants
from utils import (
    ALERT_CLOSE_NOTIFY, ALERT_DECODE_ERROR, ALERT_ILLEGAL_PARAMETER, ALERT_INTERNAL_ERROR,
    CIPHER_SUITES, SESSION_TIMEOUT, STATE_CLIENT_APPLICATION, setup_logging,
    prompt_ip_port, handle_session_timeout
)

# Sets up logging for the client with DEBUG level to "client.log"
logger = setup_logging("client", "client.log", logging.DEBUG)

def main(ip: str = None, port: int = None, test_inputs: list = None) -> None:
    """
    Run the client-side TLS 1.3-like protocol for secure communication with a server.

    This function orchestrates the client-side protocol by:
    1. Prompting for server IP and port or using provided arguments.
    2. Loading the CA certificate for server verification.
    3. Initializing network and cryptographic objects with mutual references.
    4. Establishing a connection and negotiating the cipher suite.
    5. Performing a handshake with mutual authentication.
    6. Facilitating encrypted message exchange.

    Args:
        ip (str, optional): Server IP address. Defaults to None.
        port (int, optional): Server port number. Defaults to None.
        test_inputs (list, optional): Test inputs for message exchange. Defaults to None.

    Raises:
        TLSError: If TLS-specific errors occur (e.g., handshake failure).
        ConnectionError: If network connection fails.
        ValueError: If input data or configuration is invalid.
        Exception: For unexpected errors.
    """
    parser = argparse.ArgumentParser(description="TLS 1.3 Client")
    parser.add_argument("--test-mode", action="store_true", help="Run in test mode")
    parser.add_argument("--ip", type=str, default="127.0.0.1", help="Server IP address")
    parser.add_argument("--port", type=int, default=65432, help="Server port number")
    parser.add_argument("--message-type", type=str, choices=["1", "2", "3"], help="Message type (1: text, 2: JSON file, 3: exit)")
    parser.add_argument("--message", type=str, help="Message content or file path")
    args = parser.parse_args() if not test_inputs else None

    # Determine IP and port: use args in test mode or prompt user
    if args and args.test_mode:
        ip, port = args.ip, args.port
        test_inputs = [args.message_type, args.message] if args.message_type else None
        test_mode = True
    else:
        ip, port = (ip, port) if ip and port else prompt_ip_port(logger=logger)
        test_mode = False

    try:
        # Load CA certificate with error handling
        try:
            with open("ca.crt", "rb") as f:
                ca_cert = load_pem_x509_certificate(f.read())
            logger.info("Loaded CA certificate for server verification")
        except FileNotFoundError:
            raise TLSError("CA certificate file not found", ALERT_INTERNAL_ERROR, logger)
        except Exception as e:
            raise TLSError(f"Failed to load CA certificate: {e}", ALERT_INTERNAL_ERROR, logger)

        # Initialize network and crypto objects with mutual references
        network = ClientNetwork(ip, port, logger, ca_cert)
        crypto = ClientCrypto(logger, ca_cert, network)  # Pass network for alert sending
        network.crypto = crypto

        # Connect to the server
        logger.debug("Attempting to connect to server")
        network.connect()

        # Negotiate cipher suite
        logger.debug("Sending supported cipher suites for negotiation")
        supported_suites = CIPHER_SUITES
        chosen_suite = network.negotiate_cipher_suite(supported_suites)
        crypto.cipher_suite = chosen_suite

        use_hybrid = "Kyber" in chosen_suite
        kyber_variant = {suite: i for i, suite in enumerate(CIPHER_SUITES[1:], 1)}.get(chosen_suite)
        logger.info(f"Server selected cipher suite: {chosen_suite}")

        # Perform handshake
        client_server_handshake(crypto, network, use_hybrid, kyber_variant)
        network.sock.settimeout(SESSION_TIMEOUT)
        logger.info("Handshake completed, starting message exchange")

        # Handle message exchange with test inputs or user input
        if test_inputs:
            with patch('builtins.input', side_effect=test_inputs):
                message_exchange(crypto, network, test_mode)
        else:
            message_exchange(crypto, network, test_mode)

    except TLSError as e:
        logger.error(f"TLS error: {e}")
        # Alert already sent by TLSError if network is available
    except ConnectionError as e:
        logger.error(f"Connection failed: {e}")
        network.send_alert(ALERT_CLOSE_NOTIFY, f"Connection error: {e}")
        raise
    except ValueError as e:
        logger.error(f"Invalid data or configuration: {e}")
        network.send_alert(ALERT_ILLEGAL_PARAMETER, str(e))
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        network.send_alert(ALERT_INTERNAL_ERROR, f"Unexpected error: {e}")
        raise
    finally:
        # Clean up sensitive data and close connection
        crypto.clear_sensitive_data()
        network.close()

def client_server_handshake(crypto: ClientCrypto, network: ClientNetwork, use_hybrid: bool, kyber_variant: Optional[int]) -> None:
    """
    Perform a TLS 1.3-like handshake with mutual authentication.

    Args:
        crypto (ClientCrypto): Handles cryptographic operations.
        network (ClientNetwork): Manages network communication.
        use_hybrid (bool): True for hybrid ECC+Kyber key exchange, False for ECC only.
        kyber_variant (Optional[int]): Kyber variant (1=Kyber512, 2=Kyber768, 3=Kyber1024) or None.

    Raises:
        TLSError: Propagated from crypto or network operations if handshake fails.
    """
    handshake_start_time = time.perf_counter()
    logger.debug("Starting client-server handshake")

    # Generate client keys
    start = time.perf_counter()
    crypto.generate_keys(use_hybrid, kyber_variant)
    logger.info(f"Generated {'hybrid ECC+Kyber' if use_hybrid else 'ECC'} keys in {time.perf_counter() - start:.6f} seconds")

    # Send ClientHello
    start = time.perf_counter()
    network.send_client_hello(crypto, use_hybrid)
    logger.info(f"Sent ClientHello in {time.perf_counter() - start:.6f} seconds")

    # Receive ServerHello
    start = time.perf_counter()
    server_hello = network.receive_server_hello(crypto, use_hybrid)
    logger.info(f"Received ServerHello in {time.perf_counter() - start:.6f} seconds")

    # Derive handshake keys
    start = time.perf_counter()
    crypto.derive_handshake_keys(server_hello, use_hybrid)
    logger.info(f"Derived handshake keys in {time.perf_counter() - start:.6f} seconds")

    # Receive and verify server's CertificateVerify
    start = time.perf_counter()
    network.receive_server_certificate_verify(crypto, server_hello["cert"])
    logger.info(f"Verified Server CertificateVerify in {time.perf_counter() - start:.6f} seconds")

    # Send client's CertificateVerify
    start = time.perf_counter()
    network.send_certificate_verify(crypto)
    logger.info(f"Sent CertificateVerify in {time.perf_counter() - start:.6f} seconds")

    # Send Finished message
    start = time.perf_counter()
    network.send_finished(crypto)
    logger.info(f"Sent Finished message in {time.perf_counter() - start:.6f} seconds")

    # Receive and verify server's Finished message
    start = time.perf_counter()
    network.receive_server_finished(crypto)
    logger.info(f"Verified Server Finished in {time.perf_counter() - start:.6f} seconds")

    # Derive application key
    start = time.perf_counter()
    crypto.derive_application_key()
    logger.info(f"Derived application key in {time.perf_counter() - start:.6f} seconds")

    # Update state
    network.handshake_state = STATE_CLIENT_APPLICATION

    # Log handshake completion
    duration = time.perf_counter() - handshake_start_time
    logger.info(f"Handshake completed in {duration:.6f} seconds")
    logger.debug(f"Handshake compute time (excluding network latency): {crypto.compute_time:.6f} seconds")

def message_exchange(crypto: ClientCrypto, network: ClientNetwork, test_mode: bool = False) -> None:
    """
    Exchange encrypted application data with the server.

    Args:
        crypto (ClientCrypto): Handles encryption and decryption.
        network (ClientNetwork): Manages message sending and receiving.

    Raises:
        TLSError: If TLS-specific errors occur during message exchange.
        socket.timeout: If socket times out.
        ValueError: If message data is invalid.
        Exception: For unexpected errors.
    """
    last_activity = time.time()
    logger.debug("Starting message exchange loop")

    if test_mode:
        # Handle single message and exit
        message_type = input("Type message (1), load from JSON (2), or exit (3): ").strip()
        if message_type == "3":
            logger.info("User requested session termination")
            network.end_session("Session terminated by user")
            response = network.receive_application_data(crypto)
            if response == b"END_SESSION":
                logger.info("Received server termination confirmation")
            return
        plaintext = _get_message(message_type)
        if not plaintext:
            logger.warning("Message cannot be empty; skipping send")
            return
        try:
            network.send_application_data(crypto, plaintext)
            response = network.receive_application_data(crypto)
            logger.info(f"Received response: {response.decode('utf-8')[:50]}... (length: {len(response)} bytes)")
        except Exception as e:
            logger.error(f"Message exchange failed: {e}", exc_info=True)
        return
    else:
        while True:
            # Check for session timeout
            if handle_session_timeout(network, last_activity, SESSION_TIMEOUT):
                network.send_alert(ALERT_CLOSE_NOTIFY, "Session timeout")
                break

            # Get user input for message type
            try:
                message_type = input("Type message (1), load from JSON (2), or exit (3): ").strip()
            except EOFError:
                logger.info("Input terminated, closing session")
                network.end_session("Input terminated")
                break

            # Handle exit request
            if message_type == "3":
                logger.info("User requested session termination")
                network.end_session("Session terminated by user")
                response = network.receive_application_data(crypto)
                if response == b"END_SESSION":
                    logger.info("Received server termination confirmation")
                break

            # Get message content
            plaintext = _get_message(message_type)
            if not plaintext:
                logger.warning("Message cannot be empty; skipping send")
                return

            try:
                # Send and receive message
                start_time = time.perf_counter()
                logger.debug(f"Sending message of length {len(plaintext)} bytes")
                start = time.perf_counter()
                network.send_application_data(crypto, plaintext)
                logger.info(f"Sent application data (length: {len(plaintext)} bytes) in {time.perf_counter() - start:.6f} seconds")

                start = time.perf_counter()
                response = network.receive_application_data(crypto)
                logger.info(f"Received application data (length: {len(response)} bytes) in {time.perf_counter() - start:.6f} seconds")
                logger.info(f"Received response: {response.decode('utf-8')[:50]}... (length: {len(response)} bytes)")
                logger.debug(f"Message exchange round-trip took {time.perf_counter() - start_time:.6f} seconds")

                last_activity = time.time()
            except TLSError as e:
                logger.error(f"TLS error during message exchange: {e}")
                break
            except socket.timeout:
                logger.error("Socket timeout during message exchange")
                network.send_alert(ALERT_CLOSE_NOTIFY, "Socket timeout")
                break
            except ValueError as e:
                logger.error(f"Invalid message data: {e}")
                network.send_alert(ALERT_DECODE_ERROR, str(e))
                break
            except Exception as e:
                logger.error(f"Message exchange failed: {e}", exc_info=True)
                network.send_alert(ALERT_INTERNAL_ERROR, str(e))
                break

def _get_message(message_type: str) -> Optional[bytes]:
    """
    Retrieve message content based on user selection.

    Args:
        message_type (str): "1" for typed message, "2" for JSON file load, others invalid.

    Returns:
        Optional[bytes]: Encoded message content, or None if invalid or empty.

    Raises:
        TLSError: If file operations fail in a TLS context (though logged as warning here).
    """
    if message_type == "1":
        try:
            message = input("Enter message: ").strip()
            return message.encode('utf-8') if message else None
        except EOFError:
            logger.warning("Input terminated during message entry")
            return None

    if message_type == "2":
        file_path = input("Enter JSON file path [default: large_data.json]: ").strip() or "large_data.json"
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