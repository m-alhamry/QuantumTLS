import argparse
import logging
import threading
import signal
import socket
import time
from typing import Optional

from server_network import ServerNetwork
from server_crypto import ServerCrypto
from errors import TLSError
from utils import (
    ALERT_CLOSE_NOTIFY, ALERT_DECODE_ERROR, ALERT_HANDSHAKE_FAILURE, ALERT_INTERNAL_ERROR,
    SESSION_TIMEOUT, STATE_SERVER_APPLICATION, setup_logging, prompt_ip_port, handle_session_timeout
)

# Set up global server logger
logger = setup_logging("server", "server.log", logging.DEBUG)

# Global variables for server state management
SHUTDOWN = False  # Flag to signal server shutdown
ACTIVE_THREADS = []  # List to track active client-handling threads
SHUTDOWN_LOCK = threading.Lock()  # Lock for thread-safe operations on ACTIVE_THREADS

def handle_client(conn: socket.socket, addr: tuple[str, int], test_cipher_suite: str = None) -> None:
    """
    Handle a single client connection in a separate thread.

    This function manages the client's connection lifecycle, including cipher suite negotiation,
    handshake, and message exchange, with comprehensive error handling and logging.

    Args:
        conn (socket.socket): Socket connected to the client.
        addr (tuple[str, int]): Client's address (IP, port).
        test_cipher_suite (str, optional): Cipher suite for test mode.

    Raises:
        TLSError: For TLS-specific errors during handshake or message exchange.
        socket.error: For network-related errors.
        ValueError: For invalid data or handshake failures.
        Exception: For unexpected errors.
    """
    # Set up per-client logger
    if test_cipher_suite:
        client_logger = setup_logging("server_test", "server_test.log", logging.DEBUG)
    else:
        client_logger = setup_logging(f"server_client_{addr[1]}", f"logs/server_client_{addr[1]}.log", logging.DEBUG)
    
    # Initialize network and crypto objects with mutual references
    network = ServerNetwork("", 0, client_logger)
    network.conn = conn
    network.sock = conn
    crypto = ServerCrypto(client_logger, network)  # Pass network for alert sending
    network.crypto = crypto

    try:
        client_logger.info(f"Connected by {addr}")
        
        # Negotiate cipher suite (test mode or interactive)
        cipher_suite = network.negotiate_cipher_suite_test(test_cipher_suite) if test_cipher_suite else network.negotiate_cipher_suite()
        use_hybrid = "Kyber" in cipher_suite
        kyber_variant = {"TLS_AES_256_GCM_SHA384_Kyber512": 1, "TLS_AES_256_GCM_SHA384_Kyber768": 2, "TLS_AES_256_GCM_SHA384_Kyber1024": 3}.get(cipher_suite)
        
        # Perform handshake
        client_server_handshake(crypto, network, use_hybrid, kyber_variant)
        network.conn.settimeout(SESSION_TIMEOUT)
        client_logger.info("Handshake completed, starting message exchange")
        
        # Start message exchange
        message_exchange(crypto, network)
    
    except TLSError as e:
        client_logger.error(f"TLS error with {addr}: {e}")
        # Alert already sent by TLSError if network is available
    except socket.error as e:
        client_logger.error(f"Network error with {addr}: {e}")
        network.send_alert(ALERT_CLOSE_NOTIFY, f"Network error: {e}")
    except ValueError as e:
        client_logger.error(f"Handshake or data error with {addr}: {e}")
        network.send_alert(ALERT_HANDSHAKE_FAILURE, str(e))
    except Exception as e:
        client_logger.error(f"Unexpected error with {addr}: {e}", exc_info=True)
        network.send_alert(ALERT_INTERNAL_ERROR, str(e))
    finally:
        # Clean up sensitive data and close connection
        crypto.clear_sensitive_data()
        network.close()
        with SHUTDOWN_LOCK:
            ACTIVE_THREADS.remove(threading.current_thread())

def main(ip: Optional[str] = None, port: Optional[int] = None, server_sock: Optional[socket.socket] = None) -> None:
    """
    Run the server with support for graceful shutdown.

    Sets up a server socket, listens for connections, spawns threads for clients,
    and handles SIGINT/SIGTERM signals for clean termination.

    Args:
        ip (str, optional): IP address to bind. Defaults to None.
        port (int, optional): Port number to listen on. Defaults to None.
        server_sock (socket.socket, optional): Pre-configured socket for testing. Defaults to None.

    Raises:
        Exception: For unexpected server setup or runtime errors.
    """
    global SHUTDOWN
    
    # Parse command-line arguments or use provided values
    parser = argparse.ArgumentParser(description="TLS 1.3 Server")
    parser.add_argument("--test-mode", action="store_true", help="Run in test mode")
    parser.add_argument("--ip", type=str, default="127.0.0.1", help="IP address to bind")
    parser.add_argument("--port", type=int, default=65432, help="Port number to listen on")
    parser.add_argument("--cipher-suite", type=str, help="Cipher suite for test mode")
    args = parser.parse_args() if not server_sock else None

    if args and args.test_mode:
        ip, port, test_cipher_suite = args.ip, args.port, args.cipher_suite
    else:
        ip, port = (ip, port) if ip and port else prompt_ip_port(is_server=True, logger=logger)
        test_cipher_suite = None

    # Initialize server network
    network = ServerNetwork(ip, port, logger)
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    try:
        if server_sock:
            network.server_socket = server_sock
        else:
            network.setup()
        logger.info("Server started, awaiting connections")
        
        while not SHUTDOWN:
            try:
                network.server_socket.settimeout(1.0)
                conn, addr = network.server_socket.accept()
                thread = threading.Thread(target=handle_client, args=(conn, addr, test_cipher_suite))
                with SHUTDOWN_LOCK:
                    ACTIVE_THREADS.append(thread)
                thread.start()
                logger.info(f"Spawned thread for client {addr}")
            except socket.timeout:
                continue
    except Exception as e:
        logger.error(f"Server failed: {e}", exc_info=True)
    finally:
        shutdown_server(network)

def shutdown_handler(signum: int, _) -> None:
    """
    Handle shutdown signals (SIGINT, SIGTERM) to initiate graceful server termination.

    Args:
        signum (int): Signal number received.
    """
    global SHUTDOWN
    logger.info(f"Received signal {signum}, initiating shutdown")
    SHUTDOWN = True

def shutdown_server(network: ServerNetwork) -> None:
    """
    Gracefully shut down the server by closing sockets and joining threads.

    Args:
        network (ServerNetwork): Server network instance to shut down.
    """
    logger.info("Shutting down server...")
    with SHUTDOWN_LOCK:
        threads = ACTIVE_THREADS.copy()
    for thread in threads:
        thread.join()
    network.close()
    logger.info("Server shut down cleanly")

def client_server_handshake(crypto: ServerCrypto, network: ServerNetwork, use_hybrid: bool, kyber_variant: Optional[int]) -> None:
    """
    Perform a TLS 1.3-like handshake with mutual authentication from the server side.

    Args:
        crypto (ServerCrypto): Handles cryptographic operations.
        network (ServerNetwork): Manages network communication.
        use_hybrid (bool): True for hybrid ECC+Kyber key exchange, False for ECC only.
        kyber_variant (Optional[int]): Kyber variant (1=Kyber512, 2=Kyber768, 3=Kyber1024) or None.

    Raises:
        TLSError: If handshake fails due to cryptographic or protocol errors.
        ValueError: If input data or configuration is invalid.
        Exception: For unexpected errors.
    """
    start_time = time.perf_counter()
    network.logger.debug("Starting server-client handshake")

    # Receive ClientHello
    start = time.perf_counter()
    client_hello = network.receive_client_hello(use_hybrid)
    network.logger.info(f"Received ClientHello in {time.perf_counter() - start:.6f} seconds")

    # Extend the handshake transcript with the client's transcript
    crypto.handshake_transcript.extend(client_hello["transcript"])
    
    # Generate server keys
    start = time.perf_counter()
    crypto.generate_keys(use_hybrid, kyber_variant)
    network.logger.info(f"Generated {'hybrid ECC+Kyber' if use_hybrid else 'ECC'} keys in {time.perf_counter() - start:.6f} seconds")

    # Encapsulate Kyber shared secret if hybrid
    kyber_ct, kyber_ss = None, None
    if use_hybrid:
        start = time.perf_counter()
        kyber_ct, kyber_ss = crypto.encapsulate_kyber(client_hello["kyber_pk"])
        network.logger.info(f"Encapsulated Kyber shared secret in {time.perf_counter() - start:.6f} seconds")

    # Derive handshake keys
    start = time.perf_counter()
    crypto.derive_handshake_keys(client_hello, use_hybrid, kyber_ss)
    network.logger.info(f"Derived handshake keys in {time.perf_counter() - start:.6f} seconds")

    # Send ServerHello
    start = time.perf_counter()
    network.send_server_hello(crypto, client_hello, use_hybrid, kyber_ct)
    network.logger.info(f"Sent ServerHello in {time.perf_counter() - start:.6f} seconds")

    # Send server's CertificateVerify
    start = time.perf_counter()
    network.send_certificate_verify(crypto)
    network.logger.info(f"Sent CertificateVerify in {time.perf_counter() - start:.6f} seconds")

    # Receive client's CertificateVerify
    start = time.perf_counter()
    network.receive_client_certificate_verify(crypto, client_hello["cert"])
    network.logger.info(f"Received and verified Client CertificateVerify in {time.perf_counter() - start:.6f} seconds")

    # Receive client's Finished message
    start = time.perf_counter()
    network.receive_client_finished(crypto)
    network.logger.info(f"Received and verified Client Finished in {time.perf_counter() - start:.6f} seconds")

    # Send server's Finished message
    start = time.perf_counter()
    network.send_finished(crypto)
    network.logger.info(f"Sent Finished message in {time.perf_counter() - start:.6f} seconds")

    # Derive application key
    start = time.perf_counter()
    crypto.derive_application_key()
    network.logger.info(f"Derived application key in {time.perf_counter() - start:.6f} seconds")

    # Update state
    network.handshake_state = STATE_SERVER_APPLICATION

    # Log handshake completion
    duration = time.perf_counter() - start_time
    network.logger.info(f"Handshake completed in {duration:.6f} seconds")
    network.logger.debug(f"Handshake compute time (excluding network latency): {crypto.compute_time:.6f} seconds")

def message_exchange(crypto: ServerCrypto, network: ServerNetwork) -> None:
    """
    Exchange encrypted application data with the client.

    Args:
        crypto (ServerCrypto): Handles encryption and decryption.
        network (ServerNetwork): Manages message sending and receiving.

    Raises:
        TLSError: If TLS-specific errors occur during message exchange.
        socket.timeout: If socket times out.
        ValueError: If message data is invalid.
        Exception: For unexpected errors.
    """
    global SHUTDOWN
    last_activity = time.time()
    network.logger.debug("Starting message exchange loop")

    while not SHUTDOWN:
        try:
            # Check for session timeout
            if handle_session_timeout(network, last_activity, SESSION_TIMEOUT):
                network.send_alert(ALERT_CLOSE_NOTIFY, "Session timeout")
                break

            # Receive application data
            start_time = time.perf_counter()
            network.logger.debug("Waiting for client application data")
            message_data = network.receive_application_data(crypto)
            if message_data["type"] == "end_session":
                network.end_session("Client terminated session")
                break
            plaintext = message_data["data"]
            network.logger.info(f"Received application data (length: {len(plaintext)} bytes)")

            # Prepare response
            response = b"Message received successfully"
            network.logger.debug(f"Sending response of length {len(response)} bytes")

            # Send response
            network.send_application_data(crypto, response)
            network.logger.debug(f"Message exchange round-trip took {time.perf_counter() - start_time:.6f} seconds")

            last_activity = time.time()
        except TLSError as e:
            network.logger.error(f"TLS error during message exchange: {e}")
            break
        except socket.timeout:
            network.logger.error("Socket timeout during message exchange")
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

if __name__ == "__main__":
    main()