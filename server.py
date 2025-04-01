# Imports necessary modules for logging, threading, signals, and sockets
import logging
import threading
import signal
import socket
import time
from typing import Optional

# Imports custom modules for network and cryptographic operations
from server_network import ServerNetwork
from server_crypto import ServerCrypto

# Imports utility functions and constants
from utils import setup_logging, prompt_ip_port, handle_session_timeout, ALERT_CLOSE_NOTIFY, ALERT_INTERNAL_ERROR

# Sets up logging for the server
logger = setup_logging("server", "server.log", logging.DEBUG)

# Defines constants and global variables
# SESSION_TIMEOUT: Time in seconds after which a client session times out
SESSION_TIMEOUT = 30

# SHUTDOWN: Flag to indicate server shutdown
SHUTDOWN = False

# ACTIVE_THREADS: List to track active client-handling threads
ACTIVE_THREADS = []

# SHUTDOWN_LOCK: Lock for thread-safe operations on ACTIVE_THREADS
SHUTDOWN_LOCK = threading.Lock()

def handle_client(conn: socket.socket, addr: tuple[str, int]) -> None:
    """
    Handle a single client connection in a separate thread.

    Args:
        conn (socket.socket): Socket connected to the client.
        addr (tuple[str, int]): Client's address (IP, port).
    """
    # Set up a logger for this specific client connection
    client_logger = setup_logging(f"server_client_{addr[1]}", f"logs/server_client_{addr[1]}.log", logging.DEBUG)
    
    # Initialize network and cryptographic objects for this client
    network = ServerNetwork("", 0, client_logger)
    network.conn = conn
    network.sock = conn  # Required for BaseNetwork compatibility
    crypto = ServerCrypto(client_logger)
    
    try:
        # Log the connection from the client
        client_logger.info(f"Connected by {addr}")
        
        # Negotiate the cipher suite with the client
        cipher_suite = network.negotiate_cipher_suite()
        
        # Determine if hybrid key exchange is used based on the cipher suite
        use_hybrid = "Kyber" in cipher_suite
        
        # Map the cipher suite to the corresponding Kyber variant
        kyber_variant = {"TLS_AES_256_GCM_SHA384_Kyber512": 1, "TLS_AES_256_GCM_SHA384_Kyber768": 2, "TLS_AES_256_GCM_SHA384_Kyber1024": 3}.get(cipher_suite)
        
        # Log the start of the handshake
        client_logger.debug("Starting handshake with client")
        
        # Perform the handshake with the client
        client_server_handshake(crypto, network, use_hybrid, kyber_variant)
        
        # Set the socket timeout to the session timeout
        network.conn.settimeout(SESSION_TIMEOUT)
        
        # Log the completion of the handshake
        client_logger.info("Handshake completed, starting message exchange")
        
        # Start exchanging messages with the client
        message_exchange(crypto, network)
    except Exception as e:
        # Log any errors that occur during client handling
        client_logger.error(f"Error handling client {addr}: {e}", exc_info=True)
        
        # Send an internal error alert to the client
        network.send_alert(ALERT_INTERNAL_ERROR, str(e), encrypt=(not crypto.is_handshake_phase))
    finally:
        # Clear sensitive cryptographic data
        crypto.clear_sensitive_data()
        
        # Close the network connection
        network.close()
        
        # Remove the current thread from the active threads list
        with SHUTDOWN_LOCK:
            ACTIVE_THREADS.remove(threading.current_thread())

def main() -> None:
    """
    Run the server with support for graceful shutdown.

    Sets up a server socket, listens for connections, and spawns threads to handle clients.
    Handles SIGINT and SIGTERM signals for clean termination.
    """
    global SHUTDOWN
    
    # Prompt the user for IP and port to bind the server
    ip, port = prompt_ip_port(is_server=True, logger=logger)
    
    # Initialize the server network object
    network = ServerNetwork(ip, port, logger)
    
    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    
    try:
        # Set up the server socket
        network.setup()
        
        # Log that the server is started and awaiting connections
        logger.info("Server started, awaiting connections")
        
        # Main loop to accept client connections
        while not SHUTDOWN:
            try:
                # Set a timeout for accepting connections to allow checking the SHUTDOWN flag
                network.server_socket.settimeout(1.0)
                
                # Accept a client connection
                conn, addr = network.server_socket.accept()
                
                # Create a new thread to handle the client
                thread = threading.Thread(target=handle_client, args=(conn, addr))
                
                # Add the thread to the active threads list
                with SHUTDOWN_LOCK:
                    ACTIVE_THREADS.append(thread)
                
                # Start the thread
                thread.start()
                
                # Log that a thread has been spawned for the client
                logger.info(f"Spawned thread for client {addr}")
            except socket.timeout:
                # Continue to the next iteration if no connection is received within the timeout
                continue
    except Exception as e:
        # Log any errors that occur during server operation
        logger.error(f"Server failed: {e}", exc_info=True)
    finally:
        # Shut down the server gracefully
        shutdown_server(network)

def shutdown_handler(signum: int, _) -> None:
    """
    Handle shutdown signals (SIGINT, SIGTERM) to initiate graceful server termination.

    Args:
        signum (int): Signal number received.
    """
    global SHUTDOWN
    
    # Log the received signal and initiate shutdown
    logger.info(f"Received signal {signum}, initiating shutdown")
    SHUTDOWN = True

def shutdown_server(network: ServerNetwork) -> None:
    """
    Gracefully shut down the server by closing sockets and joining threads.

    Args:
        network (ServerNetwork): Server network instance to shut down.
    """
    # Log that the server is shutting down
    logger.info("Shutting down server...")
    
    # Get a copy of the active threads list
    with SHUTDOWN_LOCK:
        threads = ACTIVE_THREADS.copy()
    
    # Wait for all active threads to finish
    for thread in threads:
        thread.join()
    
    # Close the server network
    network.close()
    
    # Log that the server has shut down cleanly
    logger.info("Server shut down cleanly")

def client_server_handshake(crypto: ServerCrypto, network: ServerNetwork, use_hybrid: bool, kyber_variant: Optional[int]) -> None:
    """
    Perform a TLS 1.3-like handshake with mutual authentication from the server side.

    Args:
        crypto (ServerCrypto): Object handling cryptographic operations.
        network (ServerNetwork): Object managing network communication.
        use_hybrid (bool): True if using hybrid ECC+Kyber key exchange, False for ECC only.
        kyber_variant (Optional[int]): Kyber variant (1=Kyber512, 2=Kyber768, 3=Kyber1024) or None.
    """
    # Record the start time for the handshake
    start_time = time.perf_counter()
    
    # Log the receiving of ClientHello
    logger.debug("Receiving ClientHello")
    
    # Receive and process the ClientHello message
    client_hello = network.receive_client_hello(use_hybrid)
    
    # Extend the handshake transcript with the client's transcript
    crypto.handshake_transcript.extend(client_hello["transcript"])
    
    # Log the generation of server keys
    logger.debug("Generating server keys")
    
    # Generate the necessary keys based on the cipher suite
    crypto.generate_keys(use_hybrid, kyber_variant)
    
    # Log the encapsulation of Kyber shared secret if hybrid is used
    logger.debug("Encapsulating Kyber shared secret" if use_hybrid else "Skipping Kyber encapsulation")
    
    # Encapsulate the Kyber shared secret if hybrid key exchange is used
    kyber_ct, kyber_ss = (crypto.encapsulate_kyber(client_hello["kyber_pk"]) if use_hybrid else (None, None))
    
    # Log the derivation of handshake keys
    logger.debug("Deriving handshake keys")
    
    # Derive the handshake keys using the client's public keys and shared secret
    crypto.derive_handshake_keys(client_hello, use_hybrid, kyber_ss)
    
    # Log the sending of ServerHello
    logger.debug("Sending ServerHello")
    
    # Send the ServerHello message to the client
    network.send_server_hello(crypto, client_hello, use_hybrid, kyber_ct)
    
    # Log the sending of server certificate verify
    logger.debug("Sending server certificate verify")
    
    # Send the server's certificate verify message
    network.send_certificate_verify(crypto)
    
    # Log the receiving of client certificate verify
    logger.debug("Receiving client certificate verify")
    
    # Receive and verify the client's certificate verify message
    network.receive_client_certificate_verify(crypto, client_hello["cert"])
    
    # Log the receiving of client finished
    logger.debug("Receiving client finished")
    
    # Receive and verify the client's Finished message
    network.receive_client_finished(crypto)
    
    # Log the sending of server finished
    logger.debug("Sending server finished")
    
    # Send the encrypted Server Finished message
    network.send_server_finished(crypto)
    
    # Log the derivation of application key
    logger.debug("Deriving application key")
    
    # Derive the application key for encrypted communication
    crypto.derive_application_key()
    
    # Calculate the duration of the handshake
    duration = time.perf_counter() - start_time
    
    # Log the completion time of the handshake
    network.logger.info(f"Handshake completed in {duration:.6f} seconds")
    
    # Log the compute time for cryptographic operations during the handshake
    network.logger.debug(f"Handshake compute time (excluding network latency): {crypto.compute_time:.6f} seconds")

def message_exchange(crypto: ServerCrypto, network: ServerNetwork) -> None:
    """
    Exchange encrypted application data with the client.

    Args:
        crypto (ServerCrypto): Object handling encryption and decryption.
        network (ServerNetwork): Object managing message sending and receiving.
    """
    global SHUTDOWN
    
    # Record the last activity time
    last_activity = time.time()
    
    # Loop until the server is shutting down or the session ends
    while not SHUTDOWN:
        try:
            # Record the start time for the message exchange
            start_time = time.perf_counter()
            
            # Log waiting for client application data
            logger.debug("Waiting for client application data")
            
            # Receive and decrypt the client's application data
            message_data = network.receive_application_data(crypto)
            
            # If the client requests to end the session, terminate the session
            if message_data["type"] == "end_session":
                network.end_session("Client terminated session")
                break
            
            # Prepare a response message
            response = b"Message received successfully"
            
            # Log the sending of the response
            logger.debug(f"Sending response of length {len(response)} bytes")
            
            # Send the encrypted response to the client
            network.send_application_data(crypto, response)
            
            # Log the round-trip time for the message exchange
            logger.debug(f"Message exchange round-trip took {time.perf_counter() - start_time:.6f} seconds")
            
            # Update the last activity time
            last_activity = time.time()
        except socket.timeout:
            # Check if the session has timed out
            if handle_session_timeout(network, last_activity, SESSION_TIMEOUT):
                break
        except ConnectionError:
            # Send a close notify alert if the connection is closed
            network.send_alert(ALERT_CLOSE_NOTIFY, "Client disconnected")
            break
        except ValueError as e:
            # Log any value errors during message exchange
            network.logger.error(f"Message exchange error: {e}", exc_info=True)
            break

if __name__ == "__main__":
    # Entry point to start the server
    main()