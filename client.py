# Imports necessary modules for logging, timing, and type hinting
import logging
import time
from typing import Optional

# Imports custom modules for network and cryptographic operations
from client_network import ClientNetwork
from client_crypto import ClientCrypto

# Imports utility functions and constants
from utils import setup_logging, prompt_ip_port, handle_session_timeout, ALERT_INTERNAL_ERROR

# Defines constants used in the script
# SESSION_TIMEOUT: Time in seconds after which the session times out
SESSION_TIMEOUT = 30

# CIPHER_SUITES: List of available cipher suites for negotiation
CIPHER_SUITES = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_256_GCM_SHA384_Kyber512",
    "TLS_AES_256_GCM_SHA384_Kyber768",
    "TLS_AES_256_GCM_SHA384_Kyber1024"
]

# Sets up logging for the client
# Logger is configured to log to a file named "client.log" with DEBUG level
logger = setup_logging("client", "client.log", logging.DEBUG)

def main() -> None:
    """
    Run the client-side TLS 1.3-like protocol for secure communication with a server.

    This function orchestrates the client-side protocol by:
    1. Prompting for server IP and port.
    2. Initializing network and cryptographic objects.
    3. Establishing a connection to the server.
    4. Negotiating a cipher suite with the server.
    5. Performing a handshake with mutual authentication.
    6. Facilitating encrypted message exchange with the server.
    """
    # Prompt the user for server IP and port
    ip, port = prompt_ip_port(logger=logger)
    
    # Initialize network and cryptographic objects
    network = ClientNetwork(ip, port, logger)
    crypto = ClientCrypto(logger)
    
    try:
        # Log the attempt to connect to the server
        logger.debug("Attempting to connect to server")
        
        # Establish a connection to the server
        network.connect()
        
        # Prompt the user to select a cipher suite
        cipher_suite = prompt_cipher_suite()
        
        # Set the selected cipher suite in the cryptographic object
        crypto.cipher_suite = cipher_suite
        
        # Determine if hybrid key exchange is used based on the cipher suite
        use_hybrid = "Kyber" in cipher_suite
        
        # Map the cipher suite to the corresponding Kyber variant
        kyber_variant = {suite: i for i, suite in enumerate(CIPHER_SUITES[1:], 1)}.get(cipher_suite)
        
        # Log the selected cipher suite
        logger.info(f"Selected cipher suite: {cipher_suite}")
        
        # Log the start of cipher suite negotiation
        logger.debug("Negotiating cipher suite with server")
        
        # Negotiate the cipher suite with the server
        network.negotiate_cipher_suite(cipher_suite)
        
        # Perform the handshake with the server
        client_server_handshake(crypto, network, use_hybrid, kyber_variant)
        
        # Set the socket timeout to the session timeout
        network.sock.settimeout(SESSION_TIMEOUT)
        
        # Log the completion of the handshake
        logger.info("Handshake completed, starting message exchange")
        
        # Start exchanging messages with the server
        message_exchange(crypto, network)
    except Exception as e:
        # Log any errors that occur during the process
        logger.error(f"Client encountered an error: {e}", exc_info=True)
        
        # Send an internal error alert to the server
        network.send_alert(ALERT_INTERNAL_ERROR, str(e))
    finally:
        # Clear sensitive cryptographic data
        crypto.clear_sensitive_data()
        
        # Close the network connection
        network.close()

def prompt_cipher_suite() -> str:
    """
    Prompt the user to select a cipher suite from available options.

    Returns:
        str: The selected cipher suite.
    """
    # Display the available cipher suites to the user
    print("\nAvailable cipher suites:")
    for i, suite in enumerate(CIPHER_SUITES, 1):
        print(f"{i}. {suite}")
    
    # Loop until a valid choice is made
    while True:
        try:
            # Prompt the user for a choice, defaulting to 1
            choice = input(f"Choose a cipher suite (1-{len(CIPHER_SUITES)}) [default: 1]: ").strip() or "1"
            
            # Convert the choice to an integer
            choice = int(choice)
            
            # Check if the choice is within the valid range
            if 1 <= choice <= len(CIPHER_SUITES):
                # Return the selected cipher suite
                return CIPHER_SUITES[choice - 1]
            
            # Log a warning for an invalid choice
            logger.warning(f"Invalid choice. Enter a number between 1 and {len(CIPHER_SUITES)}.")
        except ValueError:
            # Log a warning for invalid input
            logger.warning("Invalid input. Please enter a number.")

def client_server_handshake(crypto: ClientCrypto, network: ClientNetwork, use_hybrid: bool, kyber_variant: Optional[int]) -> None:
    """
    Perform a TLS 1.3-like handshake with mutual authentication.

    Args:
        crypto (ClientCrypto): Object handling cryptographic operations.
        network (ClientNetwork): Object managing network communication.
        use_hybrid (bool): True if using hybrid ECC+Kyber key exchange, False for ECC only.
        kyber_variant (Optional[int]): Kyber variant (1=Kyber512, 2=Kyber768, 3=Kyber1024) or None.
    """
    # Record the start time for the handshake
    start_time = time.perf_counter()
    
    # Log the generation of client keys
    logger.debug("Generating client keys")
    
    # Generate the necessary keys based on the cipher suite
    crypto.generate_keys(use_hybrid, kyber_variant)
    
    # Log the sending of ClientHello
    logger.debug("Sending ClientHello")
    
    # Send the ClientHello message to the server
    network.send_client_hello(crypto, use_hybrid)
    
    # Log the receiving of ServerHello
    logger.debug("Receiving ServerHello")
    
    # Receive and process the ServerHello message
    server_hello = network.receive_server_hello(crypto, use_hybrid)
    
    # Log the derivation of handshake keys
    logger.debug("Deriving handshake keys")
    
    # Derive the handshake keys using the server's public keys
    crypto.derive_handshake_keys(server_hello, use_hybrid)
    
    # Log the receiving of server certificate verify
    logger.debug("Receiving server certificate verify")
    
    # Receive and verify the server's certificate verify message
    network.receive_server_certificate_verify(crypto, server_hello["cert"])
    
    # Log the sending of client certificate verify
    logger.debug("Sending client certificate verify")
    
    # Send the client's certificate verify message
    network.send_certificate_verify(crypto)
    
    # Log the sending of client finished
    logger.debug("Sending client finished")
    
    # Send the encrypted Finished message
    network.send_finished(crypto)
    
    # Log the receiving of server finished
    logger.debug("Receiving server finished")
    
    # Receive and verify the server's Finished message
    network.receive_server_finished(crypto)
    
    # Log the derivation of application key
    logger.debug("Deriving application key")
    
    # Derive the application key for encrypted communication
    crypto.derive_application_key()
    
    # Calculate the duration of the handshake
    duration = time.perf_counter() - start_time
    
    # Log the completion time of the handshake
    logger.info(f"Handshake completed in {duration:.6f} seconds")
    
    # Log the compute time for cryptographic operations during the handshake
    logger.debug(f"Handshake compute time (excluding network latency): {crypto.compute_time:.6f} seconds")

def message_exchange(crypto: ClientCrypto, network: ClientNetwork) -> None:
    """
    Exchange encrypted application data with the server.

    Args:
        crypto (ClientCrypto): Object handling encryption and decryption.
        network (ClientNetwork): Object managing message sending and receiving.
    """
    # Record the last activity time
    last_activity = time.time()
    
    # Loop until the session is terminated
    while True:
        # Check if the session has timed out
        if handle_session_timeout(network, last_activity, SESSION_TIMEOUT):
            break
        
        # Prompt the user for the type of message to send
        message_type = input("Type message (1), load from JSON (2), or exit (3): ").strip()
        
        # If the user chooses to exit, terminate the session
        if message_type == "3":
            logger.info("User requested session termination")
            network.end_session("Session terminated by user")
            response = network.receive_application_data(crypto)
            if response == b"END_SESSION":
                logger.info("Received server termination confirmation")
            break
        
        # Get the message content based on the user's choice
        plaintext = _get_message(message_type)
        
        # If no message is provided, skip sending
        if not plaintext:
            logger.warning("Message cannot be empty; skipping send")
            continue
        
        try:
            # Record the start time for the message exchange
            start_time = time.perf_counter()
            
            # Log the sending of the message
            logger.debug(f"Sending message of length {len(plaintext)} bytes")
            
            # Send the encrypted message to the server
            network.send_application_data(crypto, plaintext)
            
            # Receive and decrypt the server's response
            response = network.receive_application_data(crypto)
            
            # Log the received response
            logger.info(f"Received response: {response.decode('utf-8')[:50]}... (length: {len(response)} bytes)")
            
            # Log the round-trip time for the message exchange
            logger.debug(f"Message exchange round-trip took {time.perf_counter() - start_time:.6f} seconds")
            
            # Update the last activity time
            last_activity = time.time()
        except Exception as e:
            # Log any errors during message exchange
            logger.error(f"Message exchange failed: {e}", exc_info=True)
            
            # Send an internal error alert to the server
            network.send_alert(ALERT_INTERNAL_ERROR, str(e))
            break

def _get_message(message_type: str) -> Optional[bytes]:
    """
    Retrieve message content based on user selection.

    Args:
        message_type (str): "1" for typed message, "2" for JSON file load, others invalid.

    Returns:
        Optional[bytes]: Encoded message content, or None if invalid or empty.
    """
    # If the user chooses to type a message
    if message_type == "1":
        message = input("Enter message: ").strip()
        return message.encode('utf-8') if message else None
    
    # If the user chooses to load from a JSON file
    if message_type == "2":
        file_path = input("Enter JSON file path [default: large_data.json]: ").strip() or "large_data.json"
        try:
            with open(file_path, 'rb') as f:
                return f.read()
        except FileNotFoundError:
            logger.warning(f"File not found: {file_path}")
            return None
    
    # Log a warning for invalid message type
    logger.warning(f"Invalid message type: {message_type}")
    return None

if __name__ == "__main__":
    # Entry point to start the client
    main()