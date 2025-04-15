import argparse
import logging
import threading
import signal
import socket
import time
from typing import Dict, Optional, Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate

from server_network import ServerNetwork
from server_crypto import ServerCrypto
from errors import TLSError
from utils import (
    ALERT_BAD_CERTIFICATE, ALERT_CLOSE_NOTIFY, ALERT_DECODE_ERROR, ALERT_HANDSHAKE_FAILURE, ALERT_INTERNAL_ERROR, 
    ALERT_UNEXPECTED_MESSAGE, CIPHER_SUITE_CODES, CIPHER_SUITE_NAMES, CIPHER_SUITES, DEFAULT_CA_CERT, GROUP_KYBER1024, 
    GROUP_KYBER512, GROUP_KYBER768, GROUP_SECP384R1, HANDSHAKE_TYPE_CERTIFICATE, HANDSHAKE_TYPE_CERTIFICATE_VERIFY,
    HANDSHAKE_TYPE_FINISHED, SIGNATURE_ECDSA_SECP384R1_SHA384, SESSION_TIMEOUT, STATE_SERVER_APPLICATION, setup_logging,
    DEFAULT_IP, DEFAULT_PORT, handle_session_timeout
)

logger = setup_logging("server", "server.log", logging.DEBUG)
SHUTDOWN = False
ACTIVE_THREADS = []
SHUTDOWN_LOCK = threading.Lock()

def handle_client(conn: socket.socket, addr: tuple[str, int], mutual_auth: bool, preferred_cipher_suite: str) -> None:
    """
    Handle a client connection in a separate thread.

    Args:
        conn: Client connection socket.
        addr: Client address.
        mutual_auth: Whether to perform mutual authentication.
        preferred_cipher_suite: Preferred cipher suite for the handshake.
    """
    client_logger = setup_logging(f"server_client_{addr[1]}", f"logs/server_client_{addr[1]}.log", logging.DEBUG)
    
    network = ServerNetwork("", 0, client_logger)
    network.conn = conn
    network.sock = conn
    crypto = ServerCrypto(client_logger, network)
    network.crypto = crypto

    try:
        client_logger.info(f"Connected by {addr}")
        client_server_handshake(crypto, network, mutual_auth, preferred_cipher_suite)
        network.conn.settimeout(SESSION_TIMEOUT)
        client_logger.info("Handshake completed, starting message exchange")
        
        message_exchange(crypto, network)
    
    except TLSError as e:
        client_logger.error(f"TLS error with {addr}: {e}")
        network.close()
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
        crypto.clear_sensitive_data()
        network.close()
        with SHUTDOWN_LOCK:
            ACTIVE_THREADS.remove(threading.current_thread())

def main(ip: Optional[str] = None, port: Optional[int] = None, mutual_auth: Optional[bool] = None, cipher: Optional[int] = None, server_sock: Optional[socket.socket] = None) -> None:
    """
    Main function to run the TLS 1.3 server.

    Args:
        ip: IP address to bind (overrides command-line argument).
        port: Port number to bind (overrides command-line argument).
        mutual_auth: Enable mutual authentication.
        cipher: Preferred cipher suite index (1-4).
        server_sock: Optional pre-configured server socket for testing.
    """
    global SHUTDOWN
    
    parser = argparse.ArgumentParser(description="TLS 1.3 Server")
    parser.add_argument("--ip", type=str, default=DEFAULT_IP, help="IP address to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port number (default: 65432)")
    parser.add_argument("--mutual-auth", type=str, choices=["enable", "disable"], default="disable", help="Enable mutual authentication (default: disable)")
    parser.add_argument("--cipher", type=int, choices=[1, 2, 3, 4], default=2, help="Cipher suite: 1=TLS_AES_256_GCM_SHA384, 2=Kyber512, 3=Kyber768, 4=Kyber1024 (default: 2)")
    parser.add_argument("--test-mode", action="store_true", help="Run in test mode")
    args = parser.parse_args() if not server_sock else None

    ip = ip if ip else (args.ip if args else DEFAULT_IP)
    port = port if port else (args.port if args else DEFAULT_PORT)
    mutual_auth = mutual_auth if mutual_auth is not None else (args.mutual_auth == "enable" if args else False)
    cipher = cipher if cipher is not None else (args.cipher if args else 2)

    cipher_suite = CIPHER_SUITES[cipher - 1]
    logger.info(f"Starting server with IP: {ip}, Port: {port}, Mutual Auth: {mutual_auth}, Preferred Cipher: {cipher_suite}")

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
                thread = threading.Thread(target=handle_client, args=(conn, addr, mutual_auth, cipher_suite))
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
    Handle shutdown signals (SIGINT, SIGTERM).

    Args:
        signum: Signal number.
    """
    global SHUTDOWN
    logger.info(f"Received signal {signum}, initiating shutdown")
    SHUTDOWN = True

def shutdown_server(network: ServerNetwork) -> None:
    """
    Gracefully shut down the server.

    Args:
        network: ServerNetwork instance.
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
        crypto: ServerCrypto instance for cryptographic operations.
        network: ServerNetwork instance for network operations.
        mutual_auth: Whether to request client authentication.
        preferred_cipher_suite: Preferred cipher suite for the handshake.
    """
    start_time = time.perf_counter()
    network.logger.debug("Starting server-client handshake")

    # Receive ClientHello
    client_hello = network.receive_client_hello(crypto)
    network.logger.debug("Received ClientHello")

    # Select cipher suite
    use_hybrid, kyber_variant, selected_code = select_cipher_suite(client_hello, preferred_cipher_suite, network, crypto)

    # Validate, select key shares, Generate kyes, and derive handshake keys
    kyber_ct = validate_select_generate_derive_handshake_keys(client_hello, use_hybrid, kyber_variant, network, crypto)

                        # -- Send ServerHello & handshake messages -- #

    # Send ServerHello
    network.send_server_hello(crypto, client_hello, selected_code, kyber_ct)
    network.logger.debug("Sent ServerHello")

    # Send encrypted extensions
    network.send_encrypted_extensions(crypto)
    network.logger.debug("Sent Server EncryptedExtensions")
    
    if mutual_auth:
        # Send client certificate request
        network.send_certificate_request(crypto)
        network.logger.debug("Sent Server CertificateRequest")
    
    # Send server certificate
    network.send_certificate(crypto)
    network.logger.debug("Sent Server Certificate")
    
    # Send server certificate verify
    network.send_certificate_verify(crypto)
    network.logger.debug("Sent Server CertificateVerify")
    
    # Send finished
    network.send_finished(crypto)
    network.logger.debug("Sent Server Finished")

                        # -- Receive Client handshake messages -- #
    if mutual_auth:

        # Receive client's Certificate
        handshake_type, body = network.receive_encrypted_handshake_message(crypto)
        network.logger.debug("Recived client certificate")
        if handshake_type != HANDSHAKE_TYPE_CERTIFICATE:
            raise TLSError(f"Expected client Certificate (0x0b), got {handshake_type:02x}", ALERT_UNEXPECTED_MESSAGE, network.logger, network)
        handshake_message = bytes([handshake_type]) + len(body).to_bytes(3, 'big') + body
        crypto.handshake_transcript.extend(handshake_message)
        
        client_cert_bytes = parse_and_validate_client_certificate(body, network)
        
        # Receive client's CertificateVerify
        handshake_type, body = network.receive_encrypted_handshake_message(crypto)
        network.logger.debug("Recived client certificate verify")
        if handshake_type != HANDSHAKE_TYPE_CERTIFICATE_VERIFY:
            raise TLSError(f"Expected client CertificateVerify (0x0f), got {handshake_type:02x}", ALERT_UNEXPECTED_MESSAGE, network.logger, network)
        
        parse_and_validate_client_certificate_verify(body, client_cert_bytes, network, crypto)

        # Update transcript
        handshake_message = bytes([handshake_type]) + len(body).to_bytes(3, 'big') + body
        crypto.handshake_transcript.extend(handshake_message)
    
    # Receive client's Finished
    handshake_type, body = network.receive_encrypted_handshake_message(crypto)
    network.logger.debug("Recived client Finished")
    if handshake_type != HANDSHAKE_TYPE_FINISHED:
        raise TLSError(f"Expected client Finished (0x14), got {handshake_type:02x}", ALERT_UNEXPECTED_MESSAGE, network.logger, network)

    # Verify Finished using the current transcript (before extending)
    if not crypto.verify_finished_message(body):
        raise TLSError("Client Finished verification failed", ALERT_HANDSHAKE_FAILURE, network.logger, network)
    network.logger.debug("Verified client Finished")

    # Extend the transcript with the Finished message
    handshake_message = bytes([handshake_type]) + len(body).to_bytes(3, 'big') + body
    crypto.handshake_transcript.extend(handshake_message)
    
    # Derive application key
    crypto.derive_application_key()

    network.handshake_state = STATE_SERVER_APPLICATION
    
    duration = time.perf_counter() - start_time
    network.logger.info(f"Handshake completed in {duration:.6f} seconds")

def message_exchange(crypto: ServerCrypto, network: ServerNetwork) -> None:
    """
    Handle message exchange with the client after the handshake.

    Args:
        crypto: ServerCrypto instance for cryptographic operations.
        network: ServerNetwork instance for network operations.
    """
    global SHUTDOWN
    last_activity = time.time()
    network.logger.debug("Starting message exchange loop")

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
    kyber_variant = {"TLS_AES_256_GCM_SHA384_Kyber512": 1, "TLS_AES_256_GCM_SHA384_Kyber768": 2, "TLS_AES_256_GCM_SHA384_Kyber1024": 3}.get(crypto.cipher_suite)
    network.logger.info(f"Selected cipher suite: {crypto.cipher_suite}")
    return use_hybrid, kyber_variant, selected_code

def validate_select_generate_derive_handshake_keys(client_hello: Dict[str, bytes], use_hybrid: bool, kyber_variant: int | None, network: ServerNetwork, crypto: ServerCrypto) -> bytes | None:
    # Validate, select key shares, Generate kyes, and derive handshake keys
    if GROUP_SECP384R1 not in client_hello["key_shares"]:
        raise TLSError("Client did not provide ECC key share", ALERT_HANDSHAKE_FAILURE, network.logger, network)
    
    ecc_pk = client_hello["key_shares"][GROUP_SECP384R1]
    kyber_pk = None
    if use_hybrid:
        kyber_group = {"TLS_AES_256_GCM_SHA384_Kyber512": GROUP_KYBER512, "TLS_AES_256_GCM_SHA384_Kyber768": GROUP_KYBER768, "TLS_AES_256_GCM_SHA384_Kyber1024": GROUP_KYBER1024}.get(crypto.cipher_suite)
        if kyber_group not in client_hello["key_shares"]:
            raise TLSError(f"Client did not provide key share for {crypto.cipher_suite}", ALERT_HANDSHAKE_FAILURE, network.logger, network)
        kyber_pk = client_hello["key_shares"][kyber_group]

    crypto.generate_keys(use_hybrid, kyber_variant)
    kyber_ct, kyber_ss = None, None
    if use_hybrid:
        kyber_ct, kyber_ss = crypto.encapsulate_kyber(kyber_pk)
    crypto.derive_handshake_keys({"ecc_pk": ecc_pk}, use_hybrid, kyber_ss)
    network.is_handshake_encrypted = True
    return kyber_ct

def parse_and_validate_client_certificate(body: bytes, network: ServerNetwork) -> bytes:
    # Parse Certificate message
    if len(body) < 4:
        raise TLSError("Invalid Certificate message length", ALERT_DECODE_ERROR, network.logger, network)
    context_length = body[0]
    if context_length != 0:
        raise TLSError("Unexpected certificate_request_context", ALERT_UNEXPECTED_MESSAGE, network.logger, network)
    certificate_list_length = int.from_bytes(body[1:4], 'big')
    if len(body) != 4 + certificate_list_length:
        raise TLSError("Invalid certificate_list length", ALERT_DECODE_ERROR, network.logger, network)
    certificate_list = body[4:4 + certificate_list_length]
    
    # Parse single CertificateEntry (assuming one X.509 cert with no extensions)
    if len(certificate_list) < 6:
        raise TLSError("Certificate_list too short", ALERT_DECODE_ERROR, network.logger, network)
    certificate_type = certificate_list[0]
    if certificate_type != 0:  # X.509
        raise TLSError("Unsupported certificate_type", ALERT_HANDSHAKE_FAILURE, network.logger, network)
    cert_data_length = int.from_bytes(certificate_list[1:4], 'big')
    if len(certificate_list) < 4 + cert_data_length + 2:
        raise TLSError("Invalid cert_data length", ALERT_DECODE_ERROR, network.logger, network)
    client_cert_bytes = certificate_list[4:4 + cert_data_length]
    extensions_length = int.from_bytes(certificate_list[4 + cert_data_length:6 + cert_data_length], 'big')
    if extensions_length != 0:
        raise TLSError("Certificate extensions not supported", ALERT_HANDSHAKE_FAILURE, network.logger, network)
    # Validate certificate
    client_cert_obj = load_der_x509_certificate(client_cert_bytes)
    with open(DEFAULT_CA_CERT, "rb") as f:
        ca_cert = load_pem_x509_certificate(f.read())
    ca_public_key = ca_cert.public_key()
    ca_public_key.verify(client_cert_obj.signature, client_cert_obj.tbs_certificate_bytes, ec.ECDSA(hashes.SHA384()))
    network.logger.info("Client certificate verified against CA")
    return client_cert_bytes

def parse_and_validate_client_certificate_verify(body: bytes, client_cert_bytes: bytes, network: ServerNetwork, crypto: ServerCrypto,) -> None:
    # Validate message length
    if len(body) < 4:
        raise TLSError("Invalid CertificateVerify message", ALERT_DECODE_ERROR, network.logger, network)
    
    # Parse CertificateVerify: algorithm (2 bytes), sig_len (2 bytes), signature
    algorithm = body[0:2]
    sig_len = int.from_bytes(body[2:4], 'big')
    if len(body) != 4 + sig_len:
        raise TLSError("Invalid signature length in CertificateVerify", ALERT_DECODE_ERROR, network.logger, network)
    signature = body[4:4 + sig_len]
    
    # Verify the algorithm
    if algorithm != SIGNATURE_ECDSA_SECP384R1_SHA384:
        raise TLSError("Unsupported signature algorithm", ALERT_HANDSHAKE_FAILURE, network.logger, network)
    
    # Verify the signature
    transcript_snapshot = bytes(crypto.handshake_transcript)
    if not crypto.verify_certificate_verify(signature, client_cert_bytes, transcript_snapshot):
        raise TLSError("Client CertificateVerify verification failed", ALERT_BAD_CERTIFICATE, network.logger, network)       

if __name__ == "__main__":
    main()