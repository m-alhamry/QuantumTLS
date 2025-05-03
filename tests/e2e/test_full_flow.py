import signal
import socket
import unittest
import subprocess
import time
import os

class TestFullFlow(unittest.TestCase):
    """
    End-to-end tests for the full client-server interaction in the QuantumTLS prototype.
    These tests validate various scenarios including message exchange, session termination,
    handling large data, expired certificates, network interruptions, and performance under load.
    """

    def setUp(self):
        """
        Set up the test environment by initializing process variables and clearing log files.
        """
        self.client_proc = None
        self.server_proc = None
        # Clear client and server log files to ensure a clean slate for each test
        for log_file in ["client.log", "server.log"]:
            if os.path.exists(log_file):
                with open(log_file, "w") as f:
                    f.write("")

    def tearDown(self):
        """
        Clean up after each test by terminating any running client or server processes.
        """
        for proc in (self.server_proc, self.client_proc):
            if proc and proc.poll() is None:  # Check if the process is still running
                proc.terminate()
                try:
                    proc.wait(timeout=5)  # Wait up to 5 seconds for graceful termination
                except subprocess.TimeoutExpired:
                    proc.kill()  # Force kill if termination times out
                    proc.wait()

    def is_port_in_use(self, port):
        """
        Check if a given port is currently in use.

        Args:
            port (int): The port number to check.

        Returns:
            bool: True if the port is in use, False otherwise.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('localhost', port)) == 0

    def test_e2e_text_message(self):
        """
        Test the end-to-end flow for sending a text message from client to server.
        Verifies handshake completion and successful message receipt.
        """
        port = 65432
        if self.is_port_in_use(port):
            self.skipTest(f"Port {port} is in use")

        # Start the server in test mode with cipher suite 1 (TLS_AES_256_GCM_SHA384)
        self.server_proc = subprocess.Popen(
            ["python3", "-m", "src.server.main_server", "--test-mode", "--port", str(port), "--cipher", "1"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(1)  # Allow server to initialize

        # Start the client to send a simple text message
        self.client_proc = subprocess.Popen(
            ["python3", "-m", "src.client.main_client", "--test-mode", "--port", str(port), "--message-type", "1", "--message", "Hello, server!"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        self.client_proc.wait(timeout=20)  # Wait for client to complete

        # Verify logs for successful handshake and message exchange
        with open("client.log", "r") as f:
            client_log = f.read()
        self.assertIn("Handshake completed", client_log)
        self.assertIn("Message received and decrypted successfully", client_log)

    def test_e2e_json_file(self):
        """
        Test the end-to-end flow for sending a JSON file from client to server.
        Ensures the system handles file-based data correctly.
        """
        port = 65432
        if self.is_port_in_use(port):
            self.skipTest(f"Port {port} is in use")

        # Create a small test JSON file
        with open("test_data.json", "wb") as f:
            f.write(b'{"data": "test"}')

        # Start the server with cipher suite 3 (TLS_AES_256_GCM_SHA384_Kyber768)
        self.server_proc = subprocess.Popen(
            ["python3", "-m", "src.server.main_server", "--test-mode", "--port", str(port), "--cipher", "3"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(1)

        # Start the client to send the JSON file
        self.client_proc = subprocess.Popen(
            ["python3", "-m", "src.client.main_client", "--test-mode", "--port", str(port), "--message-type", "2", "--message", "test_data.json"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        self.client_proc.wait(timeout=10)

        # Check logs for successful execution
        with open("client.log", "r") as f:
            client_log = f.read()
        self.assertIn("Handshake completed", client_log)
        self.assertIn("Message received and decrypted successfully", client_log)

        # Clean up test file
        os.remove("test_data.json")

    def test_e2e_session_termination(self):
        """
        Test the end-to-end flow for client-initiated session termination.
        Verifies proper session closure handling.
        """
        port = 65432
        if self.is_port_in_use(port):
            self.skipTest(f"Port {port} is in use")

        self.server_proc = subprocess.Popen(
            ["python3", "-m", "src.server.main_server", "--test-mode", "--port", str(port), "--cipher", "1"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(1)

        self.client_proc = subprocess.Popen(
            ["python3", "-m", "src.client.main_client", "--test-mode", "--port", str(port), "--message-type", "3"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        self.client_proc.wait(timeout=10)

        with open("client.log", "r") as f:
            client_log = f.read()
        self.assertIn("Session terminated by user", client_log)

    def test_e2e_multi_client(self):
        """
        Test the end-to-end flow with multiple clients connecting to the server.
        Ensures the server can handle concurrent connections.
        """
        port = 65436
        if self.is_port_in_use(port):
            self.skipTest(f"Port {port} is in use")

        self.server_proc = subprocess.Popen(
            ["python3", "-m", "src.server.main_server", "--test-mode", "--port", str(port), "--cipher", "2"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(1)

        clients = []
        for i in range(3):
            # Launch three clients with unique messages
            client = subprocess.Popen(
                ["python3", "-m", "src.client.main_client", "--test-mode", "--port", str(port), "--message-type", "1", "--message", f"Client {i}"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            clients.append(client)

        for client in clients:
            client.wait(timeout=20)

        with open("client.log", "r") as f:
            client_log = f.read()
        received_count = client_log.count("Message received and decrypted successfully")
        self.assertGreaterEqual(received_count, 3, f"Expected at least 3 successes, got {received_count}")

    def test_e2e_large_data(self):
        """
        Test the end-to-end flow for sending large data from client to server.
        Validates handling of oversized payloads.
        """
        port = 65437
        if self.is_port_in_use(port):
            self.skipTest(f"Port {port} is in use")

        # Generate a large JSON file
        with open("large_data_example.json", "wb") as f:
            f.write(b'{"data": "' + b"large payload" * 1000 + b'"}')

        self.server_proc = subprocess.Popen(
            ["python3", "-m", "src.server.main_server", "--test-mode", "--port", str(port), "--cipher", "4"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(1)

        self.client_proc = subprocess.Popen(
            ["python3", "-m", "src.client.main_client", "--test-mode", "--port", str(port), "--message-type", "2", "--message", "large_data_example.json"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        self.client_proc.wait(timeout=30)

        with open("client.log", "r") as f:
            client_log = f.read()
        self.assertIn("Message received and decrypted successfully", client_log)

        os.remove("large_data_example.json")

    def test_e2e_with_expired_certificate(self):
        """
        Test the end-to-end flow with an expired client certificate.
        Ensures the server rejects the connection appropriately.
        """
        port = 65433
        if self.is_port_in_use(port):
            self.skipTest(f"Port {port} is in use")

        # Generate expired certificates if not present
        if not os.path.exists("src/client/expired_client.crt") or not os.path.exists("src/client/expired_client.key"):
            subprocess.run(["python3", "-m", "src.generate_client_expire_certs"], check=True)

        # Delete original client cert files
        for cert_file in ["src/client/client.crt", "src/client/client.key"]:
            if os.path.exists(cert_file):
                os.remove(cert_file)

        # Use expired certificates
        os.rename("src/client/expired_client.crt", "src/client/client.crt")
        os.rename("src/client/expired_client.key", "src/client/client.key")
        time.sleep(1)
        
        self.server_proc = subprocess.Popen(
            ["python3", "-m", "src.server.main_server", "--test-mode", "--port", str(port), "--cipher", "1", "--mutual-auth", "enable"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(1)

        self.client_proc = subprocess.Popen(
            ["python3", "-m", "src.client.main_client", "--test-mode", "--port", str(port), "--message-type", "1", "--message", "Test", "--mutual-auth", "enable"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        self.client_proc.wait(timeout=20)

        with open("client.log", "r") as f:
            client_log = f.read()
        self.assertIn("Received alert", client_log)
        self.assertIn("certificate_expired", client_log)
        self.assertIn("2d", client_log)  # Hex code for certificate_expired
    
        # Delete test resources
        for test_resource in ["src/client/expired_client.crt", "src/client/expired_client.key"]:
            if os.path.exists(test_resource):
                os.remove(test_resource)
        # Generate new client certificate
        subprocess.run(["python3", "-m", "src.generate_client_certs"], check=True)

    def test_long_running_session(self):
        """
        Test a long-running session to ensure stability over time.
        """
        port = 65439
        if self.is_port_in_use(port):
            self.skipTest(f"Port {port} is in use")

        self.server_proc = subprocess.Popen(
            ["python3", "-m", "src.server.main_server", "--test-mode", "--port", str(port), "--cipher", "3"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(1)

        self.client_proc = subprocess.Popen(
            ["python3", "-m", "src.client.main_client", "--test-mode", "--port", str(port), "--message-type", "1", "--message", "Long test"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(60)  # Simulate a 60-second session
        self.client_proc.terminate()
        self.server_proc.terminate()

        with open("client.log", "r") as f:
            client_log = f.read()
        self.assertIn("Message received and decrypted successfully", client_log)

    def test_e2e_network_interruption(self):
        """
        Test the end-to-end flow with a simulated network interruption.
        Verifies error handling when the server terminates unexpectedly.
        """
        port = 65434
        if self.is_port_in_use(port):
            self.skipTest(f"Port {port} is in use")

        self.server_proc = subprocess.Popen(
            ["python3", "-m", "src.server.main_server", "--test-mode", "--port", str(port), "--cipher", "3", "--test-interrupt"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(1)

        self.client_proc = subprocess.Popen(
            ["python3", "-m", "src.client.main_client", "--test-mode", "--port", str(port), "--message-type", "1", "--message", "Test"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        # Wait until the client sends the message
        while True:
            line = self.client_proc.stderr.readline()
            if "Sent application data" in line:
                break
            if self.client_proc.poll() is not None:
                break

        # Simulate network interruption by terminating the server
        self.server_proc.send_signal(signal.SIGTERM)

        try:
            self.client_proc.stdout.close()
            self.client_proc.stderr.close()
            self.client_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.client_proc.terminate()
            self.client_proc.wait()

        with open("client.log", "r") as f:
            client_log = f.read()
            
        self.assertTrue(
            any(err in client_log for err in ["TLS error", "Socket error", "Socket timeout", 
                "ConnectionAborted error", "Connection error", "Message exchange failed"]
            ),
            "Expected error message due to network interruption not found in client log"
        )

    def test_e2e_malformed_message(self):
        """
        Test the end-to-end flow with a malformed JSON message.
        Ensures the system handles invalid data gracefully.
        """
        port = 65435
        if self.is_port_in_use(port):
            self.skipTest(f"Port {port} is in use")

        with open("corrupted_data.json", "wb") as f:
            f.write(b"{data: invalid}")  # Intentionally malformed JSON

        self.server_proc = subprocess.Popen(
            ["python3", "-m", "src.server.main_server", "--test-mode", "--port", str(port), "--cipher", "4"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(1)

        self.client_proc = subprocess.Popen(
            ["python3", "-m", "src.client.main_client", "--test-mode", "--port", str(port), "--message-type", "2", "--message", "corrupted_data.json"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        self.client_proc.wait(timeout=20)

        with open("client.log", "r") as f:
            client_log = f.read()
        self.assertIn("Message received and decrypted successfully", client_log)

        os.remove("corrupted_data.json")

    def test_performance_under_load(self):
        """
        Test the performance of the system under load by performing multiple handshakes.
        Ensures the system remains responsive and completes within a time limit.
        """
        port = 65440
        if self.is_port_in_use(port):
            self.skipTest(f"Port {port} is in use")

        self.server_proc = subprocess.Popen(
            ["python3", "-m", "src.server.main_server", "--test-mode", "--port", str(port), "--cipher", "3"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(1)

        start_time = time.time()
        for _ in range(10):  # Perform 10 consecutive handshakes
            client_proc = subprocess.Popen(
                ["python3", "-m", "src.client.main_client", "--test-mode", "--port", str(port), "--message-type", "1", "--message", "Load test"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            client_proc.wait(timeout=10)
        duration = time.time() - start_time
        self.assertLess(duration, 20, f"Performance test exceeded 20s: {duration:.2f}s")

        with open("client.log", "r") as f:
            client_log = f.read()
        self.assertEqual(client_log.count("Handshake completed"), 10)

if __name__ == '__main__':
    unittest.main()