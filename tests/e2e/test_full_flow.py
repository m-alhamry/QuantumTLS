import signal
import socket
import unittest
import subprocess
import time
import os
import logging

class TestFullFlow(unittest.TestCase):
    def setUp(self):
        self.client_proc = None
        self.server_proc = None
        # Clear both client and server log files
        for log_file in ["client.log", "server_test.log"]:
            if os.path.exists(log_file):
                with open(log_file, "w") as f:
                    f.write("")

    def tearDown(self):
        for proc in (self.server_proc, self.client_proc):
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()

    def is_port_in_use(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('localhost', port)) == 0

    def test_e2e_text_message(self):
        port = 65432
        if self.is_port_in_use(port):
            self.skipTest(f"Port {port} is in use")
        
        self.server_proc = subprocess.Popen(
            ["python", "server.py", "--test-mode", "--port", str(port), "--cipher-suite", "TLS_AES_256_GCM_SHA384"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(1)  # Wait for server to start
        
        self.client_proc = subprocess.Popen(
            ["python", "client.py", "--test-mode", "--port", str(port), "--message-type", "1", "--message", "Hello, server!"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        self.client_proc.wait(timeout=20)
        
        with open("client.log", "r") as f:
            client_log = f.read()
        with open("server_test.log", "r") as f:
            server_log = f.read()
        
        self.assertIn("Handshake completed", client_log)
        self.assertIn("Received application data", server_log)
        self.assertIn("Message received successfully", client_log)

    def test_e2e_json_file(self):
        port = 65432
        if self.is_port_in_use(port):
            self.skipTest(f"Port {port} is in use")
        
        with open("test_data.json", "wb") as f:
            f.write(b'{"data": "test"}')
        
        self.server_proc = subprocess.Popen(
            ["python", "server.py", "--test-mode", "--port", str(port), "--cipher-suite", "TLS_AES_256_GCM_SHA384_Kyber768"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(1)
        
        self.client_proc = subprocess.Popen(
            ["python", "client.py", "--test-mode", "--port", str(port), "--message-type", "2", "--message", "test_data.json"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        self.client_proc.wait(timeout=10)
        
        with open("client.log", "r") as f:
            client_log = f.read()
        with open("server_test.log", "r") as f:
            server_log = f.read()
        
        self.assertIn("Handshake completed", client_log)
        self.assertIn("Received application data", server_log)
        self.assertIn("Message received successfully", client_log)
        
        os.remove("test_data.json")

    def test_e2e_session_termination(self):
        port = 65432
        if self.is_port_in_use(port):
            self.skipTest(f"Port {port} is in use")
        
        self.server_proc = subprocess.Popen(
            ["python", "server.py", "--test-mode", "--port", str(port), "--cipher-suite", "TLS_AES_256_GCM_SHA384"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(1)
        
        self.client_proc = subprocess.Popen(
            ["python", "client.py", "--test-mode", "--port", str(port), "--message-type", "3"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        self.client_proc.wait(timeout=10)
        
        with open("client.log", "r") as f:
            client_log = f.read()
        with open("server_test.log", "r") as f:
            server_log = f.read()
        
        self.assertIn("Session terminated by user", client_log)
        self.assertIn("Client terminated session", server_log)

    def test_e2e_multi_client(self):
        port = 65436
        if self.is_port_in_use(port):
            self.skipTest(f"Port {port} is in use")
        self.server_proc = subprocess.Popen(
            ["python", "server.py", "--test-mode", "--port", str(port), "--cipher-suite", "TLS_AES_256_GCM_SHA384_Kyber512"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(1)
        clients = []
        for i in range(3):
            client = subprocess.Popen(
                ["python", "client.py", "--test-mode", "--port", str(port), "--message-type", "1", "--message", f"Client {i}"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            clients.append(client)
        for client in clients:
            client.wait(timeout=20)
        with open("server_test.log", "r") as f:
            server_log = f.read()
        # Count unique "Received application data" lines
        received_count = server_log.count("Received application data")
        self.assertGreaterEqual(received_count, 3, f"Expected at least 3 'Received application data' logs, got {received_count}")

    def test_e2e_large_data(self):
        port = 65437
        if self.is_port_in_use(port):
            self.skipTest(f"Port {port} is in use")
        # Create a sample large_data_example.json
        with open("large_data_example.json", "wb") as f:
            f.write(b'{"data": "' + b"large payload" * 1000 + b'"}')  # Large payload
        self.server_proc = subprocess.Popen(
            ["python", "server.py", "--test-mode", "--port", str(port), "--cipher-suite", "TLS_AES_256_GCM_SHA384_Kyber1024"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(1)  # Wait for server to start
        self.client_proc = subprocess.Popen(
            ["python", "client.py", "--test-mode", "--port", str(port), "--message-type", "2", "--message", "large_data_example.json"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        self.client_proc.wait(timeout=30)
        with open("client.log", "r") as f:
            client_log = f.read()
        self.assertIn("Message received successfully", client_log)
        os.remove("large_data_example.json")  # Clean up

    def test_e2e_with_expired_certificate(self):
        port = 65433
        if self.is_port_in_use(port):
            self.skipTest(f"Port {port} is in use")
        if not os.path.exists("expired_client.crt"):
            self.skipTest("Expired certificate 'expired_client.crt' not found")
        # Backup and replace certificate
        if os.path.exists("client.crt"):
            if os.path.exists("client.crt.bak"):
                os.remove("client.crt.bak")
            os.rename("client.crt", "client.crt.bak")
        os.rename("expired_client.crt", "client.crt")
        try:
            self.server_proc = subprocess.Popen(
                ["python", "server.py", "--test-mode", "--port", str(port), "--cipher-suite", "TLS_AES_256_GCM_SHA384"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            time.sleep(1)
            self.client_proc = subprocess.Popen(
                ["python", "client.py", "--test-mode", "--port", str(port), "--message-type", "1", "--message", "Test"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            self.client_proc.wait(timeout=20)
            with open("server_test.log", "r") as f:
                server_log = f.read()
            # Check for the actual logged error substring
            self.assertIn("Client CertificateVerify verification failed", server_log,
                        "Expected certificate verification failure not found in server log")
        finally:
            os.rename("client.crt", "expired_client.crt")
            if os.path.exists("client.crt.bak"):
                os.rename("client.crt.bak", "client.crt")

    def test_long_running_session(self):
        port = 65439
        if self.is_port_in_use(port):
            self.skipTest(f"Port {port} is in use")
        self.server_proc = subprocess.Popen(
            ["python", "server.py", "--test-mode", "--port", str(port), "--cipher-suite", "TLS_AES_256_GCM_SHA384_Kyber768"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(1)  # Wait for server to start
        self.client_proc = subprocess.Popen(
            ["python", "client.py", "--test-mode", "--port", str(port), "--message-type", "1", "--message", "Long test"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(60)  # Run for 1 minute
        self.client_proc.terminate()
        self.server_proc.terminate()
        with open("server_test.log", "r") as f:
            server_log = f.read()
        self.assertNotIn("Memory", server_log)  # Check for memory leak logs

    def test_e2e_network_interruption(self):
        port = 65434
        if self.is_port_in_use(port):
            self.skipTest(f"Port {port} is in use")
        self.server_proc = subprocess.Popen(
            ["python", "server.py", "--test-mode", "--port", str(port), "--cipher-suite", "TLS_AES_256_GCM_SHA384_Kyber768"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(1)
        self.client_proc = subprocess.Popen(
            ["python", "client.py", "--test-mode", "--port", str(port), "--message-type", "1", "--message", "Test"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(0.5)  # Allow partial handshake
        self.server_proc.send_signal(signal.SIGTERM)
        self.client_proc.wait(timeout=20)
        with open("client.log", "r") as f:
            client_log = f.read()
        self.assertIn("TLS error: Connection refused after 3 attempts", client_log)  # Updated assertion

    def test_e2e_malformed_message(self):
        port = 65435
        if self.is_port_in_use(port):
            self.skipTest(f"Port {port} is in use")
        with open("corrupted_data.json", "wb") as f:
            f.write(b"{data: invalid}")  # Malformed JSON
        self.server_proc = subprocess.Popen(
            ["python", "server.py", "--test-mode", "--port", str(port), "--cipher-suite", "TLS_AES_256_GCM_SHA384_Kyber1024"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(1)
        self.client_proc = subprocess.Popen(
            ["python", "client.py", "--test-mode", "--port", str(port), "--message-type", "2", "--message", "corrupted_data.json"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        self.client_proc.wait(timeout=20)
        with open("client.log", "r") as f:
            client_log = f.read()
        self.assertIn("Message received successfully", client_log)  # Updated assertion
        os.remove("corrupted_data.json")

if __name__ == '__main__':
    unittest.main()