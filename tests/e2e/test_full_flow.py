import signal
import socket
import unittest
import subprocess
import time
import os

class TestFullFlow(unittest.TestCase):
    def setUp(self):
        self.client_proc = None
        self.server_proc = None
        # Clear client and server log files
        for log_file in ["client.log", "server.log"]:
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
            ["python", "server.py", "--test-mode", "--port", str(port), "--cipher", "1"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(1)
        
        self.client_proc = subprocess.Popen(
            ["python", "client.py", "--test-mode", "--port", str(port), "--message-type", "1", "--message", "Hello, server!"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        self.client_proc.wait(timeout=20)
        
        with open("client.log", "r") as f:
            client_log = f.read()
        
        self.assertIn("Handshake completed", client_log)
        self.assertIn("Message received successfully", client_log)

    def test_e2e_json_file(self):
        port = 65432
        if self.is_port_in_use(port):
            self.skipTest(f"Port {port} is in use")
        
        with open("test_data.json", "wb") as f:
            f.write(b'{"data": "test"}')
        
        self.server_proc = subprocess.Popen(
            ["python", "server.py", "--test-mode", "--port", str(port), "--cipher", "3"],
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
        
        self.assertIn("Handshake completed", client_log)
        self.assertIn("Message received successfully", client_log)
        
        os.remove("test_data.json")

    def test_e2e_session_termination(self):
        port = 65432
        if self.is_port_in_use(port):
            self.skipTest(f"Port {port} is in use")
        
        self.server_proc = subprocess.Popen(
            ["python", "server.py", "--test-mode", "--port", str(port), "--cipher", "1"],
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
        
        self.assertIn("Session terminated by user", client_log)

    def test_e2e_multi_client(self):
        port = 65436
        if self.is_port_in_use(port):
            self.skipTest(f"Port {port} is in use")
        self.server_proc = subprocess.Popen(
            ["python", "server.py", "--test-mode", "--port", str(port), "--cipher", "2"],
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
        with open("client.log", "r") as f:
            client_log = f.read()
        received_count = client_log.count("Message received successfully")
        self.assertGreaterEqual(received_count, 3, f"Expected at least 3 'Message received successfully', got {received_count}")

    def test_e2e_large_data(self):
        port = 65437
        if self.is_port_in_use(port):
            self.skipTest(f"Port {port} is in use")
        with open("large_data_example.json", "wb") as f:
            f.write(b'{"data": "' + b"large payload" * 1000 + b'"}')
        self.server_proc = subprocess.Popen(
            ["python", "server.py", "--test-mode", "--port", str(port), "--cipher", "4"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(1)
        self.client_proc = subprocess.Popen(
            ["python", "client.py", "--test-mode", "--port", str(port), "--message-type", "2", "--message", "large_data_example.json"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        self.client_proc.wait(timeout=30)
        with open("client.log", "r") as f:
            client_log = f.read()
        self.assertIn("Message received successfully", client_log)
        os.remove("large_data_example.json")

    def test_e2e_with_expired_certificate(self):
        port = 65433
        if self.is_port_in_use(port):
            self.skipTest(f"Port {port} is in use")
        # Check and generate expired certificate and key if they don't exist
        if not os.path.exists("expired_client.crt") or not os.path.exists("expired_client.key"):
            """Generate expired certificate and key using an external script."""
            subprocess.run(["python", "generate_client_expire_certs.py"], check=True)

        # Remove any existing backups to avoid FileExistsError
        for backup in ["client.crt.bak", "client.key.bak"]:
            if os.path.exists(backup):
                os.remove(backup)

        # Backup original files if they exist
        if os.path.exists("client.crt"):
            os.rename("client.crt", "client.crt.bak")
        if os.path.exists("client.key"):
            os.rename("client.key", "client.key.bak")

        # Swap in the expired certificate and key
        os.rename("expired_client.crt", "client.crt")
        os.rename("expired_client.key", "client.key")
        try:
            self.server_proc = subprocess.Popen(
                ["python", "server.py", "--test-mode", "--port", str(port), "--cipher", "1", "--mutual-auth", "enable"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            time.sleep(1)
            self.client_proc = subprocess.Popen(
                ["python", "client.py", "--test-mode", "--port", str(port), "--message-type", "1", "--message", "Test", "--send-cert", "enable"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            self.client_proc.wait(timeout=20)
            with open("client.log", "r") as f:
                client_log = f.read()
            self.assertIn("Received alert: certificate_expired (2d) - Certificate has expired", client_log)
        finally:
            subprocess.run(["python", "generate_client_certs.py"], check=True)
            for file in ["client.crt.bak", "client.key.bak", 
                         "expired_client.crt", "expired_client.key"]:
                if os.path.exists(file):
                    os.remove(file)

    def test_long_running_session(self):
        port = 65439
        if self.is_port_in_use(port):
            self.skipTest(f"Port {port} is in use")
        self.server_proc = subprocess.Popen(
            ["python", "server.py", "--test-mode", "--port", str(port), "--cipher", "3"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(1)
        self.client_proc = subprocess.Popen(
            ["python", "client.py", "--test-mode", "--port", str(port), "--message-type", "1", "--message", "Long test"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(60)
        self.client_proc.terminate()
        self.server_proc.terminate()
        with open("client.log", "r") as f:
            client_log = f.read()
        self.assertIn("Message received successfully", client_log)

    def test_e2e_network_interruption(self):
        port = 65434
        if self.is_port_in_use(port):
            self.skipTest(f"Port {port} is in use")
        self.server_proc = subprocess.Popen(
            ["python", "server.py", "--test-mode", "--port", str(port), "--cipher", "3"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(1)
        self.client_proc = subprocess.Popen(
            ["python", "client.py", "--test-mode", "--port", str(port), "--message-type", "1", "--message", "Test"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(0.5)
        self.server_proc.send_signal(signal.SIGTERM)
        self.client_proc.wait(timeout=20)
        with open("client.log", "r") as f:
            client_log = f.read()
        self.assertIn("Connection failed", client_log)

    def test_e2e_malformed_message(self):
        port = 65435
        if self.is_port_in_use(port):
            self.skipTest(f"Port {port} is in use")
        with open("corrupted_data.json", "wb") as f:
            f.write(b"{data: invalid}")
        self.server_proc = subprocess.Popen(
            ["python", "server.py", "--test-mode", "--port", str(port), "--cipher", "4"],
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
        self.assertIn("Message received successfully", client_log)
        os.remove("corrupted_data.json")

if __name__ == '__main__':
    unittest.main()