import tempfile
import time
import subprocess
import socket
import os
import logging
from statistics import mean
import unittest
import tracemalloc
tracemalloc.start()

class TestPerformance(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger('perf_test')
        logging.basicConfig(level=logging.INFO)
        self.results = {}
        # Dynamically find an available port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('localhost', 0))  # 0 lets the OS assign a free port
            self.port = s.getsockname()[1]
        self.server_proc = None
        self.client_proc = None

    def tearDown(self):
        self.logger = logging.getLogger('perf_test')
        for proc in [self.server_proc, self.client_proc]:
            if proc and proc.poll() is None:  # Check if the process is still running
                self.logger.info(f"Terminating process {proc.pid}")
                proc.terminate()  # Send termination signal
                try:
                    proc.wait(timeout=10)  # Wait up to 10 seconds for graceful exit
                    self.logger.info(f"Process {proc.pid} terminated successfully")
                except subprocess.TimeoutExpired:
                    self.logger.warning(f"Process {proc.pid} did not terminate, forcing kill")
                    proc.kill()  # Force kill if it doesn’t terminate
                    proc.wait()  # Ensure it’s fully terminated
        self.server_proc = self.client_proc = None

    def run_test(self, cipher_suite, message_size=1024):
        # Select an available port
        for attempt in range(3):
            if not self.is_port_in_use(self.port):
                break
            self.logger.info(f"Port {self.port} is in use, selecting another port (attempt {attempt + 1}/3)")
            time.sleep(1)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('localhost', 0))
                self.port = s.getsockname()[1]
        else:
            self.skipTest("No available ports found after 3 attempts")

        # Create a temporary file for the message
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as temp_file:
            temp_file.write(b"A" * message_size)
            message_file_path = temp_file.name

        try:
            # Start the server subprocess
            self.server_proc = subprocess.Popen(
                ["python", "server.py", "--test-mode", "--port", str(self.port), "--cipher-suite", cipher_suite],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            # Allow server to start
            time.sleep(1)

            # Start the client subprocess with message-type=2
            self.client_proc = subprocess.Popen(
                ["python", "client.py", "--test-mode", "--port", str(self.port), "--message-type", "2", "--message", message_file_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            # Measure execution time
            start_time = time.perf_counter()
            self.client_proc.wait(timeout=20)
            duration = time.perf_counter() - start_time

            # Terminate server
            self.server_proc.terminate()

            # Extract handshake time from client log
            with open("client.log", "r") as f:
                client_log = f.read()
            handshake_time = float(client_log.split("Handshake completed in ")[1].split(" seconds")[0])

            return duration, handshake_time

        finally:
            # Clean up temporary file
            if os.path.exists(message_file_path):
                os.remove(message_file_path)

    def is_port_in_use(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('localhost', port)) == 0

    def test_benchmark_all_variants(self):
        suites = [
            "TLS_AES_256_GCM_SHA384",
            "TLS_AES_256_GCM_SHA384_Kyber512",
            "TLS_AES_256_GCM_SHA384_Kyber768",
            "TLS_AES_256_GCM_SHA384_Kyber1024"
        ]
        sizes = [1024, 1024 * 1024]  # 1KB and 1MB
        for suite in suites:
            for size in sizes:
                durations = []
                handshake_times = []
                for _ in range(3):  # 3 runs for averaging
                    total_time, hs_time = self.run_test(suite, size)
                    durations.append(total_time)
                    handshake_times.append(hs_time)
                avg_duration = mean(durations)
                avg_handshake = mean(handshake_times)
                throughput = size / avg_duration / 1024 / 1024  # MB/s
                self.logger.info(f"{suite} ({size} bytes): Throughput={throughput:.2f} MB/s, Handshake={avg_handshake:.6f}s, Total={avg_duration:.6f}s")
                self.results[f"{suite}_{size}"] = (throughput, avg_handshake, avg_duration)

    def test_network_conditions(self):
        import platform
        if platform.system() == "Windows":
            self.skipTest("Network conditions test not supported on Windows")
        os.system("./setup_network_conditions.sh")
        try:
            self.test_benchmark_all_variants()
        finally:
            os.system("sudo tc qdisc del dev lo root")

if __name__ == '__main__':
    unittest.main()