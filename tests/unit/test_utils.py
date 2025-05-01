import logging
import os
import time
import unittest
from unittest.mock import patch
import socket
from src.utils import DEFAULT_IP, DEFAULT_PORT, setup_logging
from src.network import receive_exact, handle_session_timeout, BaseNetwork

class TestUtils(unittest.TestCase):
    """
    Unit tests for utility functions in the QuantumTLS prototype.
    Tests logging setup, data reception, and session timeout handling.
    """

    @classmethod
    def setUpClass(cls):
        """
        Set up the logger once before all tests.
        """
        cls.logger = setup_logging("test", "test.log", logging.DEBUG)

    @classmethod
    def tearDownClass(cls):
        """
        Clean up by closing logger handlers and removing the log file after all tests.
        """
        for handler in cls.logger.handlers:
            handler.close()  # Close all handlers to release the file
        if os.path.exists("test.log"):
            os.remove("test.log")  # Remove the log file

    def test_setup_logging(self):
        """
        Test the setup_logging function.
        Verifies logger level and handler count.
        """
        # logger = setup_logging("test", "test.log", logging.DEBUG)
        self.assertEqual(self.logger.level, logging.DEBUG, "Logger level should be DEBUG")
        self.assertEqual(len(self.logger.handlers), 2, "Logger should have 2 handlers (file and console)")

    @patch('socket.socket.recv')
    def test_receive_exact(self, mock_recv):
        """
        Test the receive_exact function with mocked socket receive.
        Ensures exact byte count is received in chunks.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        mock_recv.side_effect = [b'hel', b'lo']  # Simulate receiving "hello" in two parts
        data = receive_exact(sock, 5)
        self.assertEqual(data, b'hello', "Should receive exactly 'hello'")
        sock.close()

    def test_handle_session_timeout(self):
        """
        Test the handle_session_timeout function.
        Verifies timeout detection and session termination.
        """
        class MockNetwork(BaseNetwork):
            def __init__(self):
                super().__init__(DEFAULT_IP, DEFAULT_PORT, logging.getLogger('test'))
            def end_session(self, msg):
                self.logger.info(msg)

        network = MockNetwork()
        last_activity = time.time() - 40  # 40 seconds ago
        result = handle_session_timeout(network, last_activity, 30)  # 30-second timeout
        self.assertTrue(result, "Session should timeout after 40s with 30s limit")

if __name__ == '__main__':
    unittest.main()