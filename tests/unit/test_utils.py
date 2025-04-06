import logging
import time
import unittest
from unittest.mock import patch
import socket
from utils import setup_logging, receive_exact, handle_session_timeout, BaseNetwork

class TestUtils(unittest.TestCase):
    def test_setup_logging(self):
        logger = setup_logging("test", "test.log", logging.DEBUG)
        self.assertEqual(logger.level, logging.DEBUG)
        self.assertEqual(len(logger.handlers), 2)

    @patch('socket.socket.recv')
    def test_receive_exact(self, mock_recv):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        mock_recv.side_effect = [b'hel', b'lo']
        data = receive_exact(sock, 5)
        self.assertEqual(data, b'hello')
        sock.close()  # Close the socket to prevent the warning

    def test_handle_session_timeout(self):
        class MockNetwork(BaseNetwork):
            def __init__(self): super().__init__(logging.getLogger('test'))
            def end_session(self, msg): self.logger.info(msg)
        network = MockNetwork()
        last_activity = time.time() - 40  # 40 seconds ago
        result = handle_session_timeout(network, last_activity, 30)
        self.assertTrue(result)

if __name__ == '__main__':
    unittest.main()