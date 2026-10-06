import importlib
import logging
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from src.utils.errors import TLSError
from src.utils.utils import Reader, vector, setup_logging, close_logging


class TestUtils(unittest.TestCase):
    def test_reader_enforces_nested_lengths_and_trailing_bytes(self):
        for raw in (b'', b'\x00', b'\x00\x02a'):
            with self.assertRaises(ValueError):
                Reader(raw).vector()
        reader = Reader(vector(b'a') + b'extra')
        self.assertEqual(reader.vector(), b'a')
        with self.assertRaises(ValueError):
            reader.finish()

    def test_exception_has_no_network_side_effect(self):
        from unittest.mock import Mock
        network = Mock()
        error = TLSError('original', 50, network=network)
        self.assertEqual(str(error), 'original')
        self.assertFalse(network.mock_calls)

    def test_logging_creates_directories_bounds_handlers_and_rotates(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'nested' / 'log.txt'
            logger = setup_logging('qtl.test.rotation', str(path))
            self.addCleanup(close_logging, logger)
            for _ in range(3):
                logger = setup_logging('qtl.test.rotation', str(path))
            self.assertEqual(len(logger.handlers), 2)
            self.assertEqual(logger.level, logging.INFO)
            rotating = logger.handlers[0]
            self.assertEqual(rotating.maxBytes, 2 * 1024 * 1024)
            self.assertEqual(rotating.backupCount, 3)
            logger.info('metadata only')
            self.assertTrue(path.exists())

    def test_imports_do_not_create_credentials_or_logs(self):
        from unittest.mock import patch
        modules = ['src.generate_ca_certs', 'src.generate_client_certs',
                   'src.generate_client_expire_certs', 'src.generate_server_certs',
                   'src.client.main_client', 'src.server.main_server']
        with patch('src.utils.certificates.certificate_cli') as issue, patch('src.utils.utils.setup_logging') as logging_setup:
            for module in modules:
                importlib.reload(importlib.import_module(module))
        issue.assert_not_called()
        logging_setup.assert_not_called()
        for module in modules:
            importlib.reload(importlib.import_module(module))

    def test_file_input_reads_only_bounded_bytes(self):
        from unittest.mock import mock_open, patch
        from src.client.main_client import _get_message
        from src.utils.utils import MAX_MESSAGE_SIZE
        opened = mock_open(read_data=b'x' * (MAX_MESSAGE_SIZE + 1))
        with patch('builtins.open', opened), self.assertRaises(ValueError):
            _get_message('2', 'large.json')
        opened().read.assert_called_once_with(MAX_MESSAGE_SIZE + 1)

    def test_partial_stdin_cannot_extend_absolute_timeout(self):
        from unittest.mock import Mock, patch
        from src.client.main_client import timed_input
        stdin = Mock()
        stdin.fileno.return_value = 999
        with patch('src.client.main_client.sys.stdin', stdin), \
             patch('src.client.main_client.SESSION_TIMEOUT', 0.1), \
             patch('src.client.main_client.time.monotonic', side_effect=[0, 0.05, 0.11]), \
             patch('src.client.main_client.select.select', return_value=([stdin], [], [])), \
             patch('src.client.main_client.os.read', return_value=b'x'), \
             patch('builtins.print'):
            with self.assertRaises(TimeoutError):
                timed_input('Prompt')
