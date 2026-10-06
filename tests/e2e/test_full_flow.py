"""Real CLI processes, disposable credentials, exact payload assertions."""
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import time
from src.utils.certificates import generate_leaf
from tests.support import CredentialsTest

ROOT = Path(__file__).resolve().parents[2]


class TestFullFlow(CredentialsTest):
    def setUp(self):
        super().setUp()
        self.env = {**os.environ, 'PYTHONPATH': str(ROOT)}
        self.index = 0

    def cli_server(self, *options):
        self.index += 1
        logdir = self.directory / ('server-logs-' + str(self.index))
        output = (self.directory / ('server-output-' + str(self.index))).open('wb')
        self.addCleanup(output.close)
        process = subprocess.Popen([sys.executable, '-m', 'src.server.main_server', '--port', '0',
                                    '--cert-dir', str(self.directory), '--log-dir', str(logdir), *options],
                                   cwd=self.directory, env=self.env, stdout=output, stderr=output)
        def stop():
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=7)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
                    self.fail('Server shutdown exceeded deadline')
        self.addCleanup(stop)
        until = time.monotonic() + 10
        while time.monotonic() < until:
            path = logdir / 'server.log'
            if path.exists():
                match = re.search(r'Listening on .*:(\d+)', path.read_text())
                if match:
                    return process, int(match.group(1)), logdir
            if process.poll() is not None:
                self.fail('Server startup failed: ' + path.read_text() if path.exists() else 'No server log')
            time.sleep(0.02)
        self.fail('Server did not become ready')

    def cli_client(self, port, *options, cert_dir=None):
        self.index += 1
        return subprocess.run([sys.executable, '-m', 'src.client.main_client', '--port', str(port),
                               '--cert-dir', str(cert_dir or self.directory), '--log-dir', str(self.directory / ('client-logs-' + str(self.index))),
                               '--test-mode', *options], cwd=self.directory, env=self.env,
                              capture_output=True, text=True, timeout=10)

    def test_text_empty_exit_and_no_plaintext_logging(self):
        _, port, logs = self.cli_server()
        for text in ('sensitive-payload-do-not-log-9182', '', 'END_SESSION'):
            result = self.cli_client(port, '--message-type', '1', '--message', text)
            self.assertEqual(result.returncode, 0, result.stderr)
            if text:
                self.assertNotIn(text, result.stderr)
                self.assertNotIn(text, (logs / 'server.log').read_text())
        result = self.cli_client(port, '--message-type', '3')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_large_file_exact_echo_and_mutual_auth(self):
        _, port, _ = self.cli_server('--mutual-auth', 'enable', '--echo')
        path = self.directory / 'large.json'
        path.write_text('{"data":"' + 'a' * 150000 + '"}')
        result = self.cli_client(port, '--mutual-auth', 'enable', '--expect-echo', '--message-type', '2', '--message', str(path))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Verified response for 150011-byte', result.stderr)

    def test_expired_credentials_fail_without_altering_issuer_directory(self):
        _, port, _ = self.cli_server('--mutual-auth', 'enable')
        generate_leaf(self.directory, 'client', expired=True)
        fixture = self.directory / 'expired-fixture'
        fixture.mkdir()
        for source, target in (('ca.crt', 'ca.crt'), ('expired_client.crt', 'client.crt'), ('expired_client.key', 'client.key')):
            shutil.copyfile(self.directory / source, fixture / target)
        original = (self.directory / 'client.key').read_bytes()
        result = self.cli_client(port, '--mutual-auth', 'enable', '--message-type', '1', '--message', 'test', cert_dir=fixture)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('expired', result.stderr)
        self.assertEqual(original, (self.directory / 'client.key').read_bytes())

    def test_interrupt_and_wrong_host_exit_nonzero(self):
        _, port, _ = self.cli_server('--test-mode', '--test-interrupt')
        result = self.cli_client(port, '--message-type', '1', '--message', 'test')
        self.assertNotEqual(result.returncode, 0)
        result = self.cli_client(port, '--server-name', 'wrong.invalid', '--message-type', '1', '--message', 'test')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('identity mismatch', result.stderr)

    def test_restart_same_port_after_active_shutdown(self):
        process, port, _ = self.cli_server()
        result = self.cli_client(port, '--message-type', '1', '--message', 'before restart')
        self.assertEqual(result.returncode, 0, result.stderr)
        idle = socket.create_connection(('127.0.0.1', port), timeout=2)
        self.addCleanup(idle.close)
        process.terminate()
        process.wait(timeout=7)
        self.assertEqual(process.returncode, 0)
        self.assertEqual(idle.recv(1), b'')
        _, reused, _ = self.cli_server('--port', str(port))
        self.assertEqual(reused, port)
        result = self.cli_client(port, '--message-type', '1', '--message', 'after restart')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_trust_root_and_identity_fail_nonzero(self):
        empty = self.directory / 'empty'
        empty.mkdir()
        for module in ('src.client.main_client', 'src.server.main_server'):
            result = subprocess.run([sys.executable, '-m', module, '--cert-dir', str(empty), '--log-dir', str(empty / 'logs')],
                                    cwd=self.directory, env=self.env, capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('trust root', result.stderr)

    def test_concurrent_clients(self):
        from concurrent.futures import ThreadPoolExecutor
        _, port, _ = self.cli_server('--echo')
        # Separate output directories avoid shared process log handlers.
        def run(index):
            return subprocess.run([sys.executable, '-m', 'src.client.main_client', '--port', str(port),
                                   '--cert-dir', str(self.directory), '--log-dir', str(self.directory / f'parallel-{index}'),
                                   '--test-mode', '--message-type', '1', '--message', f'parallel-{index}', '--expect-echo'],
                                  cwd=self.directory, env=self.env, capture_output=True, text=True, timeout=10)
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(run, range(4)))
        for result in results:
            self.assertEqual(result.returncode, 0, result.stderr)
