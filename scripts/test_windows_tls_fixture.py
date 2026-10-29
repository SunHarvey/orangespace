"""Portable lifecycle regressions; no SSH, TLS or Windows host required."""
import contextlib
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import smoke_windows_tls_rejection as fixture


class WindowsTlsFixtureTests(unittest.TestCase):
    def run_fixture(self, *, fail=None, cleanup_stdout='Windows fallback cleanup verified\n'):
        events = []
        listener = MagicMock()
        listener.getsockname.return_value = ('127.0.0.1', 12345)
        listener.accept.return_value = (MagicMock(), ('127.0.0.1', 1))
        context = MagicMock()
        context.wrap_socket.return_value.__enter__.return_value.recv.return_value = b''

        def thread_factory(*, target, daemon):
            thread = MagicMock()
            thread.start.side_effect = lambda: (events.append('start'), target())
            thread.is_alive.return_value = False
            return thread

        def run(command, **kwargs):
            if command[0] in ('scp', 'ssh'):
                events.append(command)
                if fail:
                    fail(command, events)
            return subprocess.CompletedProcess(command, 0, stdout=cleanup_stdout)

        output = io.StringIO()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'input'
            path.touch()
            argv = ['fixture', '--ssh-target', 'fixture@host', '--identity', str(path),
                    '--known-hosts', str(path), '--bind-ip', '127.0.0.1',
                    '--test-executable', str(path)]
            with patch.object(sys, 'argv', argv), patch.object(fixture.subprocess, 'run', side_effect=run), \
                    patch.object(fixture.socket, 'socket', return_value=listener), \
                    patch.object(fixture.ssl, 'SSLContext', return_value=context), \
                    patch.object(fixture.threading, 'Thread', side_effect=thread_factory), \
                    contextlib.redirect_stdout(output):
                try:
                    fixture.main()
                except Exception as error:
                    return events, output.getvalue(), error
        return events, output.getvalue(), None

    def test_windows_cmd_marker_whitespace_is_accepted(self):
        _, output, error = self.run_fixture(cleanup_stdout='Windows fallback cleanup verified \r\n')
        self.assertIsNone(error)
        self.assertIn('"ok": true', output)

    def test_native_error_is_captured_before_exception_arguments(self):
        source = (Path(__file__).resolve().parents[1] / 'apps/windows-client/src/node_session_win.cpp').read_text()
        self.assertRegex(source, r'const DWORD error = GetLastError\(\);\s+throw std::system_error\(static_cast<int>\(error\)')

    def test_accept_deadline_starts_only_after_both_uploads(self):
        events, output, error = self.run_fixture()
        self.assertIsNone(error)
        uploads = [index for index, event in enumerate(events) if isinstance(event, list) and event[0] == 'scp']
        self.assertEqual(len(uploads), 2)
        self.assertGreater(events.index('start'), max(uploads))
        self.assertIn('"ok": true', output)

    def test_timeout_fallback_removes_and_verifies_all_exact_paths(self):
        def timeout_primary(command, events):
            if command[0] == 'ssh' and '-File' in command[-1]:
                raise subprocess.TimeoutExpired(command, 40)

        events, output, error = self.run_fixture(fail=timeout_primary)
        self.assertIsInstance(error, subprocess.TimeoutExpired)
        self.assertEqual(output, '')
        cleanup = events[-1][-1]
        self.assertTrue(cleanup.startswith('cmd /d /c '))
        executable = next(event[-1].split(':', 1)[1] for event in events if isinstance(event, list) and event[0] == 'scp')
        tag = executable.removesuffix('.exe')
        self.assertIn('rmdir /s /q C:\\' + tag, cleanup)
        for path in ('C:\\' + tag, executable, tag + '.ps1'):
            self.assertIn('(if exist ' + path + ' exit /b 1)', cleanup)
        self.assertIn('del /f /q ' + executable + ' ' + tag + '.ps1', cleanup)
        self.assertNotIn('*', cleanup)
        self.assertNotIn('?', cleanup)

    def test_cleanup_without_verification_cannot_emit_success(self):
        _, output, error = self.run_fixture(cleanup_stdout='')
        self.assertIsInstance(error, RuntimeError)
        self.assertEqual(output, '')

    def test_cleanup_timeout_cannot_emit_success(self):
        def timeout_cleanup(command, events):
            if command[0] == 'ssh' and command[-1].startswith('cmd /d /c '):
                raise subprocess.TimeoutExpired(command, 20)

        _, output, error = self.run_fixture(fail=timeout_cleanup)
        self.assertIsInstance(error, subprocess.TimeoutExpired)
        self.assertEqual(output, '')

    def test_interrupted_uploads_still_cleanup_without_starting_accept(self):
        for interrupted_upload in (1, 2):
            with self.subTest(upload=interrupted_upload):
                def timeout_upload(command, events):
                    uploads = sum(isinstance(event, list) and event[0] == 'scp' for event in events)
                    if command[0] == 'scp' and uploads == interrupted_upload:
                        raise subprocess.TimeoutExpired(command, 30)

                events, output, error = self.run_fixture(fail=timeout_upload)
                self.assertIsInstance(error, subprocess.TimeoutExpired)
                self.assertEqual(output, '')
                self.assertNotIn('start', events)
                self.assertEqual(events[-1][0], 'ssh')
                self.assertTrue(events[-1][-1].startswith('cmd /d /c '))

    def test_cleanup_failure_cannot_emit_success(self):
        def fail_cleanup(command, events):
            if command[0] == 'ssh' and '-File' not in command[-1]:
                raise subprocess.CalledProcessError(1, command)

        _, output, error = self.run_fixture(fail=fail_cleanup)
        self.assertIsInstance(error, subprocess.CalledProcessError)
        self.assertEqual(output, '')


if __name__ == '__main__':
    unittest.main()
