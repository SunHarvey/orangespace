"""Supplementary wiring checks; not native Windows/HTTPS acceptance."""
from pathlib import Path
import unittest
MAIN = (Path(__file__).parents[1] / 'src/main_win.cpp').read_text()

class Wiring(unittest.TestCase):
    def test_no_detached_cleanup_or_worker(self):
        self.assertTrue('.detach()' not in MAIN, 'detached UI work remains')
        self.assertTrue('release_grant' not in MAIN, 'unawaited grant cleanup remains')

    def test_close_uses_retirement_not_remote_logout(self):
        for required in ('sc::retire(*grant)', 'case WM_QUERYENDSESSION:',
                         'case WM_ENDSESSION:', 'finish_before_return()'):
            self.assertTrue(required in MAIN, f'missing lifecycle wiring: {required}')

    def test_restore_checks_pending_logout_gate(self):
        self.assertTrue('logout_state_.restore_blocked()' in MAIN)
        self.assertTrue('本机登录已清除；服务撤权与服务器退出已提交' not in MAIN)

    def test_stale_tunnel_cleanup_retains_owner(self):
        self.assertTrue('pending_stops_' in MAIN)
        self.assertTrue('retry_stops()' in MAIN)

    def test_cursor_hints_not_reset_on_logout(self):
        self.assertTrue('cursors_.clear()' not in MAIN)

if __name__ == '__main__':
    unittest.main()
