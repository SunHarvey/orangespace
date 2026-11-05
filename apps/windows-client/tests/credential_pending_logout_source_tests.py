"""Supplementary source boundaries only; native execution is a separate gate."""
from pathlib import Path
import unittest
ROOT = Path(__file__).parents[1]
STORE = (ROOT / 'src/credential_store_win.cpp').read_text()
MAIN = (ROOT / 'src/main_win.cpp').read_text()
class PendingWiring(unittest.TestCase):
    def test_load_save_fence_before_secrets(self):
        save = STORE.split('void CredentialStore::save(', 1)[1].split('NodeSession CredentialStore::load(', 1)[0]
        load = STORE.split('NodeSession CredentialStore::load(', 1)[1].split('void CredentialStore::erase(', 1)[0]
        for body, secret in ((save, 'session.credential_envelope()'), (load, 'directory.open(*found)')):
            self.assertIn('NodeLock lock(directory, *found, false)', body)
            self.assertLess(body.index('NodeLock lock'), body.index('require_not_pending'))
            self.assertLess(body.index('require_not_pending'), body.index(secret))
        self.assertIn('erase_pending(directory, *found)', STORE.split('void CredentialStore::erase(',1)[1])
    def test_close_preserves_saved_login(self):
        close = MAIN.split('void begin_close()',1)[1].split('void logout()',1)[0]
        self.assertNotIn('CredentialStore::', close)
        self.assertNotIn('logout_state_.begin', close)
    def test_ui_does_not_claim_missing_durability(self):
        self.assertNotIn('No durable marker API exists', MAIN)
        self.assertNotIn('强制结束后的恢复阻断尚未实现', MAIN)
        self.assertIn('未完成', MAIN)
if __name__ == '__main__':
    unittest.main()
