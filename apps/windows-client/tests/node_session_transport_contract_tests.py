"""Supplementary transport source guard; native HTTPS remains a separate gate."""
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "src" / "node_session_win.cpp"

class TransportContract(unittest.TestCase):
    def test_bearer_scheme_not_placeholder(self):
        source = SOURCE.read_text()
        self.assertIn('L"Authorization: Bearer "', source)
        self.assertNotIn('Authorization: ***', source)

    def test_no_certificate_ignore_option_and_revocation_retained(self):
        source = SOURCE.read_text()
        self.assertIn("DWORD revocation = WINHTTP_ENABLE_SSL_REVOCATION", source)
        self.assertNotIn("WINHTTP_OPTION_SECURITY_FLAGS,", source)
        self.assertIn("DWORD policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER", source)

    def test_store_uses_current_user_folder_and_handle_relative_native_rename(self):
        source = (SOURCE.parent / "credential_store_win.cpp").read_text()
        self.assertIn("KF_FLAG_DEFAULT, nullptr, &folder", source)
        self.assertIn('"NtSetInformationFile"', source)
        self.assertIn('"NtCreateFile"', source)
        self.assertIn("FILE_LIST_DIRECTORY", source)
        self.assertNotIn("CRYPTPROTECT_LOCAL_MACHINE", source)
        self.assertNotIn("if (!promoted) purge", source)

if __name__ == "__main__":
    unittest.main()
