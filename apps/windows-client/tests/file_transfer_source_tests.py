"""Secondary source contracts; native Windows filesystem validation stays separate."""
from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[3]
class FileClientContracts(unittest.TestCase):
    def test_handle_relative_local_io(self):
        source = (ROOT / 'apps/windows-client/src/file_transfer_win.cpp').read_text()
        self.assertIn('#include "file_transfer_local_io_win.hpp"', source)
        self.assertIn('path.open_upload()', source)
        local = (ROOT / 'apps/windows-client/src/file_transfer_local_io_win.hpp').read_text()
        self.assertIn('NtCreateFile', local)
        self.assertIn('NtSetInformationFile', local)
        self.assertIn('RootDirectory=parent', local)
        self.assertIn('FILE_OPEN_REPARSE_POINT', local)
        self.assertIn('ReplaceIfExists=FALSE', local)
        self.assertNotIn('CreateFileW(temporary', local)

    def test_public_sdk_native_rename_class(self):
        local = (ROOT / 'apps/windows-client/src/file_transfer_local_io_win.hpp').read_text()
        # The public Microsoft SDK FILE_INFORMATION_CLASS omits this WDK name.
        # Keep native class 10 without depending on a MinGW-only enum member.
        self.assertNotIn(',FileRenameInformation)', local)
        self.assertIn('static_cast<FILE_INFORMATION_CLASS>(10)', local)

if __name__ == '__main__':
    unittest.main()
