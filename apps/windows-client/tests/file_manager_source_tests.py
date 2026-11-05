"""Secondary native-source contracts; portable behavior lives in the C++ test."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/file_manager_win.cpp").read_text()

class FilePanelContracts(unittest.TestCase):
    def test_worker_never_calls_window_apis(self):
        worker = SOURCE.split("worker=std::thread([this]{", 1)[1].split("\n  void stop()", 1)[0]
        for forbidden in ("SendMessage", "PostMessage", "SetWindow", "MessageBox", "HWND"):
            self.assertNotIn(forbidden, worker)
        self.assertIn("job->client=std::make_shared<FileClient>(job->context)", worker)

    def test_logout_scrubs_only_after_nonblocking_drain(self):
        request = SOURCE.split("void FilePanel::request_logout()", 1)[1].split("void FilePanel::logout()", 1)[0]
        self.assertIn("++p.epoch", request)
        self.assertIn("j->cancel=true", request)
        self.assertIn("p.current={}", request)
        self.assertNotIn("p.stop()", request)
        self.assertNotIn("j->context={}", request)
        logout = SOURCE.split("void FilePanel::logout()", 1)[1].split("bool FilePanel::can_close", 1)[0]
        self.assertLess(logout.index("if(!can_close())return"), logout.index("p.stop()"))
        self.assertLess(logout.index("p.stop()"), logout.index("j->context={}"))
        self.assertIn("j->context={}", logout)
        self.assertIn("worker.join()", SOURCE)

    def test_explicit_no_clobber_label(self):
        self.assertIn("本机文件已存在，请选择其他保存位置", SOURCE)
        self.assertIn("ERROR_FILE_EXISTS", SOURCE)

    def test_return_to_browser_notifies_owner(self):
        self.assertTrue('PostMessageW(parent, ReturnToBrowserMessage, 0, 0)' in SOURCE,
                        'file back button must notify the owner view state')
        main = (ROOT / 'src/main_win.cpp').read_text()
        self.assertIn('case orangespace::files::ReturnToBrowserMessage:', main)

    def test_native_controls_and_exact_cancel(self):
        for control in ("WC_TREEVIEWW", "WC_LISTVIEWW", "LVS_EX_CHECKBOXES", "GetOpenFileNameW", "GetSaveFileNameW", "WM_DROPFILES"):
            self.assertIn(control, SOURCE)
        self.assertIn("if(id==Cancel)j->cancel=true", SOURCE)
        self.assertIn("std::make_shared<Job>(j->scope,j->kind,j->context)", SOURCE)

if __name__ == "__main__":
    unittest.main()
