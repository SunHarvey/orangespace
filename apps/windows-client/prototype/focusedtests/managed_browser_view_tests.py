"""Check window ownership and close wiring; native CEF behavior requires Win11."""
from pathlib import Path
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / "online_app.hpp").read_text()


class ManagedBrowserWindow(unittest.TestCase):
    def test_creates_top_level_window_inside_admitted_browser_process(self):
        init = SOURCE.split("void OnContextInitialized()", 1)[1]
        self.assertLess(init.index("if(!owner_)"), init.index("client_->OpenWindow()"))
        window = SOURCE.split("bool OpenWindow()", 1)[1].split("GetDialogHandler()", 1)[0]
        self.assertIn("WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN", window)
        self.assertIn("nullptr,nullptr,instance,this", window)
        self.assertIn("info.SetAsChild(window_,PageBounds())", window)
        self.assertIn("info.runtime_style=CEF_RUNTIME_STYLE_ALLOY", window)
        self.assertIn("CefBrowserHost::CreateBrowserSync", window)
        self.assertNotIn("ShowWindow", window)
        created = SOURCE.split("void OnAfterCreated", 1)[1].split("template<", 1)[0]
        self.assertIn("ShowWindow(window_,SW_SHOW)", created)

    def test_local_address_and_normal_cef_close(self):
        navigate = SOURCE.split("void Navigate()", 1)[1].split("AddressProc", 1)[0]
        self.assertLess(navigate.index("OnlineNavigation("), navigate.index("LoadURL("))
        self.assertIn("if(self->browser_&&!self->browser_->GetHost()->TryCloseBrowser())return 0;", SOURCE)
        closed = SOURCE.split("void OnBeforeClose", 1)[1].split("bool OnBeforePopup", 1)[0]
        self.assertLess(closed.index("browser_=nullptr"), closed.index("CefQuitMessageLoop()"))


if __name__ == "__main__":
    unittest.main()
