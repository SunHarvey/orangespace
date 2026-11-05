"""Exact bootstrap source-order contract; not native loader/sandbox evidence."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "bootstrap_prototype_win.cc").read_text()
BODY = SOURCE.split("CEF_BOOTSTRAP_EXPORT int RunWinMain", 1)[1]


class PinnedOfflineRuntimeTrust(unittest.TestCase):
    def test_committed_admission_precedes_runtime_loader(self):
        acquire = BODY.index("auto admission = orangespace::prototype::Admission::Acquire();")
        reject = BODY.index("if (!admission) {")
        rejection = BODY[reject:BODY.index("\n  }", reject)]
        self.assertIn("AdmissionFailureExitCode(", rejection)
        self.assertIn("return code;", rejection)
        loader = BODY.index("CefScopedLibraryLoader loader;")
        load = BODY.index("loader.LoadInMainAssert(")
        validate = BODY.index("result = CheckRuntime(")
        execute = BODY.index("CefExecuteProcess(")
        initialize = BODY.index("CefInitialize(")
        self.assertEqual([acquire, reject, loader, load, validate, execute, initialize],
                         sorted([acquire, reject, loader, load, validate, execute, initialize]))
        self.assertEqual(BODY.count("Admission::Acquire()"), 1)

    def test_unsigned_exception_requires_the_actual_admission_owner(self):
        self.assertIn("loader.LoadInMainAssert(library.c_str(), nullptr,\n"
                      "                                 static_cast<bool>(admission), &expected_info)", BODY)
        self.assertIn("Admission::LastFailureStage()", BODY)
        self.assertIn("settings.no_sandbox = false;", BODY)
        self.assertIn("settings.command_line_args_disabled = true;", BODY)
        self.assertIn('"no-sandbox", "disable-gpu-sandbox"', BODY)
        self.assertIn("if (version_info->installer_error_code || version_info->libcef_path)", BODY)
        self.assertNotIn("LoadLibraryW(", BODY)
        self.assertNotIn("LoadLibraryExW(", BODY)


if __name__ == "__main__":
    unittest.main()
