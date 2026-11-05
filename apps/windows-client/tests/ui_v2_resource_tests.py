"""Build-resource contract only; real DPI/rendering needs Windows GUI."""
from pathlib import Path
import hashlib
import unittest

ROOT = Path(__file__).resolve().parents[3]

class ApprovedResourceTests(unittest.TestCase):
    def test_logo_is_exact_approved_original(self):
        logo = ROOT / 'apps/windows-client/src/approved-logo.png'
        self.assertEqual(hashlib.sha256(logo.read_bytes()).hexdigest(),
                         'df99eb880ba63c53e9657c1a8ba3f4224a71cf2e371b5d1e9e7c1cb9bae62ec1')

    def test_both_compilers_embed_icon_and_logo_without_duplicate_manifest(self):
        cmake = (ROOT / 'apps/windows-client/CMakeLists.txt').read_text()
        self.assertIn('src/brand.rc', cmake)
        self.assertIn('201 RCDATA "approved-logo.png"', (ROOT / 'apps/windows-client/src/brand.rc').read_text())
        self.assertIn('101 ICON "orangespace.ico"', (ROOT / 'apps/windows-client/src/brand.rc').read_text())
        self.assertNotIn('RT_MANIFEST', (ROOT / 'apps/windows-client/src/brand.rc').read_text())

if __name__ == '__main__':
    unittest.main()
