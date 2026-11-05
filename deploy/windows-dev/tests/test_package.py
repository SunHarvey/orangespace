import importlib.util
import json
from pathlib import Path
import tempfile
import hashlib
from unittest.mock import patch
import unittest

MODULE = Path(__file__).parents[1] / 'package.py'
spec = importlib.util.spec_from_file_location('package_policy', MODULE)
assert spec is not None and spec.loader is not None
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)

class PackageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.src = self.root / 'source'
        self.src.mkdir()
        # Deliberately NOT a real helper; only rejection cases use it.
        for name in p.NAMES:
            (self.src / name).write_bytes(b'MZ-test-not-native')

    def test_rejects_unknown_files_including_secrets(self):
        for name in ['credentials.json', 'Profile', 'local.db', 'key.pem', 'run.log', 'extra.exe']:
            extra = self.src / name
            extra.write_text('fixture')
            with self.assertRaises(ValueError):
                p.inventory(self.src)
            extra.unlink()

    def test_rejects_root_and_ancestor_reparse_attributes(self):
        from types import SimpleNamespace
        original = Path.lstat
        for rejected in (self.src, self.root):
            def fake(path, *args, **kwargs):
                s = original(path, *args, **kwargs)
                if path == rejected:
                    return SimpleNamespace(st_mode=s.st_mode, st_file_attributes=0x400)
                return s
            with self.subTest(rejected=rejected), patch.object(Path, 'lstat', fake):
                with self.assertRaisesRegex(ValueError, 'directory'):
                    p.inventory(self.src)

    def test_rejects_hardlink(self):
        import os
        leaf = self.src / p.NAMES[0]
        os.link(leaf, self.root / 'alias')
        with self.assertRaisesRegex(ValueError, 'unique ordinary'):
            p.inventory(self.src)

    def test_rejects_extra_directory(self):
        (self.src / 'extraDir').mkdir()
        with self.assertRaisesRegex(ValueError, 'unexpected'):
            p.inventory(self.src)

    def test_equal_cardinality_duplicate_and_traversal(self):
        rows = [dict(name=n, size=1, sha256=p.HELPER_SHA256) for n in p.NAMES]
        for name in (p.NAMES[1], '../x'):
            bad = [dict(r) for r in rows]
            bad[0]['name'] = name
            self.assertEqual(len(bad), len(p.NAMES))
            with self.assertRaisesRegex(ValueError, 'allowlist'):
                p.validate_rows(bad)

    def test_rejects_unpinned_helper(self):
        with self.assertRaisesRegex(ValueError, 'helper'):
            p.inventory(self.src)

    def test_rejects_symlink(self):
        leaf = self.src / p.NAMES[0]
        leaf.unlink()
        leaf.symlink_to(self.src / p.NAMES[1])
        with self.assertRaises(ValueError):
            p.inventory(self.src)

    def test_rejects_existing_target_before_write(self):
        with self.assertRaises(FileExistsError):
            p.create(self.src, self.src)

    def test_injected_digest_model_roundtrip_and_tamper(self):
        # Explicit injected policy seam, never an approved Windows helper/package.
        digest = hashlib.sha256(b'MZ-test-not-native').hexdigest()
        target = self.root / 'owned-model-package'
        with patch.object(p, 'HELPER_SHA256', digest):
            m = p.create(self.src, target)
            self.assertEqual(len(m['files']), 5)
            self.assertEqual(p.verify(target), m)
            (target / p.NAMES[0]).write_bytes(b'MZ-tampered')
            with self.assertRaisesRegex(ValueError, 'mismatch'):
                p.verify(target)
            (target / 'credentials.json').write_text('fixture')
            with self.assertRaises(ValueError):
                p.verify(target)

    def test_manifest_rejects_missing_extra_duplicate_traversal_hash_size(self):
        # Test the real metadata validator without forging an approved helper.
        rows = [dict(name=n, size=1, sha256=p.HELPER_SHA256) for n in p.NAMES]
        p.validate_rows(rows)
        mutations = [rows[:-1], rows + [rows[0]], rows + [dict(name='../x',size=1,sha256='0'*64)],
                     [dict(r, size=-1) for r in rows], [dict(r, sha256='X'*64) for r in rows]]
        for bad in mutations:
            with self.assertRaises(ValueError):
                p.validate_rows(bad)

    def test_custom_identity_exact_manifest_and_binary_provenance(self):
        # Injected PE-byte policy fixture, not a native executable or SCM proof.
        suffix='ui-v2-p1'
        name='OrangeSpaceFoundation.Dev.'+suffix
        pipe=r'\\.\pipe\OrangeSpace.Foundation.Dev.'+suffix+'.v1.session.'
        record=('OrangeSpace.InstallIdentity.v1|'+suffix+'|'+name+'\0'+pipe+'\0').encode('utf-16le')
        for binary in p.NAMES[:3]:
            (self.src/binary).write_bytes(b'MZ'+record)
        digest=hashlib.sha256((self.src/'sing-box.exe').read_bytes()).hexdigest()
        target=self.root/'custom'
        with patch.object(p,'HELPER_SHA256',digest):
            manifest=p.create(self.src,target,development_install_id=suffix)
            self.assertEqual(manifest['service_name'],name)
            self.assertEqual(manifest['pipe_prefix'],pipe)
            self.assertEqual(p.verify(target),manifest)
            for fields in [
                {'schema','kind','files'},
                {'schema','kind','files','development_install_id'},
            ]:
                (target/'manifest.json').write_text(json.dumps({k:v for k,v in manifest.items() if k in fields}))
                with self.assertRaises(ValueError):p.verify(target)
            for changes in [dict(service_name='WinDefend'),dict(pipe_prefix=r'\\.\pipe\other'),dict(development_install_id='UPPER'),dict(extra=True)]:
                (target/'manifest.json').write_text(json.dumps(dict(manifest,**changes)))
                with self.assertRaises(ValueError):p.verify(target)

    def test_custom_identity_refuses_missing_or_mixed_binary_namespace(self):
        digest=hashlib.sha256((self.src/'sing-box.exe').read_bytes()).hexdigest()
        with patch.object(p,'HELPER_SHA256',digest):
            with self.assertRaises(ValueError):p.create(self.src,self.root/'missing',development_install_id='p1')
            self.assertFalse((self.root/'missing').exists())
            for suffix in ['../x','UPPER','x'*25,'with space']:
                with self.assertRaises(ValueError):p.create(self.src,self.root/'bad',development_install_id=suffix)
                self.assertFalse((self.root/'bad').exists())
            for binary,suffix in zip(p.NAMES[:3],['p1','p1','other']):
                record=('OrangeSpace.InstallIdentity.v1|'+suffix+'|OrangeSpaceFoundation.Dev.'+suffix+'\0'+r'\\.\pipe\OrangeSpace.Foundation.Dev.'+suffix+'.v1.session.\0').encode('utf-16le')
                (self.src/binary).write_bytes(b'MZ'+record)
            with self.assertRaises(ValueError):p.create(self.src,self.root/'mixed',development_install_id='p1')
            self.assertFalse((self.root/'mixed').exists())

if __name__ == '__main__':
    unittest.main()
