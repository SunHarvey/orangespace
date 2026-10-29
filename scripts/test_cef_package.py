"""Offline integrity tests; fixtures are NOT a CEF build or runtime."""
import importlib.util
import hashlib
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('cef_package.py')


class ArchiveIntegrityTests(unittest.TestCase):
    def test_archive_requires_both_exact_size_and_digest(self):
        self.assertTrue(SCRIPT.exists(), 'CEF archive verifier is not implemented')
        spec = importlib.util.spec_from_file_location('cef_package', SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / 'fixture'
            archive.write_bytes(b'not a runtime: integrity fixture')
            digest = hashlib.sha1(archive.read_bytes()).hexdigest()
            sha256 = hashlib.sha256(archive.read_bytes()).hexdigest()
            size = archive.stat().st_size
            module.verify_archive(archive, digest, size, sha256)
            with self.assertRaises(ValueError):
                module.verify_archive(archive, '0' * 40, size, sha256)
            with self.assertRaises(ValueError):
                module.verify_archive(archive, digest, size + 1, sha256)
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                module.verify_archive(archive, digest, size, '')


class PackageRootTests(unittest.TestCase):
    def test_exact_headers_and_nonempty_sandbox_bootstrap_required(self):
        spec = importlib.util.spec_from_file_location('cef_package', SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertTrue(hasattr(module, 'verify_root'), 'CEF root preflight is not implemented')
        lock = module.load_lock()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in module.REQUIRED_FILES:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'fixture only')
            header = root / 'include/cef_version.h'
            version = ('#define CEF_VERSION "' + lock['cef_version'] + '"\n'
                       '#define CEF_COMMIT_HASH "' + lock['cef_commit'] + '"\n'
                       '#define CEF_SANDBOX_COMPAT_HASH "' + lock['sandbox_compat'] + '"\n')
            header.write_text(version)
            api = root / 'include/cef_api_versions.h'
            api.write_text('#if defined(OS_WIN)\n#define CEF_API_HASH_15600 "' + lock['api_hash_windows'] + '"\n#endif\n')
            module.verify_root(root, lock)
            bootstrap = root / 'Release/bootstrap.exe'
            bootstrap.write_bytes(b'')
            with self.assertRaises(ValueError):
                module.verify_root(root, lock)
            bootstrap.write_bytes(b'fixture only')
            header.write_text(version.replace(lock['cef_version'], 'wrong-version'))
            with self.assertRaises(ValueError):
                module.verify_root(root, lock)
            header.write_text(version)
            api.write_text('#if defined(OS_WIN)\n#define CEF_API_HASH_15600 "' + '0' * 40 + '"\n#endif\n')
            with self.assertRaises(ValueError):
                module.verify_root(root, lock)


class ExtractionTests(unittest.TestCase):
    def test_extract_rejects_traversal_and_links_without_writing_destination(self):
        import io
        import tarfile
        spec = importlib.util.spec_from_file_location('cef_package', SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertTrue(hasattr(module, 'extract_verified'), 'safe extraction is not implemented')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for member_name, linked in [('package/../../escape', False), ('package/link', True)]:
                archive = root / 'package.tar.bz2'
                with tarfile.open(archive, 'w:bz2') as tar:
                    info = tarfile.TarInfo(member_name)
                    if linked:
                        info.type = tarfile.SYMTYPE
                        info.linkname = '../../escape'
                        tar.addfile(info)
                    else:
                        info.size = 1
                        tar.addfile(info, io.BytesIO(b'x'))
                lock = {'archive': archive.name, 'archive_sha1': hashlib.sha1(archive.read_bytes()).hexdigest(),
                        'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
                        'archive_size': archive.stat().st_size}
                with self.assertRaises(ValueError):
                    module.extract_verified(archive, root / 'destination', lock)
                self.assertFalse((root / 'destination').exists())
                self.assertFalse((root / 'escape').exists())


class SuccessfulExtractionTests(unittest.TestCase):
    def test_verified_fixture_is_promoted_once_without_merging(self):
        import tarfile
        spec = importlib.util.spec_from_file_location('cef_package', SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        lock = module.load_lock()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'fixture-source'
            for name in module.REQUIRED_FILES:
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'fixture, not CEF')
            (source / 'include/cef_version.h').write_text(
                '\n'.join('#define ' + macro + ' "' + value + '"' for macro, value in [
                    ('CEF_VERSION', lock['cef_version']), ('CEF_COMMIT_HASH', lock['cef_commit']),
                    ('CEF_SANDBOX_COMPAT_HASH', lock['sandbox_compat'])]) + '\n')
            (source / 'include/cef_api_versions.h').write_text(
                '#if defined(OS_WIN)\n#define CEF_API_HASH_15600 "' + lock['api_hash_windows'] + '"\n#endif\n')
            archive = root / 'fixture.tar.bz2'
            with tarfile.open(archive, 'w:bz2') as tar:
                tar.add(source, arcname='fixture')
            lock.update(archive=archive.name, archive_sha1=hashlib.sha1(archive.read_bytes()).hexdigest(),
                        archive_size=archive.stat().st_size)
            destination = root / 'extracted'
            bad_pin = {**lock, 'archive_sha256': '0' * 64}
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                module.extract_verified(archive, destination, bad_pin)
            self.assertFalse(destination.exists(), 'bad SHA-256 must fail before extraction')
            lock['archive_sha256'] = hashlib.sha256(archive.read_bytes()).hexdigest()
            module.extract_verified(archive, destination, lock)
            module.verify_root(destination, lock)
            with self.assertRaises(ValueError):
                module.extract_verified(archive, destination, lock)


if __name__ == '__main__':
    unittest.main()
