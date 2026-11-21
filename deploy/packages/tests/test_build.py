import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

SPEC = importlib.util.spec_from_file_location('package_build', Path(__file__).parents[1] / 'build.py')
assert SPEC is not None and SPEC.loader is not None
b = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(b)


class BuildPolicyTests(unittest.TestCase):
    def test_copy_ordinary_absolute_destination(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / 'a.txt'
            src.write_text('public')
            dst = Path(d) / 'out/a.txt'
            b.copy(src, dst)
            self.assertEqual(dst.read_text(), 'public')

    def test_member_traversal(self):
        for name in ['../x', '/x', 'a/../x', 'a\\b', 'C:x']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                b.safe_name(name)

    def test_secret_and_runtime_policy(self):
        for name, data in [('x.key', b'x'), ('Profile/x', b'x'), ('ok.txt', b'-----BEGIN PRIVATE KEY-----'),
                           ('ok.txt', b'mysql+pymysql://user:secret@real.invalid/db')]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                b.scan(name, data)
        b.scan('examples/example.json', b'{"database":"mysql+pymysql://USER:PASSWORD@mysql.example.invalid/db"}')

    def test_archive_link_duplicate_and_traversal(self):
        for name, typ in [('ok', tarfile.SYMTYPE), ('../bad', tarfile.REGTYPE)]:
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode='w') as t:
                m = tarfile.TarInfo(name); m.type = typ
                t.addfile(m)
            with self.assertRaises(ValueError):
                b.checked_archive(stream.getvalue(), 'tar')

    def test_wheelhouse_hash_and_versions(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); wheels = root / 'wheels'; wheels.mkdir()
            data = io.BytesIO()
            with zipfile.ZipFile(data, 'w') as z:
                z.writestr('demo-1.0.dist-info/METADATA', 'Name: demo\nVersion: 1.0\n')
            (wheels / 'demo.whl').write_bytes(data.getvalue())
            manifest = root / 'hashes.json'
            manifest.write_text(json.dumps({'demo.whl': b.digest(data.getvalue())}))
            lock = b.wheelhouse(wheels, manifest, {'demo': '1.0'}, root / 'out')
            self.assertIn('--hash=sha256:', lock.read_text())
            with self.assertRaises(ValueError):
                b.wheelhouse(wheels, manifest, {'demo': '2.0'}, root / 'out2')
            manifest.write_text(json.dumps({'demo.whl': '0' * 64}))
            with self.assertRaises(ValueError):
                b.wheelhouse(wheels, manifest, {'demo': '1.0'}, root / 'out3')

    def test_compatible_node_tools_record_not_reject_installed_variants(self):
        for node, npm in [('v26.7.0', '12.0.2'), ('v26.11.1', '11.20.0')]:
            self.assertTrue(b.node_tools_compatible(node, npm))
        self.assertFalse(b.node_tools_compatible('v24.0.0', '12.0.2'))

    def test_public_examples_complete_and_scannable(self):
        for role, required in [('node', {'examples/database.example.json', 'server/alembic-node.ini',
                                        'deploy/linux-node/node-a.runtime.example.json'})]:
            with tempfile.TemporaryDirectory() as d:
                b.package_examples(role, Path(d))
                files = {p.relative_to(d).as_posix() for p in Path(d).rglob('*') if p.is_file()}
                self.assertTrue(required <= files)
                for name in files:
                    b.scan(name, (Path(d) / name).read_bytes())

    def test_pins_and_unified_backend_contract(self):
        self.assertEqual(b.PIN['helper']['version'], '1.14.4')
        self.assertEqual(b.PIN['python_build']['hatchling'], '1.27.0')
        self.assertIn('npm', b.PIN)
        self.assertEqual(b.TEMP, Path('/var/tmp/hermes-runtime/tmp'))


if __name__ == '__main__':
    unittest.main()
