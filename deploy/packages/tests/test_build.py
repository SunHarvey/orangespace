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
    def test_development_install_identity(self):
        self.assertTrue(callable(getattr(b, 'install_identity', None)), 'build identity missing')
        for suffix in ['', 'a', 'dev-2026', 'a' * 24]:
            identity = b.install_identity(suffix)
            self.assertEqual(identity['development_install_id'], suffix)
            self.assertEqual(identity['service_name'], 'OrangeSpaceFoundation' + ('.Dev.' + suffix if suffix else ''))
            self.assertEqual(identity['pipe_prefix'], r'\\.\pipe\OrangeSpace.Foundation' + ('.Dev.' + suffix if suffix else '') + '.v1.session.')
            commands = b.gnu_commands(Path('/fresh'), Path('/fresh/rust'), suffix)
            self.assertIn('-DORANGESPACE_DEVELOPMENT_INSTALL_ID=' + suffix, commands[1])
        for suffix in ['A', 'a_b', 'a/b', 'a.b', 'a' * 25, 'é', "x'", 'x\n']:
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                b.install_identity(suffix)

    def test_shared_cpp_install_identity(self):
        import subprocess
        root = Path(__file__).parents[3]
        with tempfile.TemporaryDirectory() as d:
            source = Path(d) / 'identity.cpp'
            source.write_text('#include "orangespace/install_identity.hpp"\n#include <iostream>\nint main(){std::wcout << orangespace::install_identity::service_name << L"\\n" << orangespace::install_identity::pipe_prefix;}\n')
            for suffix in ['', 'dev-1', 'a' * 24, 'A', 'x' * 25, 'a_b']:
                exe = Path(d) / 'identity'
                cmd = ['g++', '-std=c++20', '-I' + str(root / 'apps/windows-service/include'),
                       '-DORANGESPACE_DEVELOPMENT_INSTALL_ID="' + suffix + '"', str(source), '-o', str(exe)]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if suffix in ['A', 'x' * 25, 'a_b']:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('Invalid development install identity', result.stderr)
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    result = subprocess.check_output([str(exe)], text=True)
                    identity = b.install_identity(suffix)
                    self.assertEqual(result, identity['service_name'] + '\n' + identity['pipe_prefix'])

    def test_protected_namespace_selection_before_scm(self):
        root = Path(__file__).parents[3]
        common = (root / 'deploy/windows-dev/Common.ps1').read_text()
        service = (root / 'deploy/windows-dev/Service.ps1').read_text()
        self.assertIn('function Select-InstallIdentity', common)
        self.assertIn('Binary namespace provenance mismatch', common)
        self.assertIn('Identity must be selected from a protected manifest', common)
        self.assertNotIn('Name=\'OrangeSpaceFoundation\'', common)
        self.assertLess(service.index('$manifest = Get-Manifest $Package'), service.index('Read-Service'))
        self.assertIn('$marker.manifestHash', common)
        self.assertIn('$marker.service -cne $script:ServiceName', common)
        self.assertIn('Existing target refused; no overwrite or adoption', service)

    def test_copy_ordinary_absolute_destination(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / 'a.txt'
            src.write_text('public')
            dst = Path(d) / 'out/a.txt'
            b.copy(src, dst)
            self.assertEqual(dst.read_text(), 'public')

    def test_cargo_hardlinked_broker_is_materialized_before_trusted_copy(self):
        with tempfile.TemporaryDirectory() as d:
            work = Path(d)
            recorded = []
            def compiler(command, cwd=None):
                recorded.append(command)
                if command[:3] == ['rustup', 'target', 'list']:
                    return 'x86_64-pc-windows-gnu'
                if command[:2] == ['cargo', 'build']:
                    release = work / 'rust/x86_64-pc-windows-gnu/release'
                    (release / 'deps').mkdir(parents=True)
                    broker = release / 'orangespace-broker.exe'
                    broker.write_bytes(b'compiled broker')
                    (release / 'deps/broker.exe').hardlink_to(broker)
                    self.assertEqual(broker.stat().st_nlink, 2)
                    with self.assertRaises(ValueError):
                        b.ordinary(broker)
                    with self.assertRaises(ValueError):
                        b.copy(broker, work / 'external-copy.exe')
                if command[:2] == ['cmake', '--build']:
                    for name in ['windows-client/OrangeSpace.exe', 'windows-client/OrangeSpaceLogin.exe',
                                 'windows-service/OrangeSpaceService.exe']:
                        p = work / 'native/apps' / name
                        p.parent.mkdir(parents=True, exist_ok=True)
                        p.write_bytes(b'compiled native')
                if command[:2] == ['x86_64-w64-mingw32-objdump', '-p']:
                    return 'DLL Name: KERNEL32.dll'
                return 'fixture version'
            with patch.object(b, 'run', side_effect=compiler), patch.object(b, 'windows_helper', return_value=b'helper'):
                b.windows_gnu(work / 'deps', work / 'stage', work, {}, 'p1')
            create = [c for c in recorded if len(c)>2 and str(c[1]).endswith('/package.py') and c[2]=='create']
            self.assertEqual(len(create),1)
            self.assertEqual(create[0][-2:],['--development-install-id','p1'])
            staged = work / 'exact-programs/orangespace-broker.exe'
            self.assertEqual(b.ordinary(staged), b'compiled broker')
            self.assertEqual(staged.stat().st_nlink, 1)
            self.assertEqual((work / 'rust/x86_64-pc-windows-gnu/release/orangespace-broker.exe').stat().st_nlink, 2)

    def test_rust_broker_materialization_refuses_links_escape_and_stale_stage(self):
        for kind in ['leaf-link', 'ancestor-link', 'work-link', 'directory', 'stale-stage']:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                work = root / 'work'
                work.mkdir()
                release = work / 'rust/x86_64-pc-windows-gnu/release'
                release.mkdir(parents=True)
                source = release / 'orangespace-broker.exe'
                outside = root / 'outside.exe'
                outside.write_bytes(b'not compiler output')
                if kind == 'leaf-link':
                    source.symlink_to(outside)
                elif kind == 'ancestor-link':
                    release.rmdir()
                    release.symlink_to(root, target_is_directory=True)
                    (root / source.name).write_bytes(b'escaped')
                elif kind == 'work-link':
                    alias = root / 'alias'
                    alias.symlink_to(work, target_is_directory=True)
                    source.write_bytes(b'broker')
                    work = alias
                elif kind == 'directory':
                    source.mkdir()
                else:
                    source.write_bytes(b'broker')
                    (work / 'materialized-rust-broker').mkdir()
                    sentinel = work / 'materialized-rust-broker/orangespace-broker.exe'
                    sentinel.write_bytes(b'do not replace')
                with self.assertRaises((ValueError, OSError)):
                    b.materialize_rust_broker(work)
                self.assertEqual(outside.read_bytes(), b'not compiler output')
                if kind == 'stale-stage':
                    self.assertEqual((work / 'materialized-rust-broker/orangespace-broker.exe').read_bytes(), b'do not replace')

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

    def test_windows_helper_requires_archive_binary_digest_and_unique_member(self):
        self.assertTrue(callable(getattr(b, 'windows_helper', None)), 'verified ZIP extractor missing')
        with tempfile.TemporaryDirectory() as d:
            deps = Path(d)
            pin = dict(b.PIN['helper'])
            pin.update(windows_archive='official.zip', windows_binary_sha256=b.digest(b'approved'))
            def archive(rows):
                stream = io.BytesIO()
                with zipfile.ZipFile(stream, 'w') as z:
                    for name, data in rows:
                        z.writestr(name, data)
                data = stream.getvalue()
                (deps / 'official.zip').write_bytes(data)
                pin['windows_archive_sha256'] = b.digest(data)
            with patch.dict(b.PIN, helper=pin):
                archive([('release/sing-box.exe', b'approved')])
                self.assertEqual(b.windows_helper(deps), b'approved')
                pin['windows_archive_sha256'] = '0' * 64
                with self.assertRaisesRegex(ValueError, 'archive digest'):
                    b.windows_helper(deps)
                archive([('release/sing-box.exe', b'wrong')])
                with self.assertRaisesRegex(ValueError, 'binary'):
                    b.windows_helper(deps)
                for rows in [[], [('a/sing-box.exe', b'approved'), ('b/sing-box.exe', b'approved')]]:
                    archive(rows)
                    with self.assertRaisesRegex(ValueError, 'binary'):
                        b.windows_helper(deps)
                archive([('../sing-box.exe', b'approved')])
                with self.assertRaises(ValueError):
                    b.windows_helper(deps)

    def test_gnu_plan_is_fresh_static_offline_single_job(self):
        commands = b.gnu_commands(Path('/fresh'), Path('/fresh/rust'))
        cargo, configure, compile_ = commands
        self.assertIn('--offline', cargo)
        self.assertIn('--locked', cargo)
        self.assertIn('x86_64-pc-windows-gnu', cargo)
        self.assertIn('orangespace-runtime', cargo)
        self.assertIn('orangespace-broker', cargo)
        self.assertEqual(cargo[cargo.index('--jobs') + 1], '1')
        self.assertIn('-DCMAKE_EXE_LINKER_FLAGS=-static -static-libgcc -static-libstdc++', configure)
        self.assertIn('-DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++-posix', configure)
        self.assertIn('-DORANGESPACE_RUNTIME_LIBRARY=/fresh/rust/x86_64-pc-windows-gnu/release/liborangespace_runtime.a', configure)
        self.assertEqual(compile_[compile_.index('--parallel') + 1], '1')
        self.assertEqual(compile_[-3:], ['OrangeSpace', 'OrangeSpaceLogin', 'OrangeSpaceService'])

    def test_compatible_node_tools_record_not_reject_installed_variants(self):
        for node, npm in [('v26.7.0', '12.0.2'), ('v26.11.1', '11.20.0')]:
            self.assertTrue(b.node_tools_compatible(node, npm))
        self.assertFalse(b.node_tools_compatible('v24.0.0', '12.0.2'))

    def test_public_examples_complete_and_scannable(self):
        for role, required in [('node', {'examples/database.example.json', 'server/alembic-node.ini',
                                        'deploy/linux-node/node-a.runtime.example.json'}),
                               ('windows', {'examples/platform.example.json', 'examples/nodes.example.json',
                                            'examples/service-state.fresh-only.example.json'})]:
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
