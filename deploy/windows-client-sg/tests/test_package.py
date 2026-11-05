import importlib.util
from pathlib import Path
import tempfile
import unittest

BASE = Path(__file__).resolve().parents[1]

class PackageTests(unittest.TestCase):
    def test_runtime_rejects_profile_cookie_sqlite(self):
        spec = importlib.util.spec_from_file_location('package', BASE / 'assemble.py')
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'Profiles').mkdir()
            (root / 'Profiles/Cookies.sqlite').write_bytes(b'private cookie fixture')
            with self.assertRaisesRegex(ValueError, 'sensitive'):
                module.scan(root)

    def test_resource_preflight_before_hashing(self):
        spec = importlib.util.spec_from_file_location('package', BASE / 'assemble.py')
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'large.dll').write_bytes(b'x' * 32)
            module.MAX_TOTAL = 16
            with self.assertRaisesRegex(ValueError, 'resource'):
                module.scan(root)
            module.MAX_TOTAL = 1024
            module.MAX_FILES = 1
            (root / 'second.dll').write_bytes(b'y')
            with self.assertRaisesRegex(ValueError, 'resource'):
                module.scan(root)
            module.MAX_FILES = 4096
            module.MAX_DEPTH = 1
            (root / 'nested').mkdir()
            (root / 'nested/a.dll').write_bytes(b'z')
            with self.assertRaisesRegex(ValueError, 'resource'):
                module.scan(root)

    def test_closed_inventory_rejects_mutations(self):
        self.assertTrue((BASE / 'assemble.py').exists(), 'reproducible assembler is missing')
        spec = importlib.util.spec_from_file_location('package', BASE / 'assemble.py')
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'client.exe').write_bytes(b'fixture only, not a PE')
            module.write_inventory(root)
            module.verify_inventory(root)
            (root / 'extra.dll').write_bytes(b'not listed')
            with self.assertRaises(ValueError): module.verify_inventory(root)
            (root / 'extra.dll').unlink()
            (root / 'client.exe').write_bytes(b'changed')
            with self.assertRaises(ValueError): module.verify_inventory(root)

    def test_inventory_and_filesystem_negative_matrix(self):
        import os
        spec = importlib.util.spec_from_file_location('package', BASE / 'assemble.py')
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            leaf = root / 'client.exe'
            leaf.write_bytes(b'unit fixture')
            module.write_inventory(root)
            inventory = root / module.INVENTORY
            good = inventory.read_bytes()
            for altered in (good.replace(b'\n', b'\r\n'), good + good,
                            good.replace(b'client.exe', b'../client.exe'),
                            good.replace(b'client.exe', b'C:/client.exe'),
                            good.replace(b'client.exe', b'CON.exe'),
                            good.replace(b'client.exe', b'client.exe:ads'),
                            good.replace(b'client.exe', b'runtime.inventory.tsv')):
                with self.subTest(altered=altered):
                    inventory.write_bytes(altered)
                    with self.assertRaises(ValueError): module.verify_inventory(root)
            inventory.write_bytes(good)
            leaf.unlink()
            with self.assertRaises(ValueError): module.verify_inventory(root)
            leaf.write_bytes(b'unit fixture')
            link = root / 'linked.exe'
            os.link(leaf, link)
            with self.assertRaises(ValueError): module.write_inventory(root)
            link.unlink()
            link.symlink_to(leaf)
            with self.assertRaises(ValueError): module.write_inventory(root)
            link.unlink()
            (root / 'CLIENT.EXE').write_bytes(b'collision')
            with self.assertRaises(ValueError): module.write_inventory(root)

    def test_builder_overlays_fresh_binaries_and_protected_configs(self):
        spec = importlib.util.spec_from_file_location('package', BASE / 'assemble.py')
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime = root / 'cef'
            runtime.mkdir()
            for name in ('client.exe','client.dll','libcef.dll','sing-box.exe'):
                (runtime / name).write_bytes(b'unit-test fixture, not native runtime')
            configs = root / 'config'
            configs.mkdir(mode=0o700)
            for name, data in [('platform.json','{"schema":1,"api_origin":"https://unit.invalid"}'),('nodes.json','{"schema":1,"nodes":[]}')]:
                (configs / name).write_text(data)
                (configs / name).chmod(0o600)
            overlays = {}
            for name in ('service','gui','broker'):
                overlays[name] = root / (name + '.exe')
                overlays[name].write_bytes(('fresh fixture ' + name).encode())
            state = root / 'state'
            state.mkdir()
            (state / 'namespace.anchor').write_bytes(b'fixture anchor\n')
            (state / 'service-state.json').write_bytes(b'{"schema":1,"sandboxes":[]}\n')
            with self.assertRaisesRegex(ValueError, 'state.*pin'):
                module.assemble(runtime, root / 'unbound', config_dir=configs, state_dir=state, **overlays)
            import json, hashlib
            pins = root / 'state-pins.json'
            original = {name: {'sha256': hashlib.sha256((state / name).read_bytes()).hexdigest(), 'size': (state / name).stat().st_size} for name in ('namespace.anchor', 'service-state.json')}
            pins.write_text(json.dumps(original))
            for bad in (b'', b'x' * 1048577):
                (state / 'namespace.anchor').write_bytes(bad)
                with self.assertRaisesRegex(ValueError, 'resource'):
                    module.assemble(runtime, root / 'oversized', config_dir=configs, state_dir=state, state_pins=pins, **overlays)
            (state / 'namespace.anchor').write_bytes(b'forged anchor')
            with self.assertRaisesRegex(ValueError, 'state.*pin'):
                module.assemble(runtime, root / 'forged', config_dir=configs, state_dir=state, state_pins=pins, **overlays)
            (state / 'namespace.anchor').write_bytes(b'fixture anchor\n')
            with self.assertRaisesRegex(ValueError, 'fresh'):
                module.assemble(runtime, root / 'implicit-fresh', config_dir=configs, **overlays)
            archive = module.assemble(runtime, root / 'installer', config_dir=configs, state_dir=state, state_pins=pins, **overlays)
            import zipfile, json
            with zipfile.ZipFile(archive) as z:
                self.assertEqual(z.read('Runtime/OrangeSpace.exe'), overlays['gui'].read_bytes())
                self.assertEqual(z.read('Runtime/OrangeSpaceSinglePrototype.exe'), overlays['service'].read_bytes())
                self.assertEqual(z.read('Runtime/orangespace-broker.exe'), overlays['broker'].read_bytes())
                for name in ('Install.cmd','Install.ps1','Start.cmd','Uninstall.cmd','Uninstall.ps1','README.txt'):
                    self.assertIn(name, z.namelist())
                self.assertEqual(z.read('State/service-state.json'), (state / 'service-state.json').read_bytes())
                self.assertIn('initial_state', json.loads(z.read('Runtime/install-manifest.json')))
            module.verify_inventory(root / 'installer' / 'Runtime')

class InstallerSourceTests(unittest.TestCase):
    def test_desktop_shortcut_object_does_not_alias_script_link_path(self):
        # PowerShell variable names are case-insensitive; these top-level
        # scripts must not replace Common.ps1's $script:Link string with COM.
        for name in ('Install.ps1', 'Uninstall.ps1'):
            with self.subTest(script=name):
                source = (BASE / name).read_text(encoding='utf-8-sig')
                self.assertNotRegex(source, r'(?i)\$link\s*=|\$link\s*\.')
                self.assertIn('$desktopLink = $shell.CreateShortcut($script:Link)', source)
                self.assertIn('$desktopLink.TargetPath', source)
                self.assertIn('-LiteralPath $script:Link', source)

    def test_existing_state_marker_contract(self):
        text = (BASE / 'Install.ps1').read_text()
        self.assertNotIn('$stateItems.Count -ne 2', text)
        self.assertIn('OS\\.SG\\.[0-9a-f]{48}\\.profile', text)
        self.assertIn('existing-state-binding-refused', text)
        self.assertIn('installer-state-binding.json', text)
        self.assertIn('fresh-state-not-authorized', text)

    def test_service_security_real_query_and_concrete_rights(self):
        common = (BASE / 'Common.ps1').read_text()
        self.assertNotIn('GetServiceObjectSecurity', common)
        self.assertNotIn('GetServiceObjectSecurity', (BASE / 'tests' / 'Parse.ps1').read_text())
        self.assertIn('QueryServiceObjectSecurity', common)
        self.assertIn('D:P(A;;0xF01FF;;;SY)(A;;0xF01FF;;;BA)(A;;0x5;;;BU)', common)

    def test_source_pins_end_after_snapshot_before_any_promotion(self):
        source = (BASE / 'Install.ps1').read_text()
        release = source.index('$pins.Clear()')
        self.assertLess(source.index("$restored = [IO.File]::ReadAllText"), release)
        self.assertLess(source.index('Assert-Inventory $staging $rows $true', source.index("$stage = 'private-state'")), release)
        self.assertLess(release, source.index('[IO.Directory]::Move($stateStaging,$script:State)'))
        self.assertLess(release, source.index('[IO.Directory]::Move($staging,$script:Root)'))
        self.assertNotIn('$stateSource', source[release:])
        self.assertNotIn('$sourceLeaf', source[release:])

    def test_native_null_and_uint_binding_contract(self):
        common = (BASE / 'Common.ps1').read_text()
        self.assertIn('OpenLocalManager(uint access)', common)
        self.assertIn('OpenSCManagerW(null,null,access)', common)
        self.assertIn('CreateLocalService(', common)
        self.assertIn('2147483648', common)
        for name in ('Common.ps1','Install.ps1','Start.ps1','Uninstall.ps1'):
            source = (BASE / name).read_text()
            self.assertNotIn('::OpenSCManagerW($null', source)
            self.assertNotIn('::CreateServiceW($manager', source)

    def test_privilege_and_identity_contract(self):
        common = BASE / 'Common.ps1'
        self.assertTrue(common.exists(), 'Windows installer implementation is missing')
        text = common.read_text(encoding='utf-8-sig')
        self.assertIn("if (-not ('OrangeInstallNative' -as [type]))", text,
                      'Install -> Start dot-source must not redefine Add-Type on PS5.1')
        for token in ('CreateServiceW', 'LocalSystem', 'FILE_SHARE_READ', 'NumberOfLinks',
                      'SetAccessRuleProtection', 'S-1-15-2-1', 'OrangeSpaceSinglePrototype.SG.v25',
                      'GetAccessRules', 'QueryServiceConfigW', 'SetServiceObjectSecurity'):
            self.assertIn(token, text)
        install = (BASE / 'Install.ps1').read_text(encoding='utf-8-sig')
        self.assertIn('Assert-Inventory', install)
        self.assertIn('namespace.anchor', install)
        self.assertNotIn('Start-Process $gui', install)
        uninstall = (BASE / 'Uninstall.ps1').read_text(encoding='utf-8-sig')
        self.assertIn('WaitForExit', uninstall)
        for file in BASE.glob('*.ps1'):
            source = file.read_text(encoding='utf-8-sig').lower()
            for forbidden in ('executionpolicy bypass', 'stop-process', 'taskkill', 'netsh', 'remove-item env:'):
                self.assertNotIn(forbidden, source)

if __name__ == '__main__': unittest.main()
