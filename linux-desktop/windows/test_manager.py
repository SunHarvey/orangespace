import json
import sqlite3
import struct
import sys
from unittest.mock import patch, Mock
import tempfile
import unittest
import uuid
from pathlib import Path
from contextlib import closing
from types import SimpleNamespace

from runtime import Config, Runtime, qemu_args, x11_setup, xauthority, remove_stale_sessions
from workspaces import Store


class AccountInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "accounts.sqlite3"
        self.store = Store(self.db)
        self.node_a = str(uuid.uuid4())
        self.node_b = str(uuid.uuid4())

    def test_explicit_registration_separate_accounts_and_persistence(self):
        secret = "a long test passphrase"
        with self.assertRaises(ValueError):
            self.store.login("operator", secret)
        a = self.store.register("Operator", secret)
        self.assertEqual(a, self.store.login("oPERAtor", secret))
        with self.assertRaises(ValueError):
            self.store.login("operator", "invalid")
        with self.assertRaises(ValueError):
            self.store.register("opErator", secret)
        b = self.store.register("Other", secret)
        sa = self.store.create(a, "工作", self.node_a)
        sb = self.store.create(b, "工作", self.node_b)
        with self.assertRaises(ValueError):
            self.store.bind(a, sb, self.node_a)
        self.store.bind(a, sa, self.node_b)
        reopened = Store(self.db)
        self.assertEqual([(r["id"], r["node"]) for r in reopened.list(a)], [(sa, self.node_b)])
        self.assertEqual([r["id"] for r in reopened.list(b)], [sb])
        self.assertNotIn(secret.encode(), self.db.read_bytes())
        with closing(sqlite3.connect(self.db)) as conn:
            salts = conn.execute("SELECT DISTINCT salt FROM account").fetchall()
            self.assertEqual(len(salts), 2)

    def test_invalid_names_nodes_and_credentials(self):
        with self.assertRaises(ValueError):
            self.store.register("ops", "short")
        user = self.store.register("test", "sufficient length")
        for name, node in [(" ", self.node_a), ("sandbox", "arbitrary"),
                           ("sandbox", self.node_a.upper()), ("x\nname", self.node_b)]:
            with self.assertRaises(ValueError):
                self.store.create(user, name, node)
        self.assertEqual(self.store.list(user), [])


class LaunchTests(unittest.TestCase):
    def test_bootstrap_inventory_before_qemu_and_image_exist(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            node = str(uuid.uuid4())
            doc = {"qemu": str(root / "qemu.exe"), "image": str(root / "not-built.qcow2"),
                   "data_image": str(root / "data.qcow2"), "cygwin_bin": str(root / "bin"), "nodes": {node: "A"}}
            path = root / "runtime.json"
            path.write_text(json.dumps(doc))
            cfg = Config.load(path)
            with self.assertRaises(ValueError):
                cfg.preflight()
            store = Store(root / "accounts.sqlite3")
            user = store.register("user", "valid password")
            sid = store.create(user, "A", node)
            self.assertEqual(store.list(user)[0]["id"], sid)
            (root / "bin").mkdir()
            for tool in (cfg.qemu, cfg.xwin, cfg.cygpath, cfg.socat, cfg.image):
                tool.touch()
            cfg.data_image.hardlink_to(cfg.image)
            with self.assertRaisesRegex(ValueError, "不同"):
                cfg.preflight()
            cfg.data_image.unlink()
            cfg.data_image.touch()
            cfg.preflight()

    def test_one_private_control_port_and_whpx_only(self):
        cfg = SimpleNamespace(qemu="qemu-system-x86_64", image="vm,data.qcow2", data_image="data,one.qcow2", memory_mib=6144, cpus=4)
        args = qemu_args(cfg, "os-secret-name", "keys,files/session.key")
        self.assertIn("q35,accel=whpx", args)
        self.assertIn("file=vm,,data.qcow2,format=qcow2,if=virtio", args)
        self.assertIn("name=opt/orangespace/key,file=keys,,files/session.key", args)
        self.assertIn("if=none,id=osdata,format=qcow2,file=data,,one.qcow2", args)
        self.assertIn("virtio-blk-pci,drive=osdata,serial=OrangeSpaceData", args)
        self.assertEqual(args.count("-netdev"), 1)
        self.assertNotIn("hostfwd", " ".join(args))
        self.assertIn("virtserialport,chardev=ctl,name=org.orangespace.control", args)
        self.assertEqual(args[args.index("-qmp") + 1], "stdio")

    def test_admission_reserves_guest_memory_before_spawning(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Runtime(SimpleNamespace(memory_mib=6144), Path(tmp))
            first = runtime._reserve_number()
            second = runtime._reserve_number()
            self.assertNotEqual(first, second)
            with self.assertRaises(RuntimeError):
                runtime._reserve_number()
            runtime.reserved_numbers.remove(first)
            self.assertNotEqual(runtime._reserve_number(), second)

    def test_x11_authority_and_setup_use_single_display_cookie(self):
        cookie = bytes(range(16))
        data = xauthority(cookie, 23)
        self.assertEqual(data[:2], b"\xff\xff")
        fields, i = [], 2
        while i < len(data):
            n = struct.unpack("!H", data[i:i+2])[0]
            fields.append(data[i+2:i+2+n])
            i += 2+n
        self.assertEqual(fields, [b"", b"23", b"MIT-MAGIC-COOKIE-1", cookie])
        setup = x11_setup(cookie)
        self.assertEqual(struct.unpack("<BBHHHHH", setup[:12]), (ord("l"), 0, 11, 0, 18, 16, 0))
        self.assertEqual(setup[-16:], cookie)

    def test_cleanup_only_owned_ephemeral_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            owned = root / "vm-123456ab"
            owned.mkdir()
            (owned / "guest.key").write_bytes(bytes(32))
            user_dir = root / "vm-1234567b"
            user_dir.mkdir()
            (user_dir / "downloads").touch()
            remove_stale_sessions(root)
            self.assertFalse(owned.exists())
            self.assertTrue((user_dir / "downloads").exists())

    def test_one_sandbox_stop_failure_preserves_both_displays_for_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Runtime(SimpleNamespace(), Path(tmp))
            runtime.vm = Mock()
            runtime.vm.poll.return_value = None
            rows = [{"id": "a"}, {"id": "b"}]
            for n, row in enumerate(rows, start=1):
                directory = Path(tmp) / row["id"]
                directory.mkdir()
                child = Mock()
                child.poll.return_value = None
                runtime.displays[row["id"]] = (n, child, directory, None)
                runtime.reserved_numbers.add(n)
            a, b = runtime.displays["a"][1], runtime.displays["b"][1]
            with patch.object(runtime, "request", side_effect=TimeoutError()):
                with self.assertRaises(TimeoutError):
                    runtime.stop(rows[0])
            self.assertEqual(set(runtime.displays), {"a", "b"})
            a.terminate.assert_not_called()
            with patch.object(runtime, "request", return_value={"desktop":"stopped"}):
                runtime.stop(rows[0])
            self.assertEqual(set(runtime.displays), {"b"})
            a.terminate.assert_called_once()
            b.terminate.assert_not_called()
            self.assertTrue((Path(tmp) / "b").exists())

    def test_stalled_agent_still_allows_graceful_vm_shutdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Runtime(SimpleNamespace(), Path(tmp))
            runtime.vm = Mock()
            runtime.hub = Mock()
            runtime.vm.poll.return_value = runtime.hub.poll.return_value = None
            row = {"id": "a"}
            runtime.displays["a"] = (1, Mock(), Path(tmp), None)
            with patch.object(runtime, "stop", side_effect=RuntimeError("guest unavailable")), \
                    patch.object(runtime, "_release_display") as release, patch.object(runtime, "_power_off") as power:
                runtime.close([row])
            power.assert_called_once_with()
            release.assert_called_once_with("a")

    def test_a_second_open_uses_existing_window_and_keeps_its_cookie(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Runtime(SimpleNamespace(nodes={"node": "example"}), Path(tmp))
            display = (13, Mock(), Path(tmp), Path(tmp) / "cookie")
            display[1].poll.return_value = None
            runtime.displays["box"] = display
            existing = {"desktop":"running", "network":"online"}
            fake_api = Mock()
            with patch.object(runtime, "ensure_vm"), patch.object(runtime, "status", return_value=existing), \
                    patch.dict(sys.modules, {"winapi":fake_api}), patch.object(runtime, "_new_display") as fresh:
                self.assertEqual(runtime.start({"id":"box", "node":"node"}), existing)
            fresh.assert_not_called()
            fake_api.window.assert_called_once_with(display[1].pid, activate=True)
            self.assertEqual(runtime.displays["box"], display)
            offline = {"desktop": "running", "network": "offline"}
            row = {"id": "box", "node": "node"}
            with patch.object(runtime, "ensure_vm"), patch.object(runtime, "status", return_value=offline), \
                    patch.dict(sys.modules, {"winapi":fake_api}), patch.object(runtime, "_start_guest", return_value=existing) as retry:
                self.assertEqual(runtime.start(row), existing)
            retry.assert_called_once_with(row, display)



if __name__ == "__main__":
    unittest.main()
