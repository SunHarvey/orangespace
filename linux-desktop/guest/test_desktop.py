"""Root-free coverage for the desktop lifecycle: ownership, slots, container and
display configuration, start/stop ordering, deletion and node configuration."""
import importlib.machinery
import importlib.util
import io
from pathlib import Path
import struct
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
import uuid

loader = importlib.machinery.SourceFileLoader("desktop", str(Path(__file__).with_name("desktop")))
spec = importlib.util.spec_from_loader(loader.name, loader)
desktop = importlib.util.module_from_spec(spec)
loader.exec_module(desktop)


class DesktopTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.user, self.sandbox, self.node = (str(uuid.uuid4()) for _ in range(3))
        self.info = {"Id": "container-a", "Name": "osdesk-" + self.sandbox, "State": {"Pid": 123, "Running": True},
                     "Config": {"Labels": {desktop.LABEL + "node": self.node}}}
        self.patch("ROOT", self.root / "state")

    def patch(self, name, *args, **kwargs):
        mock = patch.object(desktop, name, *args, **kwargs)
        self.addCleanup(mock.stop)
        return mock.start()

    def instance(self, sandbox=None):
        with desktop.ownership(self.user, sandbox or self.sandbox, True) as directory:
            return directory

    def test_wrong_user_cannot_touch_persistent_or_running_instance(self):
        self.instance()
        inspect = self.patch("inspect")
        for op, extra in (("status", ()), ("stop", ()), ("delete", ()), ("start", (self.node, "A"))):
            with self.assertRaisesRegex(desktop.DesktopError, "account"):
                desktop.run(op, str(uuid.uuid4()), self.sandbox, *extra)
        inspect.assert_not_called()

    def test_one_uuid_serializes_competing_operations_without_blocking_sibling(self):
        entering, entered = threading.Event(), threading.Event()
        def competitor():
            entering.set()
            with desktop.ownership(self.user, self.sandbox, True):
                entered.set()
        with desktop.ownership(self.user, self.sandbox, True):
            thread = threading.Thread(target=competitor)
            thread.start()
            self.assertTrue(entering.wait(2))
            self.assertFalse(entered.wait(0.05))
            with desktop.ownership(self.user, str(uuid.uuid4()), True):
                pass
        thread.join(2)
        self.assertTrue(entered.is_set())

    def test_each_sandbox_gets_its_own_persistent_uid_block_and_display(self):
        a, b = self.instance(), self.instance(str(uuid.uuid4()))
        slot_a, slot_b = desktop.slot_of(a), desktop.slot_of(b)
        self.assertNotEqual(slot_a, slot_b)
        self.assertEqual(desktop.slot_of(a), slot_a)  # stable across restarts
        blocks = [range(desktop.UID_BASE + s * desktop.UID_BLOCK, desktop.UID_BASE + (s + 1) * desktop.UID_BLOCK)
                  for s in (slot_a, slot_b)]
        self.assertFalse(set(blocks[0]) & set(blocks[1]))
        self.assertIn(desktop.host_uid(slot_a), blocks[0])

    def test_container_sees_only_its_display_home_and_no_network(self):
        directory = self.instance()
        display = self.root / "display"
        self.patch("prepare_home", return_value=(directory / "home", directory / "machine-id"))
        checked = self.patch("checked")
        desktop.create(self.user, self.sandbox, self.node, directory, 3, display, 103)
        args = checked.call_args.args
        base = desktop.UID_BASE + 3 * desktop.UID_BLOCK
        for flag in ("--network=none", "--cap-drop=ALL", "--ipc=private", "--read-only",
                     "--security-opt=no-new-privileges", f"--security-opt=seccomp={desktop.SECCOMP}",
                     f"--uidmap=0:{base}:{desktop.UID_BLOCK}", f"--gidmap=0:{base}:{desktop.UID_BLOCK}",
                     "DISPLAY=:103", f"type=bind,src={display},dst=/tmp/.X11-unix,readonly",
                     f"type=bind,src={directory / 'home'},dst=/home/desktop"):
            self.assertIn(flag, args)
        self.assertNotIn("--privileged", args)
        self.assertFalse(any("apparmor" in a for a in args))
        self.assertFalse(any("/mnt" in a for a in args))  # never the WSLg display or Windows drives

    def test_display_authority_names_this_display(self):
        cookie = bytes(range(16))
        data = desktop.authority(cookie, 107)
        self.assertEqual(data[:2], b"\xff\xff")
        fields, at = [], 2
        while at < len(data):
            (size,), at = struct.unpack("!H", data[at:at + 2]), at + 2
            fields.append(data[at:at + size])
            at += size
        self.assertEqual(fields, [b"", b"107", b"MIT-MAGIC-COOKIE-1", cookie])

    def test_window_title_is_bounded_printable_text(self):
        self.assertEqual(desktop.window_title("OrangeSpace 沙盒 A"), "OrangeSpace 沙盒 A")
        for bad in ("", "x" * 65, "a\nb", "tab\there", None):
            with self.assertRaises(ValueError):
                desktop.window_title(bad)

    def test_start_orders_window_container_gateway_launch_and_stays_offline_without_node(self):
        self.patch("inspect", side_effect=[None, self.info])
        self.patch("display_running", return_value=True)
        events = []
        self.patch("start_display", side_effect=lambda *a: events.append("window") or (self.root, 100))
        self.patch("create", side_effect=lambda *a: events.append("create"))
        self.patch("checked", side_effect=lambda *a, **k: events.append(a[1] if a[0] == desktop.PODMAN[0] else a[0]))
        self.patch("execute", return_value=subprocess.CompletedProcess([], 0))
        def network(operation, sandbox, *args):
            events.append("gateway-" + operation)
            return operation in ("down",)   # no usable node: up fails
        self.patch("gateway", side_effect=network)
        result = desktop.run("start", self.user, self.sandbox, self.node, "OrangeSpace A")
        self.assertEqual(events, ["gateway-down", "window", "create", "start", "gateway-up", "gateway-down",
                                  "exec", "gateway-status"])
        self.assertEqual((result["desktop"], result["network"]), ("running", "offline"))

    def test_reopening_a_running_desktop_changes_nothing(self):
        self.patch("inspect", return_value=self.info)
        self.patch("display_running", return_value=True)
        start_display = self.patch("start_display")
        self.patch("gateway", return_value=True)
        self.patch("execute", return_value=subprocess.CompletedProcess([], 0))
        desktop.run("start", self.user, self.sandbox, self.node, "A")
        start_display.assert_not_called()

    def test_mismatched_node_preserves_live_instance(self):
        self.patch("inspect", return_value=self.info)
        stop = self.patch("stop")
        with self.assertRaisesRegex(desktop.DesktopError, "changing"):
            desktop.run("start", self.user, self.sandbox, str(uuid.uuid4()), "A")
        stop.assert_not_called()

    def test_stop_closes_container_and_window_even_if_gateway_cleanup_fails(self):
        self.patch("gateway", return_value=False)
        remove = self.patch("remove")
        stop_display = self.patch("stop_display")
        with self.assertRaisesRegex(desktop.DesktopError, "cleanup"):
            desktop.stop(self.sandbox, self.info)
        remove.assert_called_once_with(self.info)
        stop_display.assert_called_once_with(self.sandbox)

    def test_delete_removes_local_data_and_frees_the_slot(self):
        directory = self.instance()
        slot = desktop.slot_of(directory)
        (directory / "home").mkdir()
        (directory / "home" / "file.txt").write_text("private")
        self.patch("inspect", return_value=None)
        stop = self.patch("stop")
        reply = desktop.run("delete", self.user, self.sandbox)
        self.assertTrue(reply["deleted"])
        stop.assert_called_once()
        self.assertFalse(directory.exists())
        self.assertEqual(desktop.slot_of(self.instance(str(uuid.uuid4()))), slot)

    def test_invalid_id_rejected_before_io(self):
        with self.assertRaises(ValueError):
            desktop.run("stop", self.user, "../elsewhere")

    def test_online_requires_positive_probe(self):
        self.patch("gateway", return_value=True)
        probe = self.patch("execute")
        for code, expected in ((0, "online"), (1, "offline"), (2, "gateway-ready")):
            probe.return_value = subprocess.CompletedProcess([], code)
            self.assertEqual(desktop.network_state(self.sandbox), expected)

    def test_configure_uses_stdin_once_and_requires_stopped_owner(self):
        inspect = self.patch("inspect", return_value=None)
        secret = b'{"password":"fixture"}\n'
        with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as invoke:
            reply = desktop.run("configure", self.user, self.sandbox, self.node, policy_stream=io.BytesIO(secret))
            self.assertTrue(reply["configured"])
            self.assertEqual(invoke.call_args.args[0], [str(desktop.NETWORK / "configure"), self.sandbox, self.node])
            self.assertEqual(invoke.call_args.kwargs["input"], secret)
            with self.assertRaisesRegex(desktop.DesktopError, "account"):
                desktop.run("configure", str(uuid.uuid4()), self.sandbox, self.node, policy_stream=io.BytesIO(secret))
            inspect.return_value = self.info
            with self.assertRaisesRegex(desktop.DesktopError, "stop"):
                desktop.run("configure", self.user, self.sandbox, self.node, policy_stream=io.BytesIO(secret))
            self.assertEqual(invoke.call_count, 1)

    def test_configure_rejects_oversize_before_invoking_gateway(self):
        with patch.object(subprocess, "run") as invoke, self.assertRaisesRegex(desktop.DesktopError, "32768"):
            desktop.configure(self.sandbox, self.node, io.BytesIO(b"x" * 32769))
        invoke.assert_not_called()


if __name__ == "__main__":
    unittest.main()
