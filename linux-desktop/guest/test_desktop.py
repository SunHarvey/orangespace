"""Root-free coverage for the desktop lifecycle: ownership, slots, container and
display configuration, start/stop ordering, deletion and node configuration."""
import importlib.machinery
import importlib.util
import io
from pathlib import Path
import socket
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
        self.patch("LEASES", self.root / "leases")

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

    def test_start_orders_display_window_container_gateway_launch_and_stays_offline_without_node(self):
        self.patch("inspect", side_effect=[None, self.info])
        self.patch("display_running", return_value=True)
        self.patch("window_open", return_value=True)
        events = []
        self.patch("start_display", side_effect=lambda *a: events.append("display") or (self.root, 100))
        self.patch("open_window", side_effect=lambda *a: events.append("window"))
        self.patch("create", side_effect=lambda *a: events.append("create"))
        self.patch("checked", side_effect=lambda *a, **k: events.append(a[1] if a[0] == desktop.PODMAN[0] else a[0]))
        self.patch("execute", return_value=subprocess.CompletedProcess([], 0))
        def network(operation, sandbox, *args):
            events.append("gateway-" + operation)
            return operation in ("down",)   # no usable node: up fails
        self.patch("gateway", side_effect=network)
        result = desktop.run("start", self.user, self.sandbox, self.node, "OrangeSpace A")
        self.assertEqual(events, ["gateway-down", "display", "window", "create", "start", "gateway-up",
                                  "gateway-down", "exec", "gateway-status"])
        self.assertEqual((result["desktop"], result["window"], result["network"]), ("running", "open", "offline"))

    def test_reopening_a_running_desktop_only_reopens_its_window(self):
        self.patch("inspect", return_value=self.info)
        self.patch("display_running", return_value=True)
        self.patch("window_open", return_value=False)
        start_display, create = self.patch("start_display"), self.patch("create")
        open_window = self.patch("open_window")
        self.patch("gateway", return_value=True)
        self.patch("execute", return_value=subprocess.CompletedProcess([], 0))
        desktop.run("start", self.user, self.sandbox, self.node, "A")
        start_display.assert_not_called()
        create.assert_not_called()
        open_window.assert_called_once_with(self.sandbox, desktop.slot_of(self.instance()))

    def test_display_account_is_created_once_and_never_borrowed(self):
        checked = self.patch("checked")
        getpwuid = self.patch("pwd").getpwuid
        getpwuid.side_effect = KeyError
        self.assertEqual(desktop.display_account(5), desktop.DISPLAY_UID_BASE + 5)
        self.assertEqual([c.args[0] for c in checked.call_args_list], ["/usr/sbin/groupadd", "/usr/sbin/useradd"])
        checked.reset_mock()
        getpwuid.side_effect = None
        getpwuid.return_value = type("Entry", (), {"pw_name": "osdisp5", "pw_gid": desktop.DISPLAY_UID_BASE + 5})
        self.assertEqual(desktop.display_account(5), desktop.DISPLAY_UID_BASE + 5)
        checked.assert_not_called()
        getpwuid.return_value = type("Entry", (), {"pw_name": "someone", "pw_gid": 100})
        with self.assertRaisesRegex(desktop.DesktopError, "conflicts"):
            desktop.display_account(5)

    def test_window_already_open_is_not_started_twice(self):
        self.patch("window_open", return_value=True)
        checked = self.patch("checked")
        desktop.open_window(self.sandbox, 2)
        checked.assert_not_called()

    def test_display_runs_confined_without_wslg_or_clipboard_and_viewer_socket_stays_private(self):
        short = tempfile.TemporaryDirectory(dir="/tmp")   # Unix socket paths are length-limited
        self.addCleanup(short.cleanup)
        root = Path(short.name)
        self.patch("DISPLAY_ROOT", root / "display")
        self.patch("VIEW_ROOT", root / "view")
        self.patch("execute", return_value=subprocess.CompletedProcess([], 3, stdout="inactive"))
        chown_patch = patch.object(desktop.os, "chown")
        chown = chown_patch.start()
        self.addCleanup(chown_patch.stop)
        calls = []
        def fake_systemd_run(*args, **kwargs):
            calls.append(args)
            if len(calls) == 1:   # the X server creates its two sockets
                number = next(a for a in args if a.startswith(":"))
                for path in (root / "display" / self.sandbox / ("X" + number[1:]), root / "view" / self.sandbox / "rfb"):
                    sock = socket.socket(socket.AF_UNIX)
                    sock.bind(str(path))
                    self.addCleanup(sock.close)
        self.patch("checked", side_effect=fake_systemd_run)
        self.patch("display_account", side_effect=desktop.display_uid)
        directory, number = desktop.start_display(self.sandbox, 4, "A")
        desktop.open_window(self.sandbox, 4)
        server, viewer = calls
        uid = desktop.display_uid(4)
        self.assertEqual((directory, number), (root / "display" / self.sandbox, desktop.DISPLAY_BASE + 4))
        self.assertTrue(all(c.args[1] == uid for c in chown.call_args_list))
        self.assertFalse(any(uid in range(desktop.UID_BASE + s * desktop.UID_BLOCK,
                                          desktop.UID_BASE + (s + 1) * desktop.UID_BLOCK)
                             for s in range(desktop.MAX_SLOTS)))
        for unit in (server, viewer):
            for flag in (f"--uid={uid}", "--property=NoNewPrivileges=yes", "--property=PrivateNetwork=yes",
                         "--property=ProtectSystem=strict", "-SendPrimary=0", "-SetPrimary=0"):
                self.assertIn(flag, unit)
        for flag in ("--property=InaccessiblePaths=/mnt", "-AcceptCutText=0", "-SendCutText=0", "-rfbport=-1",
                     "-nolisten", "-rfbunixmode=0600"):
            self.assertIn(flag, server)
        for flag in ("-AcceptClipboard=0", "-SendClipboard=0", "-MenuKey=None", "--property=Restart=on-failure"):
            self.assertIn(flag, viewer)
        # The viewer socket lives outside the directory the container mounts.
        rfb = root / "view" / self.sandbox / "rfb"
        self.assertIn(str(rfb), viewer)
        self.assertNotIn(directory, rfb.parents)
        self.assertEqual((root / "view" / self.sandbox).stat().st_mode & 0o777, 0o700)

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

    def test_stop_drops_only_this_sandboxs_lease(self):
        self.instance()
        sibling = str(uuid.uuid4())
        leases = self.root / "leases"
        leases.mkdir()
        for sandbox in (self.sandbox, sibling):
            (leases / (sandbox + ".json")).write_text('{"password":"fixture"}')
        self.patch("gateway", return_value=True)
        self.patch("remove")
        self.patch("stop_display")
        self.patch("inspect", return_value=self.info)
        self.patch("describe", return_value={"desktop": "stopped"})
        desktop.run("stop", self.user, self.sandbox)
        self.assertFalse((leases / (self.sandbox + ".json")).exists())
        self.assertTrue((leases / (sibling + ".json")).exists())
        desktop.run("stop", self.user, self.sandbox)  # already gone: stopping again still works

    def test_delete_removes_local_data_and_frees_the_slot(self):
        directory = self.instance()
        slot = desktop.slot_of(directory)
        (directory / "home").mkdir()
        (directory / "home" / "file.txt").write_text("private")
        (self.root / "leases").mkdir()
        lease = self.root / "leases" / (self.sandbox + ".json")
        lease.write_text("{}")
        self.patch("inspect", return_value=None)
        stop = self.patch("stop")
        reply = desktop.run("delete", self.user, self.sandbox)
        self.assertTrue(reply["deleted"])
        stop.assert_called_once()
        self.assertFalse(directory.exists())
        self.assertFalse(lease.exists())
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

    def test_lease_is_stored_and_rebuilds_only_a_running_desktop_on_its_node(self):
        inspect = self.patch("inspect", return_value=None)
        gateway = self.patch("gateway", return_value=True)
        self.patch("describe", side_effect=lambda user, sandbox, info: {"desktop": "running" if info else "stopped"})
        secret = b'{"password":"fixture"}'
        with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as invoke:
            desktop.run("lease", self.user, self.sandbox, self.node, policy_stream=io.BytesIO(secret))
            self.assertEqual(invoke.call_args.args[0], [str(desktop.NETWORK / "lease"), self.sandbox, self.node])
            self.assertEqual(invoke.call_args.kwargs["input"], secret)
            gateway.assert_not_called()  # stopped: the lease waits for the next start
            inspect.return_value = self.info
            desktop.run("lease", self.user, self.sandbox, self.node, policy_stream=io.BytesIO(secret))
            gateway.assert_called_once_with("up", self.sandbox, "123", self.node)
            with self.assertRaisesRegex(desktop.DesktopError, "another node"):
                desktop.run("lease", self.user, self.sandbox, str(uuid.uuid4()), policy_stream=io.BytesIO(secret))
            with self.assertRaisesRegex(desktop.DesktopError, "account"):
                desktop.run("lease", str(uuid.uuid4()), self.sandbox, self.node, policy_stream=io.BytesIO(secret))
            invoke.return_value = subprocess.CompletedProcess([], 1)
            with self.assertRaisesRegex(desktop.DesktopError, "rejected"):
                desktop.run("lease", self.user, self.sandbox, self.node, policy_stream=io.BytesIO(secret))
        self.assertEqual(gateway.call_count, 1)

    def test_renew_extends_only_with_a_bounded_budget(self):
        self.instance()
        gateway = self.patch("gateway", return_value=True)
        tunnel = str(uuid.uuid4())
        reply = desktop.run("renew", self.user, self.sandbox, tunnel, remaining_ms="20000")
        self.assertTrue(reply["renewed"])
        gateway.assert_called_once_with("renew", self.sandbox, tunnel, "20000")
        for budget in ("0", "30001", "-1", "1e3", ""):
            with self.subTest(budget=budget), self.assertRaisesRegex(desktop.DesktopError, "budget"):
                desktop.run("renew", self.user, self.sandbox, tunnel, remaining_ms=budget)
        gateway.return_value = False
        with self.assertRaisesRegex(desktop.DesktopError, "renewal rejected"):
            desktop.run("renew", self.user, self.sandbox, tunnel, remaining_ms="20000")
        with self.assertRaisesRegex(desktop.DesktopError, "account"):
            desktop.run("renew", str(uuid.uuid4()), self.sandbox, tunnel, remaining_ms="20000")



BOOT = """
import importlib.machinery, importlib.util, sys
from pathlib import Path
loader = importlib.machinery.SourceFileLoader("desktop", sys.argv[1])
spec = importlib.util.spec_from_loader(loader.name, loader)
desktop = importlib.util.module_from_spec(spec)
loader.exec_module(desktop)
desktop.ROOT = Path(sys.argv[2])
sys.exit(desktop.main(sys.argv[3:]))
"""


@unittest.skipUnless(hasattr(__import__("os"), "geteuid") and __import__("os").geteuid() == 0,
                     "needs root: the file operations really drop to the sandbox's UID")
class SandboxFilesTests(unittest.TestCase):
    """files-list/put/get run as the sandbox's own UID inside its Downloads folder."""

    SLOT = 63

    def setUp(self):
        import os
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / "state"
        self.user, self.sandbox = str(uuid.uuid4()), str(uuid.uuid4())
        self.uid = desktop.host_uid(self.SLOT)
        instance = self.state / "instances" / self.sandbox
        instance.mkdir(parents=True, mode=0o700)
        (self.state / "locks").mkdir(mode=0o700)
        (instance / "owner").write_text(self.user + "\n")
        (instance / "slot").write_text(f"{self.SLOT}\n")
        self.home = instance / "home"
        self.home.mkdir(mode=0o700)
        os.chown(self.home, self.uid, self.uid)
        self.downloads = self.home / "Downloads"

    def run_files(self, *args, data=b"", user=None):
        proc = subprocess.run([__import__("sys").executable, "-c", BOOT, str(Path(__file__).with_name("desktop")),
                               str(self.state), args[0], user or self.user, self.sandbox, *args[1:]],
                              input=data, capture_output=True, timeout=30)
        return proc.returncode, proc.stdout

    def json_of(self, *args, **kwargs):
        import json
        code, out = self.run_files(*args, **kwargs)
        return code, json.loads(out)

    def test_round_trip_creates_files_owned_by_the_sandbox_and_never_replaces(self):
        import json, os
        code, result = self.json_of("files-put", "报告.txt", "5", data=b"hello")
        self.assertEqual((code, result["name"]), (0, "报告.txt"))
        info = os.stat(self.downloads / "报告.txt")
        self.assertEqual((info.st_uid, info.st_gid, info.st_mode & 0o777), (self.uid, self.uid, 0o600))
        self.assertEqual(os.stat(self.downloads).st_uid, self.uid)  # created on first use, as the sandbox
        code, result = self.json_of("files-put", "报告.txt", "3", data=b"two")
        self.assertEqual(result["name"], "报告 (1).txt")
        self.assertEqual((self.downloads / "报告.txt").read_bytes(), b"hello")
        (self.downloads / "half.crdownload").write_bytes(b"x")
        (self.downloads / ".hidden").write_bytes(b"x")
        (self.downloads / "folder").mkdir()
        code, listing = self.json_of("files-list")
        self.assertEqual([f["name"] for f in listing["files"]], ["报告 (1).txt", "报告.txt"])
        code, out = self.run_files("files-get", "报告 (1).txt")
        header, body = out.split(b"\n", 1)
        self.assertEqual((code, json.loads(header), body), (0, {"size": 3}, b"two"))

    def test_short_or_long_input_publishes_nothing(self):
        import os
        for data in (b"abc", b"abcdefgh"):
            code, result = self.json_of("files-put", "a.bin", "5", data=data)
            self.assertEqual(code, 1)
            self.assertIn("error", result)
        self.assertEqual(os.listdir(self.downloads), [])

    def test_links_and_files_the_sandbox_cannot_read_stay_out_of_reach(self):
        import os
        self.downloads.mkdir()
        os.chown(self.downloads, self.uid, self.uid)
        secret = Path(self.tmp.name) / "root-only"
        secret.write_bytes(b"secret")
        secret.chmod(0o600)
        os.symlink(secret, self.downloads / "link")
        os.link(secret, self.downloads / "hard")          # a root-owned file inside Downloads
        for name in ("link", "hard"):
            code, out = self.run_files("files-get", name)
            self.assertEqual(code, 1, name)
            self.assertNotIn(b"secret", out)
        code, listing = self.json_of("files-list")
        self.assertEqual([f["name"] for f in listing["files"]], ["hard"])  # listed, but not readable

    def test_a_redirected_downloads_folder_is_refused(self):
        import os
        target = Path(self.tmp.name) / "elsewhere"
        target.mkdir()
        os.symlink(target, self.downloads)
        code, result = self.json_of("files-put", "a", "1", data=b"x")
        self.assertEqual(code, 1)
        self.assertEqual(os.listdir(target), [])

    def test_names_and_owners_are_checked_before_any_io(self):
        for name in ("../x", "a/b", ".hidden", "", "x" * 256, "a\nb"):
            code, result = self.json_of("files-put", name, "1", data=b"x")
            self.assertEqual(code, 1, name)
        code, result = self.json_of("files-list", user=str(uuid.uuid4()))
        self.assertIn("another account", result["error"])
        self.assertFalse(self.downloads.exists())


if __name__ == "__main__":
    unittest.main()
