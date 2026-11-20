"""Root-free coverage for root-only lifecycle admission, cleanup and Docker configuration."""
import importlib.machinery
import importlib.util
import io
from pathlib import Path
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
        self.info = {"Id": "container-a", "State": {"Pid": 123, "Running": True},
                     "Config": {"Labels": {desktop.LABEL + "node": self.node}}}
        self.patch("ROOT", self.root / "state")

    def patch(self, name, *args, **kwargs):
        mock = patch.object(desktop, name, *args, **kwargs)
        self.addCleanup(mock.stop)
        return mock.start()

    def test_wrong_user_cannot_touch_persistent_or_running_instance(self):
        with desktop.ownership(self.user, self.sandbox, True):
            pass
        inspect = self.patch("inspect")
        for op in ("status", "stop", "start"):
            with self.assertRaisesRegex(desktop.DesktopError, "account"):
                desktop.run(op, str(uuid.uuid4()), self.sandbox, self.node)
        inspect.assert_not_called()

    def test_one_uuid_serializes_competing_operations_without_blocking_sibling(self):
        entering = threading.Event()
        entered = threading.Event()
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

    def test_mismatched_node_preserves_live_instance(self):
        self.patch("inspect", return_value=self.info)
        stop = self.patch("stop")
        with self.assertRaisesRegex(desktop.DesktopError, "changing"):
            desktop.run("start", self.user, self.sandbox, str(uuid.uuid4()))
        stop.assert_not_called()

    def test_missing_node_keeps_desktop_isolated_and_operable(self):
        self.patch("inspect", side_effect=[None, self.info])
        self.patch("create")
        docker = self.patch("checked")
        self.patch("execute", return_value=subprocess.CompletedProcess([], 0))
        actions = []
        def network(operation, sandbox, *args):
            self.assertEqual(sandbox, self.sandbox)
            actions.append(operation)
            return operation == "down"
        self.patch("gateway", side_effect=network)
        result = desktop.run("start", self.user, self.sandbox, self.node)
        self.assertEqual((result["desktop"], result["network"]), ("running", "offline"))
        self.assertEqual(actions, ["down", "status", "up", "down", "status"])
        self.assertEqual(docker.call_count, 2)

    def test_stop_closes_container_even_if_helper_fails(self):
        self.patch("gateway", return_value=False)
        remove = self.patch("remove")
        with self.assertRaisesRegex(desktop.DesktopError, "cleanup"):
            desktop.stop(self.sandbox, self.info)
        remove.assert_called_once_with(self.info)

    def test_container_uses_current_sandbox_data_only_and_no_default_egress(self):
        self.patch("prepare_mounts", return_value=(self.root/"home", self.root/"display", self.root/"id"))
        checked = self.patch("checked")
        desktop.create(self.user, self.sandbox, self.node, self.root)
        args = checked.call_args.args
        self.assertIn("--network=none", args)
        self.assertIn("--cap-drop=ALL", args)
        self.assertIn("--ipc=private", args)
        self.assertIn("--read-only", args)
        self.assertIn("1000:1000", args)
        self.assertNotIn("--privileged", args)
        self.assertIn(f"type=bind,src={self.root/'display'},dst=/tmp/.X11-unix,readonly", args)
        self.assertIn(f"type=bind,src={self.root/'home'},dst=/home/desktop", args)

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
            reply = desktop.run("configure", self.user, self.sandbox, self.node, io.BytesIO(secret))
            self.assertTrue(reply["configured"])
            self.assertEqual(invoke.call_args.args[0], [str(desktop.NETWORK/"configure"), self.sandbox, self.node])
            self.assertEqual(invoke.call_args.kwargs["input"], secret)
            with self.assertRaisesRegex(desktop.DesktopError, "account"):
                desktop.run("configure", str(uuid.uuid4()), self.sandbox, self.node, io.BytesIO(secret))
            inspect.return_value = self.info
            with self.assertRaisesRegex(desktop.DesktopError, "stop"):
                desktop.run("configure", self.user, self.sandbox, self.node, io.BytesIO(secret))
            self.assertEqual(invoke.call_count, 1)

    def test_configure_rejects_oversize_before_invoking_gateway(self):
        with patch.object(subprocess, "run") as invoke, self.assertRaisesRegex(desktop.DesktopError, "32768"):
            desktop.configure(self.sandbox, self.node, io.BytesIO(b"x"*32769))
        invoke.assert_not_called()

if __name__ == "__main__":
    unittest.main()
