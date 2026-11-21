"""Runs the agent as a real child process over pipes, as wsl.exe does."""
import json
from pathlib import Path
import struct
import subprocess
import sys
import unittest
import uuid

AGENT = Path(__file__).resolve().parent / "agent.py"
MARKER = b"OrangeSpace-WSL-Agent-v1\n"
HEADER = struct.Struct("!BII")
REQUEST, REPLY = 1, 2


class AgentProcess:
    def __init__(self):
        self.proc = subprocess.Popen([sys.executable, str(AGENT)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, bufsize=0)

    def read_exact(self, size):
        data = b""
        while len(data) < size:
            part = self.proc.stdout.read(size - len(data))
            if not part:
                raise EOFError
            data += part
        return data

    def send(self, kind, number, payload):
        self.proc.stdin.write(HEADER.pack(kind, number, len(payload)) + payload)
        self.proc.stdin.flush()

    def request(self, number, value):
        self.send(REQUEST, number, json.dumps(value).encode())
        kind, got, size = HEADER.unpack(self.read_exact(HEADER.size))
        return kind, got, json.loads(self.read_exact(size))

    def close(self):
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait(5)
        self.proc.stdin.close()
        self.proc.stdout.close()


class AgentTest(unittest.TestCase):
    def setUp(self):
        self.agent = AgentProcess()
        self.addCleanup(self.agent.close)
        self.assertEqual(self.agent.read_exact(len(MARKER)), MARKER)

    def test_ping_and_facts(self):
        kind, number, reply = self.agent.request(7, {"op": "ping"})
        self.assertEqual((kind, number), (REPLY, 7))
        self.assertEqual(reply, {"ready": True, "agent_version": 2})
        _, _, info = self.agent.request(8, {"op": "facts"})
        for key in ("agent_version", "os", "kernel", "systemd", "windows_drives", "interop", "wslg"):
            self.assertIn(key, info)
        self.assertIsInstance(info["windows_drives"], list)

    def test_bad_requests_get_errors_and_the_agent_keeps_serving(self):
        for number, payload in ((1, b"not json"), (2, b"[1,2]"), (3, json.dumps({"op": "rm -rf"}).encode())):
            self.agent.send(REQUEST, number, payload)
            kind, got, size = HEADER.unpack(self.agent.read_exact(HEADER.size))
            self.assertEqual((kind, got), (REPLY, number))
            self.assertIn("error", json.loads(self.agent.read_exact(size)))
        self.assertEqual(self.agent.request(4, {"op": "ping"})[2]["ready"], True)

    def test_shutdown_answers_then_exits(self):
        _, _, reply = self.agent.request(5, {"op": "shutdown"})
        self.assertEqual(reply, {"stopping": True})
        self.assertEqual(self.agent.proc.wait(5), 0)

    def test_protocol_violation_ends_the_agent(self):
        self.agent.send(REPLY, 9, b"{}")  # clients never send replies
        self.assertEqual(self.agent.proc.wait(5), 0)
        self.assertEqual(self.agent.proc.stdout.read(), b"")

    def test_closing_stdin_ends_the_agent(self):
        self.agent.proc.stdin.close()
        self.assertEqual(self.agent.proc.wait(5), 0)


sys.path.insert(0, str(AGENT.parent))
import agent as agent_module  # noqa: E402


class FakeChannel:
    def __init__(self):
        self.sent = []

    def send(self, kind, number, payload=b""):
        self.sent.append((kind, number, json.loads(payload)))


class DesktopOpsTest(unittest.TestCase):
    """The agent passes validated arguments to guest/desktop and stops what it started."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = Path(self.tmp.name) / "calls.jsonl"
        fake = Path(self.tmp.name) / "desktop"
        fake.write_text(f"""#!{sys.executable}
import json, sys
data = sys.stdin.buffer.read().decode()
with open({str(self.log)!r}, "a") as out:
    out.write(json.dumps({{"args": sys.argv[1:], "stdin": data}}) + "\\n")
if sys.argv[1] == "start" and sys.argv[5] == "fail":
    print(json.dumps({{"error": "simulated failure"}})); sys.exit(1)
print(json.dumps({{"ok": sys.argv[1]}}))
""")
        fake.chmod(0o755)
        self.agent = agent_module.Agent(FakeChannel(), desktop=fake)
        self.user, self.sandbox, self.node = (str(uuid.uuid4()) for _ in range(3))

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_start_passes_validated_identifiers_and_title(self):
        reply = self.agent.perform({"op": "desktop.start", "user": self.user, "sandbox": self.sandbox,
                                    "node": self.node, "title": "OrangeSpace 沙盒 A"})
        self.assertEqual(reply, {"ok": "start"})
        self.assertEqual(self.calls()[0]["args"], ["start", self.user, self.sandbox, self.node, "OrangeSpace 沙盒 A"])

    def test_malformed_identifiers_never_reach_the_desktop_command(self):
        for bad in ({"sandbox": "../x"}, {"user": self.user.upper()}, {"node": 7}, {"title": 5}):
            request = {"op": "desktop.start", "user": self.user, "sandbox": self.sandbox, "node": self.node,
                       "title": "A", **bad}
            with self.assertRaises((ValueError, TypeError, AttributeError)):
                self.agent.perform(request)
        self.assertEqual(self.calls(), [])

    def test_desktop_errors_are_reported(self):
        with self.assertRaisesRegex(RuntimeError, "simulated failure"):
            self.agent.perform({"op": "desktop.start", "user": self.user, "sandbox": self.sandbox,
                                "node": self.node, "title": "fail"})

    def test_lease_credentials_go_on_stdin_and_renewals_are_bounded(self):
        tunnel = str(uuid.uuid4())
        lease = '{"node_id":"%s","password":"fixture-secret","remaining_ms":20000}' % self.node
        self.agent.perform({"op": "desktop.lease", "user": self.user, "sandbox": self.sandbox,
                            "node": self.node, "lease": lease})
        self.agent.perform({"op": "desktop.renew", "user": self.user, "sandbox": self.sandbox,
                            "tunnel": tunnel, "remaining_ms": 20000})
        lease_call, renew_call = self.calls()
        self.assertEqual(lease_call["args"], ["lease", self.user, self.sandbox, self.node])
        self.assertEqual(lease_call["stdin"], lease)
        self.assertNotIn("fixture-secret", " ".join(lease_call["args"]))
        self.assertEqual(renew_call["args"], ["renew", self.user, self.sandbox, tunnel, "20000"])
        for bad in ({"remaining_ms": 0}, {"remaining_ms": 30001}, {"remaining_ms": True},
                    {"remaining_ms": 1.5}, {"tunnel": "x"}):
            with self.subTest(bad=bad), self.assertRaises((ValueError, TypeError, AttributeError)):
                self.agent.perform({"op": "desktop.renew", "user": self.user, "sandbox": self.sandbox,
                                    "tunnel": tunnel, "remaining_ms": 20000, **bad})
        with self.assertRaisesRegex(ValueError, "32768"):
            self.agent.perform({"op": "desktop.lease", "user": self.user, "sandbox": self.sandbox,
                                "node": self.node, "lease": "x" * 32769})
        self.assertEqual(len(self.calls()), 2)

    def test_desktops_still_running_are_stopped_when_the_client_goes_away(self):
        other = str(uuid.uuid4())
        for sandbox in (self.sandbox, other):
            self.agent.perform({"op": "desktop.start", "user": self.user, "sandbox": sandbox,
                                "node": self.node, "title": "A"})
        self.agent.perform({"op": "desktop.stop", "user": self.user, "sandbox": other})
        self.agent.stop_started()
        stops = [c["args"] for c in self.calls() if c["args"][0] == "stop"]
        self.assertEqual(stops, [["stop", self.user, other], ["stop", self.user, self.sandbox]])



class FileTransferTest(unittest.TestCase):
    """Streams to and from a sandbox's Downloads go through guest/desktop in bounded chunks."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name) / "Downloads"
        self.folder.mkdir()
        fake = Path(self.tmp.name) / "desktop"
        # Stands in for guest/desktop files-*: same arguments, same stream formats.
        fake.write_text(f"""#!{sys.executable}
import json, sys, time
folder = {str(self.folder)!r}
op = sys.argv[1]
if op == "files-list":
    print(json.dumps({{"files": sorted(__import__("os").listdir(folder))}}))
elif op == "files-put":
    name, size = sys.argv[4], int(sys.argv[5])
    data = sys.stdin.buffer.read()
    if name == "refuse" or len(data) != size:
        print(json.dumps({{"error": "refused"}})); sys.exit(1)
    open(folder + "/" + name, "wb").write(data)
    print(json.dumps({{"name": name, "size": size}}))
elif op == "files-get":
    name = sys.argv[4]
    if name == "missing":
        print(json.dumps({{"error": "no such file"}})); sys.exit(1)
    if name == "slow":
        sys.stdout.buffer.write(b'{{"size": 1000000}}\\n'); sys.stdout.flush(); time.sleep(60)
    data = open(folder + "/" + name, "rb").read()
    sys.stdout.buffer.write(json.dumps({{"size": len(data)}}).encode() + b"\\n" + data)
""")
        fake.chmod(0o755)
        self.agent = agent_module.Agent(FakeChannel(), desktop=fake)
        self.ids = {"user": str(uuid.uuid4()), "sandbox": str(uuid.uuid4())}

    def push(self, name, data, chunk=agent_module.CHUNK):
        import base64
        transfer = self.agent.perform({"op": "files.push", **self.ids, "name": name, "size": len(data)})["transfer"]
        for at in range(0, len(data), chunk):
            self.agent.perform({"op": "files.write", "transfer": transfer,
                                "data": base64.b64encode(data[at:at + chunk]).decode()})
        return transfer, self.agent.perform({"op": "files.finish", "transfer": transfer})

    def pull(self, name):
        import base64
        started = self.agent.perform({"op": "files.pull", **self.ids, "name": name})
        data, end = b"", False
        while not end:
            reply = self.agent.perform({"op": "files.read", "transfer": started["transfer"]})
            chunk = base64.b64decode(reply["data"])
            self.assertLessEqual(len(chunk), agent_module.CHUNK)
            data, end = data + chunk, reply["end"]
        self.assertEqual(len(data), started["size"])
        return data

    def test_round_trip_in_bounded_chunks(self):
        data = bytes(range(256)) * 700  # several chunks, not a multiple of the chunk size
        _, result = self.push("报告.pdf", data)
        self.assertEqual(result, {"name": "报告.pdf", "size": len(data)})
        self.assertEqual((self.folder / "报告.pdf").read_bytes(), data)
        self.assertEqual(self.pull("报告.pdf"), data)
        self.assertEqual(self.pull_empty(), b"")
        self.assertEqual(self.agent.transfers, {})

    def pull_empty(self):
        (self.folder / "empty").write_bytes(b"")
        return self.pull("empty")

    def test_a_push_never_takes_more_or_less_than_announced(self):
        import base64
        transfer = self.agent.perform({"op": "files.push", **self.ids, "name": "a", "size": 3})["transfer"]
        with self.assertRaisesRegex(ValueError, "more data"):
            self.agent.perform({"op": "files.write", "transfer": transfer, "data": base64.b64encode(b"abcd").decode()})
        self.agent.perform({"op": "files.write", "transfer": transfer, "data": base64.b64encode(b"ab").decode()})
        with self.assertRaisesRegex(ValueError, "less data"):
            self.agent.perform({"op": "files.finish", "transfer": transfer})
        with self.assertRaisesRegex(ValueError, "invalid data"):
            self.agent.perform({"op": "files.write", "transfer": transfer, "data": "not base64!"})
        self.assertEqual(self.agent.perform({"op": "files.cancel", "transfer": transfer}), {"cancelled": True})
        with self.assertRaisesRegex(ValueError, "no such transfer"):
            self.agent.perform({"op": "files.write", "transfer": transfer, "data": ""})
        self.assertFalse((self.folder / "a").exists())

    def test_guest_refusals_are_reported_and_leave_no_transfer(self):
        with self.assertRaisesRegex(RuntimeError, "refused"):
            self.push("refuse", b"x")
        with self.assertRaisesRegex(RuntimeError, "no such file"):
            self.agent.perform({"op": "files.pull", **self.ids, "name": "missing"})
        self.assertEqual(self.agent.transfers, {})

    def test_bad_requests_never_start_a_process(self):
        for bad in ({"size": -1}, {"size": True}, {"size": 1 << 41}, {"name": 5}, {"sandbox": "x"}):
            with self.subTest(bad=bad), self.assertRaises((ValueError, TypeError, AttributeError)):
                self.agent.perform({"op": "files.push", **self.ids, "name": "a", "size": 1, **bad})
        self.assertEqual(self.agent.transfers, {})

    def test_transfers_end_with_the_control_channel(self):
        started = self.agent.perform({"op": "files.pull", **self.ids, "name": "slow"})
        process = self.agent.transfers[started["transfer"]].process
        self.agent.stop_transfers()
        self.assertIsNotNone(process.poll())
        self.assertEqual(self.agent.transfers, {})


if __name__ == "__main__":
    unittest.main()
