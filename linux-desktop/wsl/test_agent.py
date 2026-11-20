"""Runs the agent as a real child process over pipes, as wsl.exe does."""
import json
from pathlib import Path
import struct
import subprocess
import sys
import unittest

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
        self.assertEqual(reply, {"ready": True, "agent_version": 1})
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


if __name__ == "__main__":
    unittest.main()
