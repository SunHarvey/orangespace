#!/usr/bin/env python3
"""OrangeSpace guest agent for the WSL2 distribution.

The Windows client starts it as `wsl.exe -d OrangeSpace -u root -- python3
/opt/orangespace/wsl/agent.py` and talks over that process's stdin/stdout.
The pipes belong to the client process, so owning them is the
authentication: no port, socket or named pipe is exposed.

Wire format: after the agent writes MARKER, both sides exchange frames from
bridge/wire.py (`!BII` = kind, number, payload size; payload <= 64 KiB). Only
REQUEST (client -> agent) and REPLY (agent -> client) are used. Requests are
JSON objects with an "op"; replies are JSON objects, with "error" on failure.
Anything the agent logs goes to stderr, never stdout.
"""
import concurrent.futures
import json
import subprocess
import uuid
import os
from pathlib import Path
import sys
import threading

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "bridge"))
from wire import Channel, encode, REPLY, REQUEST  # noqa: E402

MARKER = b"OrangeSpace-WSL-Agent-v1\n"
VERSION = 1
DESKTOP = Path(__file__).resolve().parent.parent / "guest" / "desktop"
MAX_NODE_CONFIG = 32768


class StdioPort:
    """Binary, unbuffered stdin/stdout as one file-like port for wire.Channel."""

    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer

    def read(self, size):
        return self.reader.read(size)

    def write(self, data):
        count = self.writer.write(data)
        self.writer.flush()
        return count


def mounted(path):
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as info:
            return any(line.split()[4] == path for line in info)
    except OSError:
        return False


def os_release():
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip('"')
    except OSError:
        pass
    return "unknown"


def interop_enabled():
    """Whether this distribution can start Windows programs.

    binfmt_misc is shared by every distribution in the WSL VM, so the
    WSLInterop registration says nothing about this one. With interop off in
    /etc/wsl.conf, WSL gives processes no WSL_INTEROP session socket and
    refuses to launch Windows executables (verified 2026-11-20).
    """
    if os.environ.get("WSL_INTEROP"):
        return True
    import configparser
    conf = configparser.ConfigParser()
    try:
        conf.read("/etc/wsl.conf", encoding="utf-8")
    except (OSError, configparser.Error):
        return True
    return conf.get("interop", "enabled", fallback="true").strip().lower() != "false"


def facts():
    """What the client checks before trusting this distribution."""
    windows_drives = sorted(p.name for p in Path("/mnt").iterdir() if len(p.name) == 1 and mounted(str(p))) \
        if Path("/mnt").is_dir() else []
    return {
        "agent_version": VERSION,
        "os": os_release(),
        "kernel": os.uname().release,
        "systemd": Path("/run/systemd/system").is_dir(),
        "windows_drives": windows_drives,          # must be empty: automount disabled
        "interop": interop_enabled(),              # must be False
        "wslg": Path("/mnt/wslg/.X11-unix/X0").exists(),
    }


def canonical(value, what):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError(f"invalid {what}")
    return value


class Agent:
    def __init__(self, channel, desktop=DESKTOP):
        self.ch = channel
        self.desktop = str(desktop)
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=8)
        self.ending = threading.Event()
        self.started = {}          # sandbox -> user, for stopping on disconnect
        self.started_lock = threading.Lock()
        self.ops = {"ping": self.ping, "facts": lambda request: facts(), "shutdown": self.shutdown,
                    "desktop.start": self.desktop_start, "desktop.stop": self.desktop_simple,
                    "desktop.status": self.desktop_simple, "desktop.delete": self.desktop_simple,
                    "desktop.configure": self.desktop_configure, "desktop.lease": self.desktop_lease,
                    "desktop.renew": self.desktop_renew}

    def run_desktop(self, args, stdin=None, timeout=150):
        """guest/desktop prints one JSON object; its per-sandbox lock serializes
        competing requests for the same sandbox."""
        try:
            # Never let the child inherit our stdin: it is the client's control channel.
            proc = subprocess.run([self.desktop, *args], input=stdin if stdin is not None else b"",
                                  capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise RuntimeError("desktop operation timed out") from None
        try:
            result = json.loads(proc.stdout)
        except ValueError:
            raise RuntimeError("desktop operation failed") from None
        if not isinstance(result, dict) or proc.returncode:
            raise RuntimeError(str((result.get("error") if isinstance(result, dict) else None)
                                   or "desktop operation failed")[:240])
        return result

    def desktop_start(self, request):
        user, sandbox = canonical(request["user"], "user"), canonical(request["sandbox"], "sandbox")
        node, title = canonical(request["node"], "node"), request["title"]
        if not isinstance(title, str):
            raise ValueError("invalid window title")
        with self.started_lock:
            self.started[sandbox] = user
        return self.run_desktop(["start", user, sandbox, node, title])

    def desktop_simple(self, request):
        op = request["op"].split(".", 1)[1]
        user, sandbox = canonical(request["user"], "user"), canonical(request["sandbox"], "sandbox")
        result = self.run_desktop([op, user, sandbox])
        if op in ("stop", "delete"):
            with self.started_lock:
                self.started.pop(sandbox, None)
        return result

    def desktop_configure(self, request):
        user, sandbox = canonical(request["user"], "user"), canonical(request["sandbox"], "sandbox")
        node, settings = canonical(request["node"], "node"), request["settings"]
        if not isinstance(settings, str) or len(settings.encode("utf-8")) > MAX_NODE_CONFIG:
            raise ValueError("node configuration must be UTF-8 text of at most 32768 bytes")
        return self.run_desktop(["configure", user, sandbox, node], stdin=settings.encode("utf-8"), timeout=20)

    def desktop_lease(self, request):
        """A new node lease (tunnel credentials) for one sandbox; never logged."""
        user, sandbox = canonical(request["user"], "user"), canonical(request["sandbox"], "sandbox")
        node, lease = canonical(request["node"], "node"), request["lease"]
        if not isinstance(lease, str) or len(lease.encode("utf-8")) > MAX_NODE_CONFIG:
            raise ValueError("node lease must be UTF-8 text of at most 32768 bytes")
        return self.run_desktop(["lease", user, sandbox, node], stdin=lease.encode("utf-8"), timeout=60)

    def desktop_renew(self, request):
        user, sandbox = canonical(request["user"], "user"), canonical(request["sandbox"], "sandbox")
        tunnel, remaining = canonical(request["tunnel"], "tunnel"), request["remaining_ms"]
        if type(remaining) is not int or not 0 < remaining <= 30000:
            raise ValueError("invalid lease budget")
        return self.run_desktop(["renew", user, sandbox, tunnel, str(remaining)], timeout=10)

    def stop_started(self):
        """The client went away: no desktop outlives its control channel."""
        with self.started_lock:
            started, self.started = dict(self.started), {}
        for sandbox, user in started.items():
            try:
                self.run_desktop(["stop", user, sandbox])
            except (RuntimeError, OSError):
                pass

    def ping(self, request):
        return {"ready": not self.ending.is_set(), "agent_version": VERSION}

    def shutdown(self, request):
        self.ending.set()
        return {"stopping": True}

    def perform(self, request):
        if not isinstance(request, dict) or not isinstance(request.get("op"), str):
            raise ValueError("expected a JSON object with an op")
        handler = self.ops.get(request["op"])
        if handler is None:
            raise ValueError("unknown operation")
        if self.ending.is_set() and request["op"] != "ping":
            raise ValueError("agent is stopping")
        return handler(request)

    def reply(self, number, payload):
        try:
            response = self.perform(json.loads(payload))
        except (KeyError, OSError, ValueError, TypeError, RuntimeError) as error:
            response = {"error": str(error)[:280]}
        try:
            self.ch.send(REPLY, number, encode(response))
        except (OSError, ValueError, EOFError):
            pass

    def run(self):
        try:
            while not self.ending.is_set():
                kind, number, payload = self.ch.receive()
                if kind != REQUEST:
                    raise ValueError("unexpected client frame")
                try:
                    request = json.loads(payload)
                    op = request.get("op") if isinstance(request, dict) else None
                except ValueError:
                    op = None
                if op == "shutdown":
                    self.reply(number, payload)  # answer before leaving the loop
                    break
                self.pool.submit(self.reply, number, payload)
        except (EOFError, ValueError):
            pass  # client gone or protocol violation: stop serving
        finally:
            self.ending.set()
            self.pool.shutdown(wait=True, cancel_futures=True)
            self.stop_started()


def main():
    reader = os.fdopen(0, "rb", buffering=0)
    writer = os.fdopen(1, "wb", buffering=0)
    port = StdioPort(reader, writer)
    port.write(MARKER)
    Agent(Channel(port)).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
