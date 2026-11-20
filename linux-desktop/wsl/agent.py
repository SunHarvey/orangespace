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
import os
from pathlib import Path
import sys
import threading

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "bridge"))
from wire import Channel, encode, REPLY, REQUEST  # noqa: E402

MARKER = b"OrangeSpace-WSL-Agent-v1\n"
VERSION = 1


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


class Agent:
    def __init__(self, channel):
        self.ch = channel
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=8)
        self.ending = threading.Event()
        self.ops = {"ping": self.ping, "facts": lambda request: facts(), "shutdown": self.shutdown}

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


def main():
    reader = os.fdopen(0, "rb", buffering=0)
    writer = os.fdopen(1, "wb", buffering=0)
    port = StdioPort(reader, writer)
    port.write(MARKER)
    Agent(Channel(port)).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
