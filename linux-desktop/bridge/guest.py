"""Root guest service. The single control peer authenticates with this VM's boot key."""
import concurrent.futures
import itertools
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import threading

from wire import (Channel, Streams, SocketEndpoint, authenticate, background, encode,
                  identity, DATA, CLOSE, OPEN, REPLY, REQUEST, CREDIT)


def authority(cookie):
    # FamilyWild matches the container hostname. Include only display zero.
    fields = [b"", b"0", b"MIT-MAGIC-COOKIE-1", cookie]
    return b"\xff\xff" + b"".join(struct.pack("!H", len(s)) + s for s in fields)


class DesktopDisplay:
    def __init__(self, agent, user, sandbox, node, cookie):
        self.agent, self.user, self.sandbox, self.node = agent, user, sandbox, node
        self.cookie = cookie
        self.dir = agent.root / sandbox
        self.sock = socket.socket(socket.AF_UNIX)
        self.closed = threading.Event()
        try:
            # RuntimeDirectory is root-owned. Only the service creates entries here.
            self.dir.mkdir(mode=0o755, exist_ok=True)
            self.dir.chmod(0o755)
            (self.dir / "X0").unlink(missing_ok=True)
            auth = self.dir / "Xauthority"
            auth.write_bytes(authority(cookie))
            os.chown(auth, -1, agent.display_gid)
            auth.chmod(0o440)
            self.sock.bind(str(self.dir / "X0"))
            (self.dir / "X0").chmod(0o666)
            self.sock.listen(16)
            self.sock.settimeout(1)
        except BaseException:
            self.close()
            raise

    def accept(self):
        while not self.closed.is_set():
            try:
                sock, _ = self.sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            number = next(self.agent.stream_numbers)
            try:
                self.agent.streams.add(number, self.sandbox, SocketEndpoint(sock),
                    announce=lambda: self.agent.ch.send(OPEN, number, self.sandbox.encode()))
            except (OSError, EOFError, ValueError):
                sock.close()

    def close(self):
        self.closed.set()
        self.sock.close()
        self.agent.streams.discard(self.sandbox)
        for name in ("X0", "Xauthority"):
            (self.dir / name).unlink(missing_ok=True)
        try:
            self.dir.rmdir()
        except OSError:
            pass


class Agent:
    def __init__(self, channel, root, desktop, display_gid=1000):
        self.ch = channel
        self.root = Path(root)
        self.desktop = desktop
        self.display_gid = display_gid
        self.streams = Streams(channel)
        self.stream_numbers = itertools.count(1)
        self.displays = {}
        self.locks = [threading.Lock() for _ in range(64)]
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=8)
        self.ending = threading.Event()

    def command(self, op, user, sandbox, node=None, settings=None):
        args = [self.desktop, op, user, sandbox]
        if op in ("start", "configure"):
            args.append(node)
        proc = subprocess.run(args, input=settings, capture_output=True, timeout=150)
        try:
            result = json.loads(proc.stdout)
        except ValueError:
            raise RuntimeError(f"desktop {op} failed") from None
        if not isinstance(result, dict) or proc.returncode:
            message = result.get("error") if isinstance(result, dict) else None
            raise RuntimeError(str(message or f"desktop {op} failed")[:240])
        return result

    def perform(self, request):
        op = request["op"]
        user, sid = identity(request["user"]), identity(request["sandbox"])
        if op not in ("start", "stop", "status", "configure"):
            raise ValueError("unknown desktop operation")
        with self.locks[hash(sid) % len(self.locks)]:
            display = self.displays.get(sid)
            if display and display.user != user:
                raise ValueError("workspace owner mismatch")
            if op == "configure":
                if display:
                    raise ValueError("stop the desktop before importing a node")
                if not isinstance(request["settings"], str):
                    raise ValueError("expected a UTF-8 node configuration")
                settings = request["settings"].encode("utf-8")
                if len(settings) > 32768:
                    raise ValueError("node configuration is too large")
                return self.command(op, user, sid, identity(request["node"]), settings)
            if op == "start":
                if self.ending.is_set():
                    raise ValueError("control connection closed")
                node = identity(request["node"])
                cookie = bytes.fromhex(request["cookie"])
                if len(cookie) != 16:
                    raise ValueError("invalid X authority")
                if display and (display.node != node or display.cookie != cookie):
                    raise ValueError("stop the existing desktop before changing its display or node")
                if not display:
                    previous = self.command("status", user, sid)
                    if previous.get("desktop") != "stopped":
                        raise ValueError("stop the previous desktop before reconnecting")
                    display = DesktopDisplay(self, user, sid, node, cookie)
                    self.displays[sid] = display
                    background(display.accept)
                try:
                    return self.command(op, user, sid, node)
                except Exception:
                    # Reconcile partial starts through the same lifecycle owner.
                    try:
                        self.command("stop", user, sid)
                    finally:
                        self.displays.pop(sid, None)
                        display.close()
                    raise
            result = self.command(op, user, sid)
            if op == "stop" and display:
                self.displays.pop(sid, None)
                display.close()
            return result

    def reply(self, number, payload):
        try:
            response = self.perform(json.loads(payload))
        except (KeyError, OSError, ValueError, TypeError, RuntimeError, subprocess.TimeoutExpired) as error:
            response = {"error": str(error)[:280]}
        try:
            self.ch.send(REPLY, number, encode(response))
        except (OSError, ValueError, EOFError):
            pass

    def run(self):
        self.root.mkdir(parents=True, exist_ok=True, mode=0o711)
        try:
            while True:
                kind, number, payload = self.ch.receive()
                if kind == REQUEST:
                    self.pool.submit(self.reply, number, payload)
                elif kind == DATA:
                    self.streams.data(number, payload)
                elif kind == CREDIT:
                    self.streams.credit(number)
                elif kind == CLOSE:
                    self.streams.finish(number)
                else:
                    raise ValueError("unexpected host frame")
        finally:
            self.ending.set()
            self.pool.shutdown(wait=True, cancel_futures=True)
            for sid, display in list(self.displays.items()):
                try:
                    self.command("stop", display.user, sid)
                except Exception:
                    pass
                display.close()


if __name__ == "__main__":
    key = Path("/sys/firmware/qemu_fw_cfg/by_name/opt/orangespace/key/raw").read_bytes()
    with open("/dev/virtio-ports/org.orangespace.control", "r+b", buffering=0) as port:
        authenticate(port, key, host=False)
        Agent(Channel(port), "/run/orangespace/display", "/opt/orangespace/guest/desktop").run()
