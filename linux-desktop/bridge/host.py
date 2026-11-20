"""Per-VM local display broker and the manager's command-line client."""
import argparse
import itertools
import json
import os
from pathlib import Path
import queue
import re
import secrets
import socket
import socketserver
import struct
import subprocess
import sys
import threading

from wire import (Channel, Streams, authenticate, background, encode, identity, read_exact,
                  write_all, BLOCK, MAX_PAYLOAD, CLOSE, OPEN, REQUEST, REPLY, DATA, CREDIT)


class Relay:
    def __init__(self, executable, display):
        self.proc = subprocess.Popen([executable, "STDIO", f"UNIX-CONNECT:/tmp/.X11-unix/X{display}"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))

    def read(self):
        return self.proc.stdout.read(BLOCK)

    def write(self, data):
        write_all(self.proc.stdin, data)

    def close(self):
        self.proc.kill()
        self.proc.wait()
        self.proc.stdin.close()
        self.proc.stdout.close()


class Hub:
    def __init__(self, channel, relay_factory=Relay):
        self.ch = channel
        self.relay = relay_factory
        self.streams = Streams(channel)
        self.closed = threading.Event()
        self.mutex = threading.Lock()
        self.pending = {}
        self.displays = {}
        self.numbers = itertools.count(1)
        self.locks = [threading.Lock() for _ in range(64)]

    def request(self, message, timeout):
        number, reply = next(self.numbers), queue.Queue(1)
        with self.mutex:
            if self.closed.is_set():
                raise EOFError("guest disconnected")
            self.pending[number] = reply
        try:
            self.ch.send(REQUEST, number, encode(message))
            try:
                return reply.get(timeout=timeout)
            except queue.Empty:
                raise TimeoutError("guest command timed out; check status or stop the desktop") from None
        finally:
            with self.mutex:
                self.pending.pop(number, None)

    def run(self):
        try:
            while not self.closed.is_set():
                kind, number, payload = self.ch.receive()
                if kind == REPLY:
                    with self.mutex:
                        reply = self.pending.get(number)
                        if reply:
                            reply.put_nowait(json.loads(payload))
                elif kind == OPEN:
                    sid = identity(payload.decode())
                    with self.mutex:
                        display = self.displays.get(sid)
                    if display:
                        try:
                            self.streams.add(number, sid, self.relay(display["relay"], display["display"]))
                            continue
                        except (OSError, ValueError):
                            pass
                    self.ch.send(CLOSE, number)
                elif kind == DATA:
                    self.streams.data(number, payload)
                elif kind == CREDIT:
                    self.streams.credit(number)
                elif kind == CLOSE:
                    self.streams.finish(number)
                else:
                    raise ValueError("unexpected guest frame")
        except (OSError, EOFError, ValueError):
            pass
        finally:
            with self.mutex:
                self.closed.set()
                for reply in self.pending.values():
                    if reply.empty():
                        reply.put_nowait({"error": "guest disconnected"})
            self.streams.discard()

    def command(self, spec):
        op = spec["op"]
        if op == "ping":
            return {"ready": not self.closed.is_set()}
        if op == "shutdown":
            self.closed.set()
            return {"stopping": True}
        if op not in ("start", "stop", "status", "configure"):
            raise ValueError("unknown host operation")
        user, sid = identity(spec["user"]), identity(spec["sandbox"])
        timeout = int(spec.get("timeout", 90))
        if not 1 <= timeout <= 180:
            raise ValueError("invalid timeout")
        with self.locks[hash(sid) % len(self.locks)]:
            with self.mutex:
                existing = self.displays.get(sid)
            if existing and existing["user"] != user:
                raise ValueError("unexpected desktop owner")
            message = {"op": op, "user": user, "sandbox": sid}
            if op == "configure":
                if existing:
                    raise ValueError("stop the desktop before importing a node")
                message.update(node=identity(spec["node"]), settings=spec["settings"])
            if op == "start":
                node = identity(spec["node"])
                display = spec["display"]
                if type(display) is not int or not 0 <= display <= 65535:
                    raise ValueError("invalid X display number")
                cookie = bytes.fromhex(spec["cookie"])
                if len(cookie) != 16:
                    raise ValueError("invalid cookie file")
                binding = {"user": user, "relay": spec["relay"], "display": display,
                           "cookie": cookie.hex(), "node": node}
                with self.mutex:
                    if existing and existing != binding:
                        raise ValueError("stop the existing display before replacing its binding")
                    if any(v["display"] == display and k != sid for k, v in self.displays.items()):
                        raise ValueError("X display belongs to another sandbox")
                    self.displays[sid] = binding
                message.update(node=node, cookie=cookie.hex())
            # On ambiguous timeout retain the binding for explicit stop/reconciliation.
            result = self.request(message, timeout)
            if (op == "start" and "error" in result and not existing) or (op == "stop" and "error" not in result):
                with self.mutex:
                    self.displays.pop(sid, None)
                self.streams.discard(sid)
            return result


def read_message(file):
    size = struct.unpack("!I", read_exact(file, 4))[0]
    if not 0 < size <= MAX_PAYLOAD:
        raise ValueError("invalid local request")
    value = json.loads(read_exact(file, size))
    if not isinstance(value, dict):
        raise ValueError("invalid local message")
    return value


def send_message(file, value):
    data = encode(value)
    if len(data) > MAX_PAYLOAD:
        raise ValueError("local message is too large")
    write_all(file, struct.pack("!I", len(data)) + data)


class LocalServer(socketserver.ThreadingTCPServer):
    daemon_threads = True


def rendezvous(args):
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,128}", args.pipe):
        raise ValueError("invalid pipe name")
    return args.state_dir / (args.pipe + ".hub.json")


def serve(args):
    from winpipe import QemuPipe
    info = rendezvous(args)
    if args.qemu_pid is None or args.key_file is None:
        raise ValueError("missing QEMU identity")
    pipe = QemuPipe(args.pipe, args.qemu_pid)
    local_key = secrets.token_bytes(32)
    try:
        authenticate(pipe, args.key_file.read_bytes(), host=True)
        hub = Hub(Channel(pipe))
        background(hub.run)

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    self.request.settimeout(5)
                    with self.request.makefile("rwb", buffering=0) as conn:
                        authenticate(conn, local_key, host=False)
                        request = read_message(conn)
                        try:
                            result = hub.command(request)
                        except (KeyError, ValueError, TypeError, EOFError, OSError) as error:
                            result = {"error": str(error)}
                        send_message(conn, result)
                except (OSError, ValueError, EOFError):
                    return

        with LocalServer(("127.0.0.1", 0), Handler) as server:
            server.timeout = 0.25
            tmp = info.with_suffix(".tmp")
            with open(tmp, "x", encoding="utf-8") as out:
                json.dump({"port": server.server_address[1], "key": local_key.hex()}, out)
            os.replace(tmp, info)
            while not hub.closed.is_set():
                server.handle_request()
    finally:
        info.unlink(missing_ok=True)
        pipe.close()


def client(args):
    info = json.loads(rendezvous(args).read_text(encoding="utf-8"))
    message = {"op": args.command, "user": args.user, "sandbox": args.sandbox,
               "node": args.node, "timeout": args.timeout}
    if args.command == "configure":
        if not args.config_file:
            raise ValueError("select a private node JSON file")
        with args.config_file.open("rb") as source:
            raw = source.read(32769)
        if len(raw) > 32768:
            raise ValueError("node configuration is too large")
        # Preserve duplicate fields for the guest's strict schema validation.
        message["settings"] = raw.decode("utf-8-sig")
    if args.command == "start":
        if not args.cookie_file or not args.x_relay or not args.x_relay.is_file():
            raise ValueError("missing display relay or authority")
        message.update(display=args.display, cookie=args.cookie_file.read_bytes().hex(),
                       relay=str(args.x_relay.resolve()))
    with socket.create_connection(("127.0.0.1", info["port"]), timeout=3) as sock:
        sock.settimeout(args.timeout + 5)
        with sock.makefile("rwb", buffering=0) as conn:
            authenticate(conn, bytes.fromhex(info["key"]), host=True)
            send_message(conn, message)
            return read_message(conn)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--pipe", required=True)
    parser.add_argument("--qemu-pid", type=int)
    parser.add_argument("--key-file", type=Path)
    parser.add_argument("--user")
    parser.add_argument("--sandbox")
    parser.add_argument("--node")
    parser.add_argument("--display", type=int)
    parser.add_argument("--x-relay", type=Path)
    parser.add_argument("--cookie-file", type=Path)
    parser.add_argument("--config-file", type=Path)
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("command", choices=("serve", "ping", "start", "stop", "status", "configure", "shutdown"))
    args = parser.parse_args()
    try:
        if args.command == "serve":
            serve(args)
            return 0
        result = client(args)
    except (OSError, EOFError, ValueError, TypeError, KeyError, RuntimeError) as error:
        result = {"error": str(error)}
    print(json.dumps(result, ensure_ascii=True), flush=True)
    return int("error" in result)


if __name__ == "__main__":
    sys.exit(main())
