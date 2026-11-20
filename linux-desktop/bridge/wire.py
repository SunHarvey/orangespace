"""Small framed protocol for one private virtio serial device per VM."""
import hashlib
import hmac
import json
import os
import queue
import socket
import struct
import threading
import uuid

REQUEST, REPLY, OPEN, DATA, CLOSE, CREDIT = range(1, 7)
HEADER = struct.Struct("!BII")
BLOCK = 16384
MAX_PAYLOAD = 65536
MAX_STREAMS = 48
WINDOW = 32
PREFIX = b"OrangeSpace-Linux-Desktop-v1\0"


def identity(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError("invalid workspace identifier")
    return value


def read_exact(file, size):
    result = bytearray()
    while len(result) < size:
        part = file.read(size - len(result))
        if not part:
            raise EOFError("channel disconnected")
        result.extend(part)
    return bytes(result)


def write_all(file, data):
    view = memoryview(data)
    while view:
        count = file.write(view)
        if not count:
            raise EOFError("channel closed while writing")
        view = view[count:]


def encode(value):
    return json.dumps(value, separators=(",", ":"), allow_nan=False, ensure_ascii=False).encode()


def authenticate(file, key, *, host):
    if len(key) != 32:
        raise ValueError("invalid VM boot key")
    def proof(label, challenges):
        return hmac.digest(key, PREFIX + label + challenges, hashlib.sha256)
    if host:
        first = os.urandom(32)
        write_all(file, first)
        second = read_exact(file, 32)
        if not hmac.compare_digest(read_exact(file, 32), proof(b"guest", first + second)):
            raise ValueError("guest boot identity mismatch")
        write_all(file, proof(b"host", first + second))
    else:
        first = read_exact(file, 32)
        second = os.urandom(32)
        write_all(file, second + proof(b"guest", first + second))
        if not hmac.compare_digest(read_exact(file, 32), proof(b"host", first + second)):
            raise ValueError("host boot identity mismatch")


def background(fn, *args):
    thread = threading.Thread(target=fn, args=args, daemon=True)
    thread.start()
    return thread


class Channel:
    def __init__(self, file):
        self.file = file
        self.lock = threading.Lock()

    def send(self, kind, number, payload=b""):
        if not 0 < number <= 0xffffffff or len(payload) > MAX_PAYLOAD:
            raise ValueError("invalid frame")
        with self.lock:
            write_all(self.file, HEADER.pack(kind, number, len(payload)) + payload)

    def receive(self):
        kind, number, size = HEADER.unpack(read_exact(self.file, HEADER.size))
        if not number or kind not in (REQUEST, REPLY, OPEN, DATA, CLOSE, CREDIT) or size > MAX_PAYLOAD:
            raise ValueError("invalid frame header")
        if (kind in (CLOSE, CREDIT) and size) or (kind == DATA and not 0 < size <= BLOCK):
            raise ValueError("invalid stream frame")
        return kind, number, read_exact(self.file, size)


class SocketEndpoint:
    def __init__(self, sock):
        self.sock = sock

    def read(self):
        return self.sock.recv(BLOCK)

    def write(self, data):
        self.sock.sendall(data)

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


class Streams:
    """A slow X client consumes only its own bounded queue."""
    def __init__(self, channel):
        self.channel = channel
        self.lock = threading.Lock()
        self.window = threading.Condition(self.lock)
        self.credits = {}
        self.items = {}

    def add(self, number, sandbox, endpoint, announce=None):
        outgoing = queue.Queue(maxsize=WINDOW + 1)
        with self.lock:
            if number in self.items or sum(s == sandbox for s, _, _ in self.items.values()) >= MAX_STREAMS:
                endpoint.close()
                raise ValueError("too many display connections")
            self.items[number] = sandbox, endpoint, outgoing
            self.credits[number] = WINDOW
        if announce:
            try:
                announce()
            except Exception:
                self.close(number, notify=False)
                raise
        background(self._read, number, endpoint)
        background(self._write, number, endpoint, outgoing)

    def _read(self, number, endpoint):
        try:
            while data := endpoint.read():
                with self.window:
                    self.window.wait_for(lambda: self.credits.get(number) != 0)
                    if number not in self.credits:
                        break
                    self.credits[number] -= 1
                self.channel.send(DATA, number, data)
        except (OSError, ValueError, EOFError):
            pass
        finally:
            self.close(number, notify=True)

    def _write(self, number, endpoint, outgoing):
        try:
            while (data := outgoing.get()) is not None:
                endpoint.write(data)
                self.channel.send(CREDIT, number)
        except (OSError, ValueError, EOFError):
            pass
        finally:
            self.close(number, notify=True)

    def credit(self, number):
        with self.window:
            if number in self.credits:
                if self.credits[number] >= WINDOW:
                    raise ValueError("invalid display credit")
                self.credits[number] += 1
                self.window.notify_all()

    def data(self, number, payload):
        with self.lock:
            entry = self.items.get(number)
            if not entry:
                return
            try:
                entry[2].put_nowait(payload)
                return
            except queue.Full:
                pass
        self.close(number, notify=True)

    def finish(self, number):
        with self.lock:
            entry = self.items.get(number)
            if not entry:
                return
            try:
                entry[2].put_nowait(None)
                return
            except queue.Full:
                pass
        self.close(number, notify=False)

    def close(self, number, *, notify):
        with self.window:
            entry = self.items.pop(number, None)
            self.credits.pop(number, None)
            self.window.notify_all()
        if entry:
            _, endpoint, outgoing = entry
            if notify:
                try:
                    self.channel.send(CLOSE, number)
                except (OSError, EOFError, ValueError):
                    pass
            endpoint.close()
            while True:
                try:
                    outgoing.put_nowait(None)
                    break
                except queue.Full:
                    try:
                        outgoing.get_nowait()
                    except queue.Empty:
                        pass

    def discard(self, sandbox=None):
        with self.lock:
            ids = [i for i, (owner, _, _) in self.items.items() if sandbox is None or owner == sandbox]
        for number in ids:
            self.close(number, notify=True)
