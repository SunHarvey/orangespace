"""Framed request/reply protocol between the Windows client and the guest agent.

Each frame is a `!BII` header (kind, request number, payload size) followed by
at most 64 KiB of payload. The client sends REQUEST frames and the agent answers
each with a REPLY frame carrying the same number. The frame layout and kind
values are shared with the C++ client (apps/windows-client, wsl_runtime).
"""
import json
import struct
import threading

REQUEST, REPLY = 1, 2
HEADER = struct.Struct("!BII")
MAX_PAYLOAD = 65536


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


class Channel:
    def __init__(self, file):
        self.file = file
        self.lock = threading.Lock()

    def send(self, kind, number, payload=b""):
        if kind not in (REQUEST, REPLY) or not 0 < number <= 0xffffffff or len(payload) > MAX_PAYLOAD:
            raise ValueError("invalid frame")
        with self.lock:
            write_all(self.file, HEADER.pack(kind, number, len(payload)) + payload)

    def receive(self):
        kind, number, size = HEADER.unpack(read_exact(self.file, HEADER.size))
        if not number or kind not in (REQUEST, REPLY) or size > MAX_PAYLOAD:
            raise ValueError("invalid frame header")
        return kind, number, read_exact(self.file, size)
