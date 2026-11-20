"""Duplex Windows named pipe client. Concurrent read and write need overlapped I/O."""
import ctypes as C
import re
import time
from ctypes import wintypes as W


class Overlapped(C.Structure):
    _fields_ = [("internal", C.c_size_t), ("high", C.c_size_t), ("offset", W.DWORD),
                ("offset_high", W.DWORD), ("event", W.HANDLE)]


class QemuPipe:
    def __init__(self, name, expected_pid):
        if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,128}", name) or expected_pid <= 0:
            raise ValueError("invalid QEMU pipe identity")
        kernel = C.WinDLL("kernel32", use_last_error=True)
        def api(name, returns, *args):
            fn = getattr(kernel, name)
            fn.restype, fn.argtypes = returns, args
            return fn
        handle, dword, ptr = W.HANDLE, W.DWORD, C.c_void_p
        dwordp, ovp = C.POINTER(dword), C.POINTER(Overlapped)
        create = api("CreateFileW", handle, W.LPCWSTR, dword, dword, ptr, dword, dword, handle)
        server = api("GetNamedPipeServerProcessId", W.BOOL, handle, dwordp)
        self.event = api("CreateEventW", handle, ptr, W.BOOL, W.BOOL, W.LPCWSTR)
        self.readfile = api("ReadFile", W.BOOL, handle, ptr, dword, dwordp, ovp)
        self.writefile = api("WriteFile", W.BOOL, handle, ptr, dword, dwordp, ovp)
        self.result = api("GetOverlappedResult", W.BOOL, handle, ovp, dwordp, W.BOOL)
        self.closehandle = api("CloseHandle", W.BOOL, handle)
        deadline = time.monotonic() + 30
        while True:
            self.handle = create("\\\\.\\pipe\\" + name, 0xC0000000, 0, None, 3,
                                 0x40000000 | 0x00100000, None)  # OVERLAPPED, SQOS/anonymous
            if self.handle != C.c_void_p(-1).value:
                break
            if C.get_last_error() not in (2, 231) or time.monotonic() >= deadline:
                raise C.WinError(C.get_last_error())
            time.sleep(0.1)
        pid = dword()
        if not server(self.handle, C.byref(pid)) or pid.value != expected_pid:
            self.close()
            raise RuntimeError("unexpected QEMU pipe server")

    def _io(self, function, buf, size):
        ov = Overlapped()
        ov.event = self.event(None, True, False, None)
        if not ov.event:
            raise C.WinError(C.get_last_error())
        try:
            count = W.DWORD()
            if not function(self.handle, buf, size, C.byref(count), C.byref(ov)):
                if C.get_last_error() != 997:
                    raise C.WinError(C.get_last_error())
                if not self.result(self.handle, C.byref(ov), C.byref(count), True):
                    raise C.WinError(C.get_last_error())
            return count.value
        finally:
            self.closehandle(ov.event)

    def read(self, size):
        buf = C.create_string_buffer(size)
        count = self._io(self.readfile, buf, size)
        return buf.raw[:count]

    def write(self, data):
        data = bytes(data)
        buf = C.create_string_buffer(data)
        return self._io(self.writefile, buf, len(data))

    def close(self):
        if self.handle:
            self.closehandle(self.handle)
            self.handle = None
