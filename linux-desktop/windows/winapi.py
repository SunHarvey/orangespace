"""Small Win32 boundary. Imported by the manager on Windows only."""
import csv
import ctypes
import msvcrt
import re
import subprocess
from ctypes import wintypes as w


def private_directory(path):
    """Replace the directory DACL, including inherited ACEs, before creating secrets."""
    path.mkdir(parents=True, exist_ok=True)
    if path.lstat().st_file_attributes & 0x400:
        raise ValueError("运行目录不能是重解析点")
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    who = subprocess.check_output(
        [str(system_binary("whoami.exe")), "/user", "/fo", "csv", "/nh"],
        creationflags=subprocess.CREATE_NO_WINDOW
    ).decode("ascii", errors="replace")
    sid = next(csv.reader([who.strip()]))[-1]
    if not re.fullmatch(r"S-1-(?:\d+-)+\d+", sid):
        raise ValueError("无法识别 Windows 登录身份")
    descriptor = ctypes.c_void_p()
    sddl = f"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{sid})"
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        w.LPCWSTR, w.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        adv.SetFileSecurityW.argtypes = [w.LPCWSTR, w.DWORD, ctypes.c_void_p]
        if not adv.SetFileSecurityW(str(path), 0x80000004, descriptor):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree(descriptor)


def system_binary(name):
    from pathlib import Path
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    buf = ctypes.create_unicode_buffer(32768)
    length = kernel.GetSystemDirectoryW(buf, len(buf))
    if not 0 < length < len(buf):
        raise ctypes.WinError(ctypes.get_last_error())
    return Path(buf.value) / name


def single_manager(directory):
    handle = (directory / "manager.lock").open("a+b")
    try:
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    except OSError:
        handle.close()
        raise ValueError("当前 Windows 用户已经运行了客户端") from None
    return handle


def own_process_tree():
    """The manager joins the job before spawning children. All handles are non-inheritable."""
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    size = ctypes.c_size_t

    class Basic(ctypes.Structure):
        _fields_ = [("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong),
                    ("flags", w.DWORD), ("min_ws", size), ("max_ws", size),
                    ("process_limit", w.DWORD), ("affinity", size),
                    ("priority", w.DWORD), ("scheduling", w.DWORD)]

    class Extended(ctypes.Structure):
        _fields_ = [("basic", Basic), ("io", ctypes.c_ulonglong * 6),
                    ("process_memory", size), ("job_memory", size),
                    ("peak_process", size), ("peak_job", size)]

    kernel.CreateJobObjectW.restype = w.HANDLE
    kernel.GetCurrentProcess.restype = w.HANDLE
    kernel.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
    kernel.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
    job = kernel.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    info = Extended()
    info.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if (not kernel.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info))
            or not kernel.AssignProcessToJobObject(job, kernel.GetCurrentProcess())):
        raise ctypes.WinError(ctypes.get_last_error())
    # The OS releases this handle on manager exit, including abnormal exit.
    return job


def window(pid, title=None, activate=False):
    user = ctypes.WinDLL("user32", use_last_error=True)
    found = []
    callback_type = ctypes.WINFUNCTYPE(w.BOOL, w.HWND, w.LPARAM)
    user.GetWindowThreadProcessId.argtypes = [w.HWND, ctypes.POINTER(w.DWORD)]
    user.IsWindowVisible.argtypes = [w.HWND]
    user.GetWindowTextLengthW.argtypes = [w.HWND]

    @callback_type
    def visit(hwnd, _):
        owner = w.DWORD()
        user.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value == pid and user.IsWindowVisible(hwnd) and user.GetWindowTextLengthW(hwnd):
            found.append(hwnd)
            return False
        return True

    user.EnumWindows(visit, 0)
    if found:
        hwnd = found[0]
        if title:
            user.SetWindowTextW.argtypes = [w.HWND, w.LPCWSTR]
            user.SetWindowTextW(hwnd, title)
        if activate:
            user.ShowWindow.argtypes = [w.HWND, ctypes.c_int]
            user.ShowWindow(hwnd, 9)  # SW_RESTORE
            user.SetForegroundWindow.argtypes = [w.HWND]
            user.SetForegroundWindow(hwnd)
    return bool(found)
