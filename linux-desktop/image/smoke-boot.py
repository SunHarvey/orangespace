#!/usr/bin/env python3
"""Boot both clean amd64 disks under QEMU/TCG and authenticate the installed guest service."""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bridge"))
from guest import authority
from host import Hub
from wire import Channel, authenticate, background


def connect(path, proc, deadline):
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"QEMU exited with code {proc.returncode}")
        sock = socket.socket(socket.AF_UNIX)
        try:
            sock.connect(str(path))
        except (FileNotFoundError, ConnectionRefusedError):
            sock.close()
            time.sleep(.1)
            continue
        return sock
    raise TimeoutError("QEMU local socket did not appear")


def qmp(file, name):
    file.write(json.dumps({"execute": name, "id": name}).encode() + b"\n")
    while data := file.readline():
        reply = json.loads(data)
        if reply.get("id") == name:
            if "return" not in reply:
                raise RuntimeError(reply)
            return
    raise EOFError("QMP disconnected")


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


def linux_window(hub, tmp, case):
    relay = shutil.which("socat")
    if not relay:
        raise RuntimeError("--desktop needs socat, Xvfb and xprop")
    with ExitStack() as clean:
        cookie = os.urandom(16)
        auth = tmp / "Xauthority"
        auth.write_bytes(authority(cookie))
        server = subprocess.Popen(["Xvfb", "-displayfd", "1", "-auth", str(auth), "-nolisten", "tcp",
                                   "-extension", "MIT-SHM", "-screen", "0", "1024x768x24"],
                                  stdout=subprocess.PIPE, text=True)
        clean.callback(stop, server)
        number = int(server.stdout.readline())
        server.stdout.close()
        args = {**case, "op": "start", "display": number, "cookie": cookie.hex(), "relay": relay,
                "node": str(uuid.uuid4()), "timeout": 180}
        result = hub.command(args)
        if result.get("desktop") != "running" or result.get("network") != "offline":
            raise RuntimeError(result)
        env = {**os.environ, "DISPLAY": f":{number}", "XAUTHORITY": str(auth)}
        # The wildcard authority used by the guest specifies display zero. xprop
        # on the test host needs the actual local display number.
        fields = (b"", str(number).encode(), b"MIT-MAGIC-COOKIE-1", cookie)
        auth.write_bytes(b"\xff\xff" + b"".join(struct.pack("!H", len(v)) + v for v in fields))
        until = time.monotonic() + 30
        names = []
        while time.monotonic() < until:
            listing = subprocess.check_output(["xprop", "-root", "_NET_CLIENT_LIST"], env=env, text=True)
            ids = listing.partition("#")[2].strip().split(", ")
            names = [subprocess.check_output(["xprop", "-id", wid, "WM_CLASS"], env=env,
                                             text=True).lower() for wid in ids if wid]
            if all(any(key in row for row in names) for key in ("pcmanfm-qt", "chromium")):
                break
            time.sleep(.5)
        else:
            raise RuntimeError(f"expected Chromium and file-manager windows: {names}")
        print("PASS real Chromium and PCManFM-Qt windows through QEMU virtio-serial", flush=True)
        if hub.command({**case, "op":"stop"}).get("desktop") != "stopped":
            raise RuntimeError("desktop did not stop")


def verify(args):
    with tempfile.TemporaryDirectory(dir=args.work_dir, prefix="osvm-") as folder, ExitStack() as clean:
        tmp = Path(folder).resolve()
        if len(os.fsencode(tmp / "serial.sock")) >= 100:
            raise ValueError("choose a shorter work-dir path for Unix sockets")
        for name, base in (("system", args.system), ("data", args.data)):
            subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b",
                            str(base.resolve(strict=True)), str(tmp / (name + ".qcow2"))], check=True)
        key = os.urandom(32)
        (tmp / "key").write_bytes(key)
        log = clean.enter_context((tmp / "qemu.log").open("wb"))
        cmd = ["qemu-system-x86_64", "-machine", "q35,accel=tcg", "-cpu", "max", "-smp", "2", "-m", "2560",
               "-display", "none", "-monitor", "none", "-serial", "file:console.log",
               "-qmp", "unix:qmp.sock,server=on,wait=off", "-boot", "strict=on",
               "-drive", "file=system.qcow2,if=none,id=osroot,format=qcow2",
               "-device", "virtio-blk-pci,drive=osroot,bootindex=1",
               "-drive", "file=data.qcow2,id=osdata,if=none,format=qcow2",
               "-device", "virtio-blk-pci,drive=osdata,serial=OrangeSpaceData",
               "-netdev", "user,id=wan,ipv6=off", "-device", "virtio-net-pci,netdev=wan,romfile=",
               "-device", "virtio-serial-pci", "-chardev", "socket,id=ctl,path=serial.sock,server=on,wait=off",
               "-device", "virtserialport,chardev=ctl,name=org.orangespace.control",
               "-fw_cfg", "name=opt/orangespace/key,file=key"]
        proc = subprocess.Popen(cmd, cwd=tmp, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        clean.callback(stop, proc)
        def diagnostics():
            if sys.exc_info()[0]:
                for path in (tmp / "qemu.log", tmp / "console.log"):
                    if path.exists():
                        print(path.read_bytes()[-5000:].decode(errors="replace"), file=sys.stderr)
        try:
            deadline = time.monotonic() + args.timeout
            monitor = clean.enter_context(connect(tmp / "qmp.sock", proc, deadline))
            monitor.settimeout(20)
            qmpfile = clean.enter_context(monitor.makefile("rwb", 0))
            if "QMP" not in json.loads(qmpfile.readline()):
                raise RuntimeError("missing QMP greeting")
            qmp(qmpfile, "qmp_capabilities")
            chan = clean.enter_context(connect(tmp / "serial.sock", proc, deadline))
            chan.settimeout(max(deadline - time.monotonic(), 1))
            port = clean.enter_context(chan.makefile("rwb", 0))
            authenticate(port, key, host=True)
            chan.settimeout(None)
            hub = Hub(Channel(port))
            background(hub.run)
            case = {"user": str(uuid.uuid4()), "sandbox": str(uuid.uuid4()), "timeout": 90}
            reply = hub.command({**case, "op": "status"})
            if (reply.get("user_id") != case["user"] or reply.get("sandbox_id") != case["sandbox"]
                    or reply.get("desktop") != "stopped" or reply.get("network") != "offline"):
                raise RuntimeError(reply)
            print("PASS amd64 TCG boot, required data mount, Docker image import and authenticated guest", flush=True)
            if args.desktop:
                linux_window(hub, tmp, case)
            qmp(qmpfile, "system_powerdown")
            proc.wait(timeout=150)
            if proc.returncode:
                raise RuntimeError(f"QEMU exited with code {proc.returncode}")
            print("PASS ACPI guest shutdown", flush=True)
        except BaseException:
            diagnostics()
            raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("system", type=Path)
    parser.add_argument("data", type=Path)
    parser.add_argument("--work-dir", type=Path, help="disk-backed directory for disposable overlays")
    parser.add_argument("--desktop", action="store_true", help="verify a full offline desktop on an Xvfb server")
    parser.add_argument("--timeout", type=int, default=600)
    verify(parser.parse_args())
