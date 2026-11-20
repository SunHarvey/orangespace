import json
import os
import queue
import re
import secrets
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from workspaces import canonical, label


def absolute_path(value):
    path = Path(os.path.expandvars(os.fspath(value)))
    if not path.is_absolute():
        raise ValueError(f"请配置绝对路径：{path}")
    return path


def require_file(value):
    path = Path(value)
    if not path.is_absolute() or not path.is_file():
        raise ValueError(f"缺少文件或路径不是绝对路径：{path}")
    return path


@dataclass(frozen=True)
class Config:
    qemu: Path
    xwin: Path
    socat: Path
    cygpath: Path
    image: Path
    data_image: Path
    memory_mib: int
    cpus: int
    nodes: dict

    @classmethod
    def load(cls, path):
        doc = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        nodes = {canonical(k): label(v) for k, v in doc["nodes"].items()}
        ram, cpus = doc.get("memory_mib", 6144), doc.get("cpus", 4)
        if type(ram) is not int or not 3072 <= ram <= 131072:
            raise ValueError("memory_mib 应为 3072–131072 之间的整数")
        if type(cpus) is not int or not 1 <= cpus <= 64 or not nodes:
            raise ValueError("请配置有效的 cpus 和至少一个节点")
        bin_dir = Path(doc["cygwin_bin"])
        return cls(absolute_path(doc["qemu"]), absolute_path(bin_dir / "XWin.exe"),
                   absolute_path(bin_dir / "socat.exe"), absolute_path(bin_dir / "cygpath.exe"),
                   absolute_path(doc["image"]), absolute_path(doc["data_image"]), ram, cpus, nodes)

    def preflight(self):
        # Local registration and inventory must work before the private node image is built.
        for path in (self.qemu, self.xwin, self.socat, self.cygpath, self.image, self.data_image):
            require_file(path)
        if self.image.samefile(self.data_image):
            raise ValueError("系统盘和用户数据盘必须是不同的文件")


def xauthority(cookie, number):
    def field(v):
        return struct.pack("!H", len(v)) + v
    return (b"\xff\xff" + field(b"") + field(str(number).encode("ascii")) +
            field(b"MIT-MAGIC-COOKIE-1") + field(cookie))


def x11_setup(cookie):
    name = b"MIT-MAGIC-COOKIE-1"
    return (struct.pack("<BBHHHHH", ord("l"), 0, 11, 0, len(name), len(cookie), 0) +
            name + bytes(-len(name) % 4) + cookie + bytes(-len(cookie) % 4))


def display_accepts(socat, number, cookie):
    # Read the X11 setup reply via the exact local transport the bridge will use.
    proc = subprocess.Popen([str(socat), "STDIO", f"UNIX-CONNECT:/tmp/.X11-unix/X{number}"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    received = queue.Queue(1)
    def read_status():
        try:
            received.put(proc.stdout.read(1))
        except OSError:
            received.put(b"")
    reader = threading.Thread(target=read_status, daemon=True)
    reader.start()
    try:
        proc.stdin.write(x11_setup(cookie))
        proc.stdin.flush()
        # Keep stdin open until the X server has answered the connection request.
        return received.get(timeout=3)
    except (queue.Empty, BrokenPipeError):
        return b""
    finally:
        stop_process(proc)
        reader.join(timeout=3)
        proc.stdout.close()
        try:
            proc.stdin.close()
        except BrokenPipeError:
            pass


def qemu_args(cfg, pipe, key):
    # QEMU's option lists escape a literal comma by doubling it.
    image = str(cfg.image).replace(",", ",,")
    data_image = str(cfg.data_image).replace(",", ",,")
    key = str(key).replace(",", ",,")
    return [str(cfg.qemu), "-machine", "q35,accel=whpx", "-m", str(cfg.memory_mib),
            "-smp", str(cfg.cpus), "-display", "none", "-monitor", "none", "-serial", "none",
            "-qmp", "stdio", "-drive", f"file={image},format=qcow2,if=virtio",
            "-drive", f"if=none,id=osdata,format=qcow2,file={data_image}",
            "-device", "virtio-blk-pci,drive=osdata,serial=OrangeSpaceData",
            "-netdev", "user,id=wan,ipv6=off", "-device", "virtio-net-pci,netdev=wan",
            "-device", "virtio-serial-pci", "-chardev", f"pipe,id=ctl,path={pipe}",
            "-device", "virtserialport,chardev=ctl,name=org.orangespace.control",
            "-fw_cfg", f"name=opt/orangespace/key,file={key}"]


def remove_stale_sessions(state):
    """Called only under the per-Windows-user manager lock after crash containment."""
    for item in state.iterdir():
        if not re.fullmatch(r"vm-[a-z0-9_]{8}", item.name):
            continue
        info = item.lstat()
        if item.is_dir() and not item.is_symlink() and not (getattr(info, "st_file_attributes", 0) & 0x400):
            if (item / "guest.key").is_file():
                shutil.rmtree(item)


def stop_process(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


class Runtime:
    """The caller serializes operations on each sandbox. Other desktops may start concurrently."""
    def __init__(self, config, state):
        self.cfg = config
        self.state = state
        remove_stale_sessions(state)
        self.bridge = require_file(Path(__file__).resolve().parents[1] / "bridge" / "host.py")
        self.python = Path(sys.executable).with_name("python.exe")
        self.lock = threading.RLock()
        self.vm = self.hub = self.session = None
        self.displays = {}
        self.reserved_numbers = set()
        self.hidden = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    def _bridge_args(self):
        return [str(self.python), str(self.bridge), "--pipe", self.pipe, "--state-dir", str(self.session)]

    def request(self, op, row=None, options=(), timeout=100):
        args = self._bridge_args() + ["--timeout", str(max(1, min(timeout - 8, 180)))]
        if row is not None:
            args += ["--user", row["user_id"], "--sandbox", row["id"], "--node", row["node"]]
        proc = subprocess.run(args + list(options) + [op], capture_output=True, timeout=timeout,
                              creationflags=self.hidden)
        try:
            reply = json.loads(proc.stdout.decode("utf-8"))
        except (ValueError, UnicodeError):
            reply = {}
        if proc.returncode or not isinstance(reply, dict) or not reply or reply.get("error"):
            # Do not copy arbitrary diagnostic output into the UI or a log.
            message = str(reply.get("error", ""))[:240] if isinstance(reply, dict) else ""
            raise RuntimeError(f"通信命令 {op} 失败。{message}")
        if row is not None:
            if reply.get("sandbox_id") != row["id"] or reply.get("user_id") != row["user_id"]:
                raise RuntimeError("客体回复的沙盒或账号身份不匹配")
            if reply.get("desktop") == "running" and reply.get("node_id") != row["node"]:
                raise RuntimeError("运行中的客体节点与本地绑定不匹配")
        return reply

    def _receive_qmp(self, stream, messages):
        try:
            for line in stream:
                obj = json.loads(line)
                if "event" not in obj:
                    messages.put(obj)
        except (ValueError, OSError):
            pass
        finally:
            messages.put(None)

    def _qmp(self, op, timeout=10):
        request_id = secrets.token_hex(5)
        self.vm.stdin.write(json.dumps({"execute": op, "id": request_id}).encode() + b'\n')
        self.vm.stdin.flush()
        until = time.monotonic() + timeout
        while True:
            data = self.qmp_messages.get(timeout=max(0, until - time.monotonic()))
            if data is None:
                raise RuntimeError("QEMU 管理通道已关闭")
            if data.get("id") == request_id:
                if "return" not in data:
                    raise RuntimeError(f"QEMU 拒绝命令 {op}")
                return

    def ensure_vm(self):
        with self.lock:
            if self.vm is not None:
                if self.vm.poll() is None and self.hub is not None and self.hub.poll() is None:
                    return
                raise RuntimeError("虚拟机或本地桥已退出，请通过“退出账号”清理后重新登录")
            self.cfg.preflight()
            self.session = Path(tempfile.mkdtemp(prefix="vm-", dir=self.state))
            self.pipe = "orangespace-" + secrets.token_hex(24)
            key = self.session / "guest.key"
            key.write_bytes(secrets.token_bytes(32))
            try:
                # Keep the diagnostic in the protected account directory for failed boots.
                with (self.state / "qemu.log").open("wb") as log:
                    self.vm = subprocess.Popen(qemu_args(self.cfg, self.pipe, key), stdin=subprocess.PIPE,
                                               stdout=subprocess.PIPE, stderr=log, creationflags=self.hidden)
                self.qmp_messages = queue.Queue()
                threading.Thread(target=self._receive_qmp, args=(self.vm.stdout, self.qmp_messages),
                                 daemon=True).start()
                with (self.state / "bridge.log").open("wb") as log:
                    self.hub = subprocess.Popen(self._bridge_args() + ["--qemu-pid", str(self.vm.pid),
                                                "--key-file", str(key), "serve"], stdout=log, stderr=log,
                                                creationflags=self.hidden)
                greeting = self.qmp_messages.get(timeout=30)
                if not greeting or "QMP" not in greeting:
                    raise RuntimeError("QEMU/WHPX 启动失败，详见 qemu.log")
                self._qmp("qmp_capabilities")
                until = time.monotonic() + 300
                while time.monotonic() < until and self.vm.poll() is None and self.hub.poll() is None:
                    try:
                        if self.request("ping", timeout=3).get("ready") is True:
                            return
                    except (RuntimeError, subprocess.TimeoutExpired):
                        time.sleep(.3)
                raise RuntimeError("Linux 管理代理未就绪，请检查镜像与 bridge.log")
            except BaseException:
                # Startup has not admitted a desktop yet.
                self._power_off(failed_boot=True)
                raise

    def _power_off(self, failed_boot=False):
        """Normal exits wait for guest ACPI shutdown before freeing the disk."""
        if self.vm is not None and self.vm.poll() is None:
            if failed_boot:
                stop_process(self.vm)
            else:
                self._qmp("system_powerdown")
                try:
                    self.vm.wait(timeout=45)
                except subprocess.TimeoutExpired:
                    raise RuntimeError("客体尚未关机，请稍后重试退出；查看客体 ACPI 处理") from None
        stop_process(self.hub)
        if self.vm is not None:
            self.vm.stdin.close()
            self.vm.stdout.close()
        self.hub = self.vm = None
        if self.session is not None:
            shutil.rmtree(self.session)
        self.session = None

    def _reserve_number(self):
        # Each desktop has a 2 GiB guest cgroup. Reserve 1 GiB for the guest and gateways.
        with self.lock:
            capacity = (self.cfg.memory_mib - 1024) // 2048
            if len(self.reserved_numbers) >= capacity:
                raise RuntimeError(f"当前虚拟机的桌面容量为 {capacity} 个，请先停止闲置沙盒")
            for _ in range(512):
                number = 32 + secrets.randbelow(4096)
                if number not in self.reserved_numbers:
                    self.reserved_numbers.add(number)
                    return number
            raise RuntimeError("无法分配显示编号")

    def _new_display(self, row):
        import winapi
        cfg = self.cfg
        number = self._reserve_number()
        work = self.session / row["id"]
        proc = None
        try:
            work.mkdir()
            cookie_file = work / "cookie"
            cookie = secrets.token_bytes(16)
            cookie_file.write_bytes(cookie)
            auth = work / "Xauthority"
            auth.write_bytes(xauthority(cookie, number))
            unix_auth = subprocess.check_output([str(cfg.cygpath), "-u", str(auth)], timeout=5,
                                                creationflags=self.hidden).decode("utf-8").strip()
            proc = subprocess.Popen([str(cfg.xwin), f":{number}", "-screen", "0", "1280x800",
                                     "-noreset", "-noclipboard", "-nolisten", "tcp", "-notrayicon",
                                     "-resize=randr", "-extension", "MIT-SHM", "-auth", unix_auth],
                                    cwd=work, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            until = time.monotonic() + 15
            while time.monotonic() < until:
                if proc.poll() is not None:
                    raise RuntimeError("XWin 启动失败，请检查 Cygwin/X 安装与显示编号")
                if winapi.window(proc.pid, "OrangeSpace · " + row["name"]):
                    # XWin can create the top-level window before accepting connections.
                    if display_accepts(cfg.socat, number, cookie) == b"\x01":
                        if display_accepts(cfg.socat, number, secrets.token_bytes(16)) != b"\x00":
                            raise RuntimeError("显示服务未拒绝错误的 X11 身份")
                        break
                time.sleep(.05)
            else:
                raise RuntimeError("XWin 未显示独立窗口")
            return (number, proc, work, cookie_file)
        except BaseException:
            stop_process(proc)
            shutil.rmtree(work, ignore_errors=True)
            with self.lock:
                self.reserved_numbers.discard(number)
            raise

    def _release_display(self, sid):
        with self.lock:
            current = self.displays.pop(sid, None)
            if current is None:
                return
            number, proc, work, _ = current
            self.reserved_numbers.discard(number)
        stop_process(proc)
        shutil.rmtree(work, ignore_errors=True)

    def start(self, row):
        import winapi
        if row["node"] not in self.cfg.nodes:
            raise ValueError("绑定节点已从配置中移除，请先重新绑定")
        self.ensure_vm()
        sid = row["id"]
        with self.lock:
            current = self.displays.get(sid)
        if current and current[1].poll() is None:
            result = self.status(row)
            if result.get("desktop") == "running":
                winapi.window(current[1].pid, activate=True)
                if result.get("network") == "offline":
                    return self._start_guest(row, current)
                return result
        if current:
            self.stop(row)
        current = self._new_display(row)
        with self.lock:
            self.displays[sid] = current
        try:
            return self._start_guest(row, current)
        except BaseException:
            # An ambiguous timeout may have admitted the desktop. Retain the display on failed stop.
            self.stop(row)
            raise

    def _start_guest(self, row, display):
        number, _, _, cookie = display
        return self.request("start", row, ["--display", str(number), "--cookie-file", str(cookie),
                                          "--x-relay", str(self.cfg.socat)], timeout=168)

    def configure(self, row, path):
        if row["id"] in self.displays:
            raise ValueError("请先停止这个沙盒，再导入节点配置")
        self.ensure_vm()
        return self.request("configure", row, ["--config-file", str(path)])

    def status(self, row):
        if self.vm is None or self.vm.poll() is not None:
            return {"desktop": "stopped", "network": "offline"}
        return self.request("status", row, timeout=25)

    def stop(self, row, timeout=100):
        if self.vm is not None and self.vm.poll() is None:
            result = self.request("stop", row, timeout=timeout)
            if result.get("desktop") != "stopped":
                raise RuntimeError("沙盒尚未停止")
        self._release_display(row["id"])
        return {"desktop": "stopped", "network": "offline"}

    def close(self, rows):
        if self.vm is None:
            return
        if self.vm.poll() is None and self.hub and self.hub.poll() is None:
            # Stop live desktops before retiring their X connections.
            for row in rows:
                if row["id"] in self.displays:
                    try:
                        self.stop(row, timeout=35)
                    except (RuntimeError, OSError, subprocess.TimeoutExpired):
                        # A lost agent must not prevent an authorized guest-wide ACPI shutdown.
                        break
        with self.lock:
            self._power_off()
            for sid in list(self.displays):
                self._release_display(sid)
