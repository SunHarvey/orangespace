#!/usr/bin/env python3
"""Run in a disposable Debian guest as root. Writes two raw X11 desktop PNGs."""
import contextlib
import argparse
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import uuid

DESKTOP = "/opt/orangespace/guest/desktop"


def command(*args, env=None):
    return subprocess.run(args, env=env, capture_output=True, text=True, check=True).stdout.strip()


def request(op, user, sandbox, *args):
    reply = subprocess.run([DESKTOP, op, user, sandbox, *args], capture_output=True, text=True)
    result = json.loads(reply.stdout)
    if reply.returncode:
        raise RuntimeError(result)
    return result


def authority(number, cookie):
    fields = [b"", str(number).encode(), b"MIT-MAGIC-COOKIE-1", cookie]
    return struct.pack("!H", 65535) + b"".join(struct.pack("!H", len(v)) + v for v in fields)


@contextlib.contextmanager
def display(sandbox):
    directory = Path("/run/orangespace/display") / sandbox
    directory.mkdir(mode=0o755, parents=True)
    directory.chmod(0o755)
    auth = directory / "Xauthority"
    cookie = os.urandom(16)
    auth.write_bytes(authority(0, cookie))
    os.chown(auth, 0, 1000)
    auth.chmod(0o440)
    framebuffer = tempfile.TemporaryDirectory(prefix="os-xvfb-frame-")
    proc = subprocess.Popen(["Xvfb", "-displayfd", "1", "-auth", str(auth), "-nolisten", "tcp",
                             "-extension", "MIT-SHM", "-screen", "0", "1280x800x24",
                             "-fbdir", framebuffer.name],
                            stdout=subprocess.PIPE, text=True)
    mounted = False
    try:
        number = int(proc.stdout.readline().strip())
        with auth.open("ab") as f:
            f.write(authority(number, cookie))
        local = directory / "X0"
        local.touch()
        command("mount", "--bind", f"/tmp/.X11-unix/X{number}", str(local))
        mounted = True
        yield {"DISPLAY": f":{number}", "XAUTHORITY": str(auth), "PATH": os.environ["PATH"],
               "QA_FRAMEBUFFER": str(Path(framebuffer.name) / "Xvfb_screen0")}
    finally:
        if mounted:
            command("umount", str(directory / "X0"))
        proc.terminate()
        proc.wait(timeout=6)
        framebuffer.cleanup()
        shutil.rmtree(directory)


def windows(env, pattern):
    found = command("xdotool", "search", "--onlyvisible", "--class", pattern, env=env)
    return found.splitlines()


def navigate(env, browser, address):
    command("xdotool", "windowactivate", "--sync", browser, "key", "ctrl+l", env=env)
    command("xdotool", "type", address, env=env)
    command("xdotool", "key", "Return", env=env)


def await_title(env, browser, expected):
    for _ in range(80):
        if expected in command("xdotool", "getwindowname", browser, env=env):
            return
        time.sleep(0.12)
    raise RuntimeError("browser did not display " + expected)


def layout(env, address):
    browser = windows(env, "^chromium$")[-1]
    # PCManFM owns both the desktop wallpaper and the Home window. Only Home
    # belongs to a normal workspace; moving the wallpaper leaves Files hidden.
    files = next(line.split()[0] for line in command("wmctrl", "-lx", env=env).splitlines()
                 if line.split()[1] != "-1" and line.split()[2] == "pcmanfm-qt.pcmanfm-qt")
    for wid, x, w in ((browser, "8", "750"), (files, "772", "482")):
        command("wmctrl", "-i", "-r", wid, "-b", "remove,maximized_vert,maximized_horz", env=env)
        command("wmctrl", "-i", "-r", wid, "-e", f"0,{x},36,{w},678", env=env)
    navigate(env, browser, address)
    command("xdotool", "windowactivate", "--sync", files, "key", "F5", env=env)
    command("xdotool", "windowactivate", "--sync", browser, env=env)
    return browser


def screenshot(env, path):
    with tempfile.TemporaryDirectory() as tmp:
        frame = Path(tmp) / "desktop.xwd"
        # Copy the actual framebuffer. XGetImage of a 24-bit root window can
        # leave the client area of differently sized visual depths undefined.
        shutil.copyfile(env["QA_FRAMEBUFFER"], frame)
        command("magick", str(frame), str(path))


def check_isolation(sandbox):
    name = "osdesk-" + sandbox
    command("docker", "exec", name, "/bin/sh", "-c",
            'test ! -e /dev/virtio-ports && test ! -e /run/docker.sock && '
            'test ! -r /sys/firmware/qemu_fw_cfg/by_name/opt/orangespace/key/raw && '
            'test "$(id -u)" -eq 1000 && grep -Eq "^NoNewPrivs:[[:space:]]+1$" /proc/self/status && '
            'grep -Eq "^CapEff:[[:space:]]+0+$" /proc/self/status && '
            'grep -q "orangespace-desktop (enforce)" /proc/self/attr/current')
    processes = command("docker", "top", name, "-eo", "pid,args").splitlines()
    renderer = next(line.split(None, 1)[0] for line in processes if "--type=renderer" in line)
    status = Path(f"/proc/{renderer}/status").read_text().splitlines()
    assert len(next(s for s in status if s.startswith("NSpid:")).split()) >= 4
    assert int(next(s for s in status if s.startswith("Seccomp_filters:")).split()[1]) >= 2


def main(out, nodes):
    user, a, b, node_a, node_b = (str(uuid.uuid4()) for _ in range(5))
    out.mkdir(parents=True, exist_ok=True)
    lab_context = contextlib.nullcontext()
    if nodes:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "network"))
        from smoke import paired_nodes
        lab_context = paired_nodes([a, b])
    with lab_context as lab, display(a) as xa, display(b) as xb:
        if lab:
            node_a, node_b = (node.id for node in lab.nodes)
        try:
            for sandbox, node in ((a, node_a), (b, node_b)):
                state = request("start", user, sandbox, node)
                assert state["desktop"] == "running", state
                if not lab:
                    assert state["network"] == "offline", state
                check_isolation(sandbox)
            for sandbox, name in ((a, "sandbox-a.txt"), (b, "sandbox-b.txt")):
                command("docker", "exec", "osdesk-" + sandbox, "touch", "/home/desktop/" + name)
            files_b = command("docker", "exec", "osdesk-" + b, "ls", "/home/desktop")
            assert "sandbox-a.txt" not in files_b and "sandbox-b.txt" in files_b
            url = lab.url if lab else "chrome://settings/appearance"
            browser_a = layout(xa, url)
            browser_b = layout(xb, url)
            if lab:
                await_title(xa, browser_a, "OrangeSpace node A")
                await_title(xb, browser_b, "OrangeSpace node B")
                assert request("status", user, a)["network"] == "online"
                assert request("status", user, b)["network"] == "online"
            command("xdotool", "windowactivate", "--sync", browser_a, "key", "ctrl+d", env=xa)
            time.sleep(0.5)
            command("xdotool", "key", "Return", env=xa)
            time.sleep(2)
            screenshot(xa, out / "sandbox-a.png")
            screenshot(xb, out / "sandbox-b.png")
            usage = {}
            for label, sandbox in (("A", a), ("B", b)):
                usage[label] = int(command("docker", "exec", "osdesk-" + sandbox, "cat",
                                           "/sys/fs/cgroup/memory.current"))
            guest = [l for l in Path("/proc/meminfo").read_text().splitlines()
                     if l.startswith(("MemTotal:", "MemAvailable:"))]
            (out / "resource-sample.json").write_text(json.dumps({
                "architecture": os.uname().machine, "workload": "two live Chromium + PCManFM-Qt views",
                "linux_meminfo": guest, "desktop_cgroup_bytes": usage,
                "desktop_image_bytes": int(command("docker", "image", "inspect", "--format={{.Size}}",
                                                   "orangespace/desktop:dev"))}, indent=2) + "\n")
            if lab:
                lab.nodes[0].stop()
                navigate(xa, browser_a, url + "?after-node-stop-a")
                navigate(xb, browser_b, "about:blank")
                await_title(xb, browser_b, "about:blank")
                navigate(xb, browser_b, url + "?after-node-stop-b")
                await_title(xb, browser_b, "OrangeSpace node B")
                for _ in range(12):
                    if request("status", user, a)["network"] == "offline":
                        break
                    time.sleep(0.6)
                else:
                    raise RuntimeError("offline probe for stopped node A remained healthy")
                lab.assert_no_direct()
            request("stop", user, a)
            assert int(command("xdotool", "getactivewindow", env=xb)) == int(browser_b)
            assert request("status", user, b)["desktop"] == "running"
            request("start", user, a, node_a)
            command("docker", "exec", "osdesk-" + a, "test", "-f", "/home/desktop/sandbox-a.txt")
            bookmarks = command("docker", "exec", "osdesk-" + a, "cat", "/home/desktop/.config/chromium/Default/Bookmarks")
            assert any(item.get("url") == url for root in json.loads(bookmarks)["roots"].values()
                       for item in root.get("children", [])), "Chromium bookmark was not retained"
            print(json.dumps({"display": "Xvfb", "desktops": 2, "two_tuic_nodes": bool(lab), "independent_files": True,
                              "sibling_window_survived": True, "home_preserved": True, "bookmark_preserved": True}))
        finally:
            for sandbox in (a, b):
                request("stop", user, sandbox)
                # Only the unique fixture, after positive confirmation its instance stopped.
                data = Path("/var/lib/orangespace/desktop/instances") / sandbox
                if (data / "owner").is_file() and (data / "owner").read_text().strip() == user:
                    shutil.rmtree(data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--nodes", action="store_true", help="use the isolated paired TUIC node fixture")
    args = parser.parse_args()
    main(args.output.resolve(), args.nodes)
