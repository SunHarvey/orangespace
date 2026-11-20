#!/usr/bin/env python3
"""Exercise both bridge peers, the real Docker CLI and two X servers in one test VM."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import uuid

from guest import Agent, authority
from host import Hub
from wire import Channel, authenticate, background


def main(nodes):
    root = Path("/run/orangespace/display")
    control = "/opt/orangespace/guest/desktop"
    user = str(uuid.uuid4())
    with ExitStack() as clean, tempfile.TemporaryDirectory() as tmp:
        a, b = socket.socketpair()
        clean.callback(a.close)
        clean.callback(b.close)
        hostport = clean.enter_context(a.makefile("rwb", buffering=0))
        guestport = clean.enter_context(b.makefile("rwb", buffering=0))
        key = os.urandom(32)
        def guest():
            try:
                authenticate(guestport, key, host=False)
                Agent(Channel(guestport), root, control).run()
            except (EOFError, OSError):
                pass
        guest_thread = background(guest)
        authenticate(hostport, key, host=True)
        hub = Hub(Channel(hostport))
        host_thread = background(hub.run)
        def disconnect():
            a.shutdown(socket.SHUT_RDWR)
            host_thread.join(5)
            guest_thread.join(30)
        clean.callback(disconnect)
        cases = []
        for name in ("A", "B"):
            cookie = os.urandom(16)
            auth = Path(tmp) / name
            auth.write_bytes(authority(cookie))
            server = subprocess.Popen(["Xvfb", "-displayfd", "1", "-auth", str(auth), "-nolisten",
                                       "tcp", "-extension", "MIT-SHM", "-screen", "0", "1280x800x24"],
                                      stdout=subprocess.PIPE, text=True)
            clean.callback(server.wait, 10)
            clean.callback(server.terminate)
            display = int(server.stdout.readline())
            server.stdout.close()
            sid = str(uuid.uuid4())
            case = dict(user=user, sandbox=sid, node=str(uuid.uuid4()), display=display, op="start",
                        cookie=cookie.hex(), relay=shutil.which("socat"), timeout=150)
            if not case["relay"]:
                raise RuntimeError("install socat")
            def cleanup_case(data=case):
                reply = hub.command(dict(data, op="stop"))
                if reply.get("desktop") != "stopped":
                    raise RuntimeError(reply)
                directory = Path("/var/lib/orangespace/desktop/instances") / data["sandbox"]
                owner = directory / "owner"
                if owner.is_file() and owner.read_text().strip() == user:
                    shutil.rmtree(directory)
            clean.callback(cleanup_case)
            cases.append(case)
        if nodes:
            sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "network"))
            from smoke import paired_nodes
            lab = clean.enter_context(paired_nodes([case["sandbox"] for case in cases]))
            for case, node in zip(cases, lab.nodes):
                case["node"] = node.id
                settings = dict(node.policy)
                credentials = settings.pop("bindings")[case["sandbox"]]
                settings.update(node_id=node.id, **credentials)
                saved = hub.command(dict(case, op="configure", settings=json.dumps(settings)))
                if saved.get("configured") is not True:
                    raise RuntimeError(saved)
                # Only the imported per-sandbox settings can now authorize these desktops.
                node.record.write_text(json.dumps({**node.policy, "bindings": {}}))
        with ThreadPoolExecutor(2) as pool:
            states = list(pool.map(hub.command, cases))
        if any(state.get("desktop") != "running" for state in states):
            raise RuntimeError(states)
        if nodes and any(state["network"] != "online" for state in states):
            raise RuntimeError("imported node did not pass its sandbox TLS probe")
        def check_windows(case):
            cid = "osdesk-" + case["sandbox"]
            result = subprocess.check_output(["docker", "exec", cid, "xprop", "-root", "_NET_CLIENT_LIST"], text=True)
            ids = result.split("#", 1)[1].strip().split(", ")
            names = [subprocess.check_output(["docker", "exec", cid, "xprop", "-id", wid, "WM_CLASS"],
                                             text=True).lower() for wid in ids]
            assert any("chromium" in row for row in names), names
            assert any("pcmanfm-qt" in row for row in names), names
        for case in cases:
            check_windows(case)
        assert hub.command(dict(cases[0], op="stop"))["desktop"] == "stopped"
        check_windows(cases[1])
        if nodes:
            assert hub.command(dict(cases[1], op="status"))["network"] == "online"
            lab.assert_no_direct()
        print("PASS authenticated duplex bridge, two live Chromium/file-manager desktops, B after stopping A")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nodes", action="store_true", help="import two temporary TUIC nodes through the bridge")
    main(parser.parse_args().nodes)
