#!/usr/bin/env python3
"""Run as root in a disposable systemd Linux guest with IPv4 forwarding enabled."""
import contextlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import selectors
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid

import gateway

TARGET = "198.51.100.77"
TCP = 18089
UDP = 18090
DNS = 53
HTTPS = 18443
HTTP = 18091
HERE = Path(__file__).resolve().parent
PAYLOAD = bytes(range(256)) * 32
CHUNKS = 64


def run(*args, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, timeout=30, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{Path(args[0]).name} {' '.join(args[1:2])} exited {result.returncode}: "
                           f"{result.stderr.strip()[-300:]}")
    return result


def finish(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def spawn(stack, *args):
    proc = subprocess.Popen(args, stdout=subprocess.DEVNULL)
    stack.callback(finish, proc)
    return proc


def serve(marker, log, cert, key):
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    def health(conn):
        with conn, tls.wrap_socket(conn, server_side=True) as stream:
            if stream.recv(2048).startswith(b"GET /ready HTTP/1.0\r\n"):
                stream.sendall(b"HTTP/1.0 204 No Content\r\n\r\n")
    def page(conn):
        with conn:
            request = conn.recv(4096)
            if request.startswith(b"GET "):
                title = "OrangeSpace node " + marker
                body = f"<!doctype html><title>{title}</title><h1>{title}</h1>".encode()
                conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n"
                             b"Cache-Control: no-store\r\n\r\n" + body)
    def tcp_reply(conn):
        with conn:
            mode = conn.recv(8)
            conn.sendall(marker.encode())
            if mode == b"stream":
                for _ in range(CHUNKS):
                    time.sleep(0.05)
                    conn.sendall(PAYLOAD)
    selector = selectors.DefaultSelector()
    tcp_handlers = {TCP: tcp_reply, HTTPS: health, HTTP: page}
    for port in (*tcp_handlers, UDP, DNS):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if port in tcp_handlers else socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((TARGET, port))
        if port in tcp_handlers:
            sock.listen()
        selector.register(sock, selectors.EVENT_READ, port)
    Path(log + ".ready").touch()
    while True:
        for event, _ in selector.select():
            sock = event.fileobj
            with open(log, "ab") as seen:
                seen.write(b"1")
            if event.data in tcp_handlers:
                conn, _ = sock.accept()
                threading.Thread(target=tcp_handlers[event.data], args=(conn,), daemon=True).start()
            else:
                message, addr = sock.recvfrom(2048)
                if event.data == DNS:
                    ip = {"A": "192.0.2.11", "B": "192.0.2.12", "HOST": "192.0.2.13"}[marker]
                    message = (message[:2] + bytes.fromhex("81800001000100000000") + message[12:] +
                               bytes.fromhex("c00c00010001000000000004") + socket.inet_aton(ip))
                else:
                    message = marker.encode() + message
                sock.sendto(message, addr)


def probe(kind, expected):
    if kind in ("tcp", "stream"):
        with socket.create_connection((TARGET, TCP), timeout=2) as conn:
            conn.sendall(kind.encode())
            if kind == "stream":
                data = conn.makefile("rb")
                assert data.read(len(expected)) == expected.encode()
                assert hashlib.sha256(data.read()).digest() == hashlib.sha256(PAYLOAD * CHUNKS).digest()
            else:
                reply = conn.makefile("rb").read()
                if not reply:
                    raise ConnectionResetError("no application data")
                assert reply == expected.encode()
        return
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        if kind == "udp":
            query = os.urandom(12)
            sock.sendto(query, (TARGET, UDP))
            assert sock.recv(256) == expected.encode() + query
        else:
            query = (os.urandom(2) + bytes.fromhex("01000001000000000000") +
                     b"\x06orange\x04test\x00" + bytes.fromhex("00010001"))
            sock.sendto(query, (TARGET, DNS))
            answer = sock.recv(512)
            assert answer[:2] == query[:2] and answer[2:12] == bytes.fromhex("81800001000100000000")
            expected_ip = {"A": "192.0.2.11", "B": "192.0.2.12", "HOST": "192.0.2.13"}[expected]
            assert socket.inet_ntoa(answer[-4:]) == expected_ip


@dataclass
class TestNode:
    id: str
    sandbox: str
    process: subprocess.Popen
    lease: dict
    tunnel: str = ""

    def stop(self):
        finish(self.process)

    def grant(self, remaining_ms=30000):
        """Hand the sandbox a fresh node lease (what the client does), new tunnel id."""
        self.tunnel = str(uuid.uuid4())
        run(str(HERE / "lease"), self.sandbox, self.id,
            input=json.dumps({**self.lease, "tunnel_id": self.tunnel, "remaining_ms": remaining_ms}))

    def renew(self, remaining_ms=30000):
        run(str(HERE / "renew"), self.sandbox, self.tunnel, str(remaining_ms))


@dataclass
class NodeLab:
    nodes: list
    canary: Path
    baseline: int
    url = f"http://{TARGET}:{HTTP}/"

    def assert_no_direct(self):
        assert self.canary.stat().st_size == self.baseline


def check(prefix, expected, kinds=("tcp", "udp", "dns"), blocked=False):
    for kind in kinds:
        outcome = subprocess.run([*prefix, sys.executable, __file__, "probe", kind, expected],
                                 capture_output=True, text=True, timeout=8)
        if blocked:
            # Wrong answers (including a direct reply) fail separately from a transport failure.
            assert outcome.returncode == 2, (expected, kind, outcome.returncode, outcome.stderr)
        else:
            assert outcome.returncode == 0, (expected, kind, outcome.stderr)


@contextlib.contextmanager
def paired_nodes(sandbox_ids):
    if len(sandbox_ids) != 2 or len(set(sandbox_ids)) != 2:
        raise ValueError("provide two distinct sandbox IDs")
    sandbox_ids = [gateway.uuid_text(s) for s in sandbox_ids]
    tag = secrets.token_hex(3)
    this = str(Path(__file__).resolve())

    def ip(*args):
        return run("ip", *args)

    with contextlib.ExitStack() as stack:
        stack.callback(os.umask, os.umask(0o077))
        fixture_lock = stack.enter_context(open("/run/orangespace-network-smoke.lock", "a"))
        fcntl.flock(fixture_lock, fcntl.LOCK_EX)
        tmp = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="os-gateway-qa-")))
        dummy = "ost" + tag
        ip("link", "add", dummy, "type", "dummy")
        stack.callback(ip, "link", "del", dummy)
        ip("addr", "add", TARGET + "/32", "dev", dummy)
        ip("link", "set", dummy, "up")
        cert, key = tmp / "node.crt", tmp / "node.key"
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=node.test", "-addext", "subjectAltName=DNS:node.test",
            "-keyout", str(key), "-out", str(cert))

        def start_target(prefix, label):
            log = str(tmp / label)
            p = spawn(stack, *prefix, sys.executable, this, "serve", label, log, str(cert), str(key))
            for _ in range(100):
                if Path(log + ".ready").exists():
                    return
                if p.poll() is not None:
                    raise RuntimeError("test responder exited")
                time.sleep(.02)
            raise RuntimeError("test responder did not start")

        start_target([], "HOST")
        check([], "HOST")
        direct_baseline = (tmp / "HOST").stat().st_size
        cases = []
        for index, label in enumerate(("A", "B")):
            ns = "osqan" + tag + label
            ip("netns", "add", ns)
            stack.callback(ip, "netns", "delete", ns)
            ip("-n", ns, "link", "set", "lo", "up")
            wan = "oq" + tag + label
            ip("link", "add", wan, "type", "veth", "peer", "name", "eth0", "netns", ns)
            root_ip = "198.18.250." + str(index * 4 + 1)
            endpoint = "198.18.250." + str(index * 4 + 2)
            ip("addr", "add", root_ip + "/30", "dev", wan)
            ip("link", "set", wan, "up")
            ip("-n", ns, "addr", "add", endpoint + "/30", "dev", "eth0")
            ip("-n", ns, "link", "set", "eth0", "up")
            ip("-n", ns, "addr", "add", TARGET + "/32", "dev", "lo")
            node_prefix = ["ip", "netns", "exec", ns]
            start_target(node_prefix, label)
            node_id, auth = (str(uuid.uuid4()) for _ in range(2))
            sandbox_id = sandbox_ids[index]
            password = secrets.token_urlsafe(24)
            cfg = {"log": {"disabled": True}, "inbounds": [{"type": "tuic", "listen": endpoint, "listen_port": 10443,
                                 "users": [{"uuid": auth, "password": password}],
                                 "tls": {"enabled": True, "certificate_path": str(cert),
                                         "key_path": str(key)}}], "outbounds": [{"type": "direct"}]}
            server = tmp / (label + ".conf")
            server.write_text(json.dumps(cfg))
            node = spawn(stack, *node_prefix, "sing-box", "run", "-c", str(server))
            lease = {"node_id": node_id, "endpoint_ip": endpoint, "endpoint_port": 10443,
                     "tls_server_name": "node.test", "certificate_pem": cert.read_text(),
                     "uuid": auth, "password": password,
                     "probe": {"ipv4": TARGET, "port": HTTPS, "tls_name": "node.test",
                               "path": "/ready", "certificate_pem": cert.read_text()}}
            stack.callback(lambda s=sandbox_id: gateway.lease_path(s).unlink(missing_ok=True))
            cases.append(TestNode(node_id, sandbox_id, node, lease))
        yield NodeLab(cases, tmp / "HOST", direct_baseline)


def fixture():
    with contextlib.ExitStack() as stack:
        ids = [str(uuid.uuid4()) for _ in range(2)]
        lab = stack.enter_context(paired_nodes(ids))
        a, b = lab.nodes
        cases = []
        for node in lab.nodes:
            desk = "osqad" + secrets.token_hex(3)
            run("ip", "netns", "add", desk)
            stack.callback(run, "ip", "netns", "delete", desk)
            run("ip", "-n", desk, "link", "set", "lo", "up")
            desktop = ["ip", "netns", "exec", desk]
            sleeper = spawn(stack, *desktop, "sleep", "600")
            stack.callback(run, str(HERE / "down"), node.sandbox)
            cases.append((sleeper, desktop))
        (sleeper_a, desktop_a), (sleeper_b, desktop_b) = cases
        # Without a lease there is no way out at all.
        assert subprocess.run([str(HERE / "up"), a.sandbox, str(sleeper_a.pid), a.id]).returncode == 1
        # A lease names its node: it cannot start the gateway toward another one.
        a.grant()
        assert subprocess.run([str(HERE / "up"), a.sandbox, str(sleeper_a.pid), b.id]).returncode == 1
        b.grant()
        with ThreadPoolExecutor(max_workers=2) as pool:
            starts = [pool.submit(run, str(HERE / "up"), node.sandbox, str(sleeper.pid), node.id)
                      for node, (sleeper, _) in zip(lab.nodes, cases)]
            for future in starts:
                future.result()
        for label, node, desktop in (("A", a, desktop_a), ("B", b, desktop_b)):
            check(desktop, label)
            run(str(HERE / "status"), node.sandbox)
            run(str(HERE / "probe"), node.sandbox)
        # Losing node A cuts A only; B's long stream keeps its integrity.
        a.renew()
        b.renew()
        stream = spawn(stack, *desktop_b, sys.executable, __file__, "probe", "stream", "B")
        time.sleep(.25)
        a.stop()
        check(desktop_a, "A", blocked=True)
        assert subprocess.run([str(HERE / "probe"), a.sandbox]).returncode == 1
        assert stream.wait(8) == 0
        check(desktop_b, "B")
        run(str(HERE / "down"), a.sandbox)
        assert subprocess.run([str(HERE / "probe"), a.sandbox]).returncode == 2
        check(desktop_a, "A", blocked=True)
        check(desktop_b, "B")
        # Killing B's tunnel helper cuts B; a new lease brings it back.
        b.renew()
        run("systemctl", "stop", gateway.Gateway(b.sandbox).unit)
        check(desktop_b, "B", blocked=True)
        run(str(HERE / "down"), b.sandbox)
        b.grant()
        run(str(HERE / "up"), b.sandbox, str(sleeper_b.pid), b.id)
        run(str(HERE / "probe"), b.sandbox)
        check(desktop_b, "B")
        # Each renewal extends the kernel permit; only the current tunnel may renew.
        down_old = b.tunnel
        run(str(HERE / "down"), b.sandbox)
        b.grant(6000)
        run(str(HERE / "up"), b.sandbox, str(sleeper_b.pid), b.id)
        started = time.monotonic()
        while time.monotonic() - started < 8:
            check(desktop_b, "B")
            b.renew(6000)
            time.sleep(2)
        check(desktop_b, "B")
        for stale in (str(uuid.uuid4()), down_old):
            assert subprocess.run([str(HERE / "renew"), b.sandbox, stale, "6000"]).returncode == 1
        # When renewals stop, the kernel withdraws the permit on its own.
        time.sleep(5.6)
        check(desktop_b, "B", blocked=True)
        assert subprocess.run([str(HERE / "status"), b.sandbox]).returncode == 1
        run(str(HERE / "down"), b.sandbox)
        # An expired lease cannot start a gateway.
        b.grant(600)
        time.sleep(0.3)
        assert subprocess.run([str(HERE / "up"), b.sandbox, str(sleeper_b.pid), b.id]).returncode == 1
        check(desktop_b, "B", blocked=True)
        lab.assert_no_direct()
        print("PASS no lease no egress, lease bound to its node, concurrent TCP/UDP/DNS egress, remote loss, "
              "local helper loss, explicit stop, lease renewal and lapse, stale tunnel refused, expired lease refused, "
              "sandbox HTTPS health, sibling stream SHA-256, zero direct-canary requests")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        fixture()
    elif sys.argv[1] == "serve":
        serve(*sys.argv[2:])
    elif sys.argv[1] == "probe":
        try:
            probe(sys.argv[2], sys.argv[3])
        except OSError:
            sys.exit(2)
