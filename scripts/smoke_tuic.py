#!/usr/bin/env python3
"""Real loopback-only TUIC TCP/UDP isolation smoke test; does NOT validate WFP.

Requires sing-box 1.14.4, the compiled orangespace-broker, and openssl.
No public website is contacted. All credentials and certificates are ephemeral.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import json
from pathlib import Path
import secrets
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
import uuid

from node_config import node_config


DESTINATION = socket.inet_aton("198.18.0.1") + struct.pack("!H", 18080)


def exact(sock, size):
    result = b""
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        result += chunk
    return result


def socks_connect(port, username, password, command=1):
    sock = socket.create_connection(("127.0.0.1", port), timeout=4)
    try:
        sock.settimeout(4)
        sock.sendall(b"\x05\x01\x02")
        if exact(sock, 2) != b"\x05\x02":
            raise ConnectionError("SOCKS authentication method rejected")
        user, secret = username.encode(), password.encode()
        sock.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(secret)]) + secret)
        if exact(sock, 2) != b"\x01\x00":
            raise ConnectionError("SOCKS credentials rejected")
        address = DESTINATION if command == 1 else b"\x00" * 6
        sock.sendall(b"\x05" + bytes([command]) + b"\x00\x01" + address)
        header = exact(sock, 4)
        if header[:3] != b"\x05\x00\x00":
            raise ConnectionError("SOCKS destination rejected")
        if header[3] == 1:
            host = socket.inet_ntoa(exact(sock, 4))
        elif header[3] == 4:
            host = socket.inet_ntop(socket.AF_INET6, exact(sock, 16))
        else:
            raise ConnectionError("unexpected SOCKS response address")
        bound_port = struct.unpack("!H", exact(sock, 2))[0]
        return sock, (host, bound_port)
    except BaseException:
        sock.close()
        raise


def tcp_roundtrip(settings, label, index):
    payload = f"{label}:tcp:{index}:{secrets.token_hex(16)}\n".encode()
    sock, _ = socks_connect(settings["socks_port"], settings["socks_username"], settings["socks_password"])
    with sock:
        sock.sendall(payload)
        response = exact(sock, len(label.encode()) + 1 + len(payload))
    if response != label.encode() + b":" + payload:
        raise AssertionError("TCP response crossed a node or stream")


def udp_roundtrip(settings, label, index):
    payload = f"{label}:udp:{index}:{secrets.token_hex(16)}".encode()
    control, relay = socks_connect(settings["socks_port"], settings["socks_username"], settings["socks_password"], 3)
    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(4)
        udp.sendto(b"\x00\x00\x00\x01" + DESTINATION + payload, relay)
        response, _ = udp.recvfrom(65535)
    if response[:4] != b"\x00\x00\x00\x01" or response[10:] != label.encode() + b":" + payload:
        raise AssertionError("UDP response crossed a node or association")


class TcpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(4)
        data = bytearray()
        while len(data) < 4096:
            chunk = self.request.recv(4096 - len(data))
            if not chunk:
                return
            data.extend(chunk)
            if data.endswith(b"\n"):
                self.request.sendall(self.server.label + b":" + data)
                return


class UdpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(self.server.label + b":" + data, self.client_address)


class TcpServer(socketserver.ThreadingTCPServer):
    daemon_threads = True


def free_port(kind):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def write_private(path, value):
    with path.open("x") as stream:
        path.chmod(0o600)
        json.dump(value, stream)


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sing-box", type=Path, required=True)
    parser.add_argument("--broker", type=Path, default=Path("target/debug/orangespace-broker"))
    args = parser.parse_args()
    binary, broker = args.sing_box.resolve(), args.broker.resolve()
    version = subprocess.check_output([str(binary), "version"], text=True).splitlines()[0]
    if version != "sing-box version 1.14.4":
        raise RuntimeError("this smoke test is pinned to sing-box 1.14.4")
    with tempfile.TemporaryDirectory(prefix="orangespace-tuic-") as directory, ExitStack() as stack:
        root = Path(directory)
        cert, key = root / "cert.pem", root / "key.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=orangespace.test", "-addext", "subjectAltName=DNS:orangespace.test",
            "-keyout", str(key), "-out", str(cert),
        ], check=True, capture_output=True)
        user = str(uuid.uuid4())

        def cli(*arguments, success=True):
            result = subprocess.run([str(broker), "--data-dir", str(root / "state"), *arguments], capture_output=True, text=True, timeout=15)
            if success and result.returncode:
                raise RuntimeError("broker command failed: " + result.stdout + result.stderr)
            return result

        def launch(config, name):
            path = root / (name + ".json")
            write_private(path, config)
            subprocess.run([str(binary), "check", "-c", str(path)], check=True, capture_output=True)
            log = stack.enter_context((root / (name + ".log")).open("w+"))
            process = subprocess.Popen([str(binary), "run", "-c", str(path)], stdout=log, stderr=log)
            stack.callback(stop, process)
            return process

        nodes, clients, settings_list, sandbox_ids = [], [], [], []
        for label in ("shenzhen", "guangzhou"):
            tcp = stack.enter_context(TcpServer(("127.0.0.1", 0), TcpEcho))
            echo_port = tcp.server_address[1]
            udp = stack.enter_context(socketserver.ThreadingUDPServer(("127.0.0.1", echo_port), UdpEcho))
            tcp.label = udp.label = label.encode()
            for service in (tcp, udp):
                threading.Thread(target=service.serve_forever, daemon=True).start()
                stack.callback(service.shutdown)
            tunnel_port = free_port(socket.SOCK_DGRAM)
            tuic_uuid, tuic_password = str(uuid.uuid4()), secrets.token_urlsafe(32)
            production_config = root / (label + "-production-check.json")
            write_private(production_config, node_config(
                [{"uuid": tuic_uuid, "password": tuic_password}], str(cert), str(key), tunnel_port))
            subprocess.run([str(binary), "check", "-c", str(production_config)], check=True, capture_output=True)
            # Each simulated node routes the SAME destination to a different labeled echo.
            # This test-only override is not used in the production node configuration.
            server_config = {
                "log": {"level": "warn"},
                "inbounds": [{"type": "tuic", "listen": "127.0.0.1", "listen_port": tunnel_port,
                    "users": [{"uuid": tuic_uuid, "password": tuic_password}],
                    "zero_rtt_handshake": False,
                    "tls": {"enabled": True, "certificate_path": str(cert), "key_path": str(key)}}],
                "outbounds": [{"type": "direct", "tag": "echo-only"}],
                "route": {"rules": [{"ip_cidr": ["198.18.0.1/32"], "port": 18080, "action": "route",
                    "outbound": "echo-only", "override_address": "127.0.0.1", "override_port": echo_port},
                    {"action": "reject"}]},
            }
            nodes.append(launch(server_config, label + "-node"))
            sandbox = json.loads(cli("create", "--user", user, "--name", label).stdout)["sandbox"]["id"]
            sandbox_ids.append(sandbox)
            node_id = str(uuid.uuid4())
            cli("bind", "--user", user, "--sandbox", sandbox, "--node", node_id)
            settings = {
                "node_id": node_id,
                "endpoint_ip": "127.0.0.1", "endpoint_port": tunnel_port, "tls_server_name": "orangespace.test",
                "certificate_path": str(cert), "tuic_uuid": tuic_uuid, "tuic_password": tuic_password,
                "socks_port": free_port(socket.SOCK_STREAM), "socks_username": label,
                "socks_password": secrets.token_urlsafe(32),
            }
            settings_list.append(settings)
            settings_path, config_path = root / (label + "-settings.json"), root / (label + "-generated.json")
            write_private(settings_path, settings)
            cli("tunnel-config", "--user", user, "--sandbox", sandbox, "--settings-file", str(settings_path), "--output", str(config_path))
            clients.append(launch(json.loads(config_path.read_text()), label + "-client"))

        for process, settings in zip(clients, settings_list):
            deadline = time.monotonic() + 10
            while True:
                if process.poll() is not None:
                    raise RuntimeError("sing-box client exited during startup")
                try:
                    with socket.create_connection(("127.0.0.1", settings["socks_port"]), timeout=0.2):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("SOCKS listener did not start")
                    time.sleep(0.05)
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(operation, settings, label, index)
                       for settings, label in zip(settings_list, ("shenzhen", "guangzhou"))
                       for index in range(16) for operation in (tcp_roundtrip, udp_roundtrip)]
            for future in futures:
                future.result()

        stop(nodes[0])
        for operation in (tcp_roundtrip, udp_roundtrip):
            try:
                operation(settings_list[0], "shenzhen", 99)
            except (OSError, ConnectionError):
                pass
            else:
                raise AssertionError("stopped node unexpectedly returned traffic")
            operation(settings_list[1], "guangzhou", 99)
        blocked = cli("open", "--user", user, "--sandbox", sandbox_ids[1], success=False)
        if blocked.returncode == 0:
            raise AssertionError("broker allowed a browser without WFP protection")
        print(json.dumps({"ok": True, "sing_box": "1.14.4", "nodes": 2, "parallel_roundtrips": 64,
                          "tcp": True, "udp_native": True, "node_failure_isolated": True,
                          "unprotected_browser_blocked": True, "windows_wfp_validated": False}, indent=2))


if __name__ == "__main__":
    main()
