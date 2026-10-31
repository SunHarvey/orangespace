"""Real Linux sing-box tests; no stub can satisfy these process checks."""
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time
from dataclasses import replace
from uuid import UUID

import pytest
from fastapi.testclient import TestClient as FastAPITestClient

from orangespace_node.app import create_app
from orangespace_node.auth import create_user, set_tunnel_grant
from test_tunnels import binding
from orangespace_node.tunnels import SecretText


def redact_json(value):
    if isinstance(value, dict):
        return {key: SecretText(item) if key in {"access_token", "tuic_uuid", "tuic_password", "probe_request", "probe_response", "proof"} and isinstance(item, str) else redact_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_json(item) for item in value]
    return value


class TestClient(FastAPITestClient):
    __test__ = False

    def request(self, *args, **kwargs):
        response = super().request(*args, **kwargs)
        original_json = response.json
        response.json = lambda *a, **kw: redact_json(original_json(*a, **kw))
        return response


@pytest.fixture
def runtime_client(config, tmp_path):
    configured = os.environ.get("ORANGESPACE_TEST_SING_BOX")
    if not configured:
        pytest.skip("set ORANGESPACE_TEST_SING_BOX for real node runtime")
    binary = Path(configured)
    if os.geteuid() != 0:
        pytest.skip("protected root-owned fixture needs root; production service remains nonroot")
    assert binary.is_absolute() and binary.is_file()
    import shutil
    trusted_binary = tmp_path / "sing-box"
    shutil.copyfile(binary, trusted_binary)
    trusted_binary.chmod(0o755)
    binary = trusted_binary
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=orangespace.test", "-addext", "subjectAltName=DNS:orangespace.test"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    key.chmod(0o600)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    lock = tmp_path / "runtime.lock"
    lock.touch(mode=0o600)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        probe_port = sock.getsockname()[1]
    settings = dict(executable=str(binary), executable_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(), certificate=str(cert), private_key=str(key), endpoint_ip="127.0.0.1", listen_ip="127.0.0.1", tls_server_name="orangespace.test", port_start=port, port_end=min(port + 8, 65535), max_leases=4, lease_seconds=30, startup_timeout=2, probe_port=probe_port, dns_port=5353, lock_file=str(lock))
    path = tmp_path / "runtime.json"
    path.write_text(json.dumps(settings))
    path.chmod(0o600)
    app = create_app(replace(config, tunnel_config=path))
    with TestClient(app, base_url=f"http://127.0.0.1:{probe_port}", client=("127.0.0.1", 50000)) as client:
        create_user(app.state.database, "alice", "alice-password-for-tests")
        create_user(app.state.database, "bruce", "bruce-password-for-tests")
        set_tunnel_grant(app.state.database, "alice", True)
        auth = {"Authorization": "Bearer " + client.post("/v1/auth/login", json={"username": "alice", "password": "alice-password-for-tests"}).json()["access_token"]}
        yield client, auth, path, cert


def test_real_listener_credentials_and_secret_free_persistence(runtime_client):
    client, auth, path, _cert = runtime_client
    request = binding()
    response = client.post("/v1/tunnels", headers={**auth, "X-OrangeSpace-Lease-Schema": "2"}, json=request)
    assert response.status_code == 200
    value = response.json()
    assert set(value) == {"user_id", "node_id", "sandbox_id", "generation", "tunnel_id", "expires_at", "endpoint_ip", "endpoint_port", "tls_server_name", "tuic_uuid", "tuic_password", "probe_host", "probe_port", "probe_request", "probe_response", "lease_schema", "remaining_ttl_ms"}
    assert all(value[k] == v for k, v in request.items())
    assert UUID(value["tuic_uuid"]).int != 0
    assert value["tuic_uuid"] not in (value["user_id"], value["tunnel_id"])
    secrets = [auth["Authorization"].split()[1], value["tuic_password"], value["probe_request"], value["probe_response"]]
    assert len(set(secrets)) == 4 and all(re.fullmatch(r"[A-Za-z0-9_-]{43}", x) for x in secrets)
    assert time.time() < value["expires_at"] <= int(time.time()) + 30
    assert value["probe_host"] == "127.0.0.1"
    manager = client.app.state.tunnels
    lease = manager.leases[value["tunnel_id"]]
    assert lease.process.poll() is None
    for name in ("cmdline", "environ"):
        contents = Path(f"/proc/{lease.process.pid}/{name}").read_bytes()
        assert all(x.encode() not in contents for x in secrets + [value["tuic_uuid"]])
    for file in path.parent.glob("*.sqlite3*"):
        assert all(x.encode() not in file.read_bytes() for x in secrets + [value["tuic_uuid"]])
    assert client.post(f'/v1/tunnels/{value["tunnel_id"]}/probe', headers={"X-OrangeSpace-Probe": value["probe_request"]}).json() == {"tunnel_id": value["tunnel_id"], "proof": value["probe_response"]}
    assert client.delete(f'/v1/tunnels/{value["tunnel_id"]}', headers=auth).status_code == 204
    assert lease.process.poll() is not None


def new_lease(client, auth, **changes):
    response = client.post("/v1/tunnels", headers={**auth, "X-OrangeSpace-Lease-Schema": "2"}, json=binding(**changes))
    assert response.status_code == 200
    return response.json()


def test_renew_owner_session_logout_independent_listener(runtime_client):
    client, auth, _path, _cert = runtime_client
    a = new_lease(client, auth)
    second = {"Authorization": "Bearer " + client.post("/v1/auth/login", json={"username": "alice", "password": "alice-password-for-tests"}).json()["access_token"]}
    b = new_lease(client, second)
    manager = client.app.state.tunnels
    a_process, b_process = manager.leases[a["tunnel_id"]].process, manager.leases[b["tunnel_id"]].process
    url = f'/v1/tunnels/{a["tunnel_id"]}'
    assert client.post(url + "/renew", headers={**auth, "X-OrangeSpace-Lease-Schema": "2"}).status_code == 200
    reply = client.post(url + "/renew", headers={**auth, "X-OrangeSpace-Lease-Schema": "2"}, json={}).json()
    assert set(reply) == {"tunnel_id", "expires_at", "node_id", "lease_schema", "remaining_ttl_ms"}
    assert reply["tunnel_id"] == a["tunnel_id"] and reply["node_id"] == a["node_id"]
    assert client.post(url + "/renew", headers={**auth, "X-OrangeSpace-Lease-Schema": "2"}, json={"expires_at": 9999999999}).status_code == 422
    assert client.post(url + "/renew", headers={**second, "X-OrangeSpace-Lease-Schema": "2"}).status_code == 404
    assert client.delete(url, headers=second).status_code == 404
    assert client.post("/v1/auth/logout", headers=auth).status_code == 204
    assert a_process.poll() is not None
    assert b_process.poll() is None
    assert client.post(f'/v1/tunnels/{b["tunnel_id"]}/renew', headers={**second, "X-OrangeSpace-Lease-Schema": "2"}).status_code == 200
    assert client.post(url + "/probe", headers={"X-OrangeSpace-Probe": a["probe_request"]}).status_code == 404
    assert client.delete(f'/v1/tunnels/{b["tunnel_id"]}', headers=second).status_code == 204
    assert client.delete(f'/v1/tunnels/{b["tunnel_id"]}', headers=second).status_code == 204


def wait_removed(manager, tunnel_id, process):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        with manager.lock:
            if (tunnel_id not in manager.leases
                    and manager.children.get(process.pid) is not process
                    and process.poll() is not None and process.pidfd is None):
                return
        time.sleep(0.02)
    pytest.fail("listener ownership was not fully released")


@pytest.mark.parametrize("reason", ["lease", "session", "revoked", "user", "grant", "grant-toggle", "child"])
def test_live_reaper_removes_invalid_authorization(runtime_client, reason):
    from orangespace_node.database import AccessSession, User
    from orangespace_node.auth import digest_token
    client, auth, _path, _cert = runtime_client
    value = new_lease(client, auth)
    manager = client.app.state.tunnels
    lease = manager.leases[value["tunnel_id"]]
    if reason == "lease":
        lease.reply["expires_at"] = int(time.time()) - 1
    elif reason in ("session", "revoked", "user"):
        with manager.db.session() as db:
            access = db.get(AccessSession, digest_token(auth["Authorization"].split()[1]))
            if reason == "session":
                access.expires_at = int(time.time()) - 1
            elif reason == "revoked":
                access.revoked_at = int(time.time())
            else:
                db.get(User, access.user_id).enabled = False
    elif reason in ("grant", "grant-toggle"):
        set_tunnel_grant(manager.db, "alice", False)
        if reason == "grant-toggle":
            set_tunnel_grant(manager.db, "alice", True)
    else:
        lease.process.kill()
    wait_removed(manager, value["tunnel_id"], lease.process)
    assert client.post(f'/v1/tunnels/{value["tunnel_id"]}/probe', headers={"X-OrangeSpace-Probe": value["probe_request"]}).status_code == 404


def test_replay_generation_restart_and_probe_separation(runtime_client, config):
    client, auth, path, _cert = runtime_client
    value = new_lease(client, auth)
    url = f'/v1/tunnels/{value["tunnel_id"]}'
    for supplied in ({}, auth, {"X-OrangeSpace-Probe": value["probe_response"]}, {"X-OrangeSpace-Probe": value["tuic_password"]}):
        assert client.post(url + "/probe", headers=supplied).status_code in (400, 404)
    assert client.post("/v1/tunnels", headers={**auth, "X-OrangeSpace-Lease-Schema": "2"}, json=binding(tunnel_id=value["tunnel_id"], generation=2)).status_code == 409
    assert client.post("/v1/tunnels", headers={**auth, "X-OrangeSpace-Lease-Schema": "2"}, json=binding(sandbox_id=value["sandbox_id"])).status_code == 409
    replacement = new_lease(client, auth, sandbox_id=value["sandbox_id"], generation=2)
    assert client.post(url + "/probe", headers={"X-OrangeSpace-Probe": value["probe_request"]}).status_code == 404
    assert replacement["tuic_uuid"] != value["tuic_uuid"]
    manager = client.app.state.tunnels
    process = manager.leases[replacement["tunnel_id"]].process
    manager.close()
    assert process.poll() is not None
    # Existing DB has only tombstones; no active credentials can be restored.
    from orangespace_node.tunnels import TunnelManager
    restarted = TunnelManager(manager.db, replace(config, tunnel_config=path))
    try:
        assert not restarted.leases
        from orangespace_node.auth import authenticate
        current = authenticate(manager.db, auth["Authorization"].split()[1])
        from orangespace_node.tunnels import TunnelBody
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as error:
            restarted.create(current, TunnelBody(**binding(tunnel_id=value["tunnel_id"], generation=3)))
        assert error.value.status_code == 409
    finally:
        restarted.close()


def test_logout_invalidates_create_already_starting(runtime_client, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    import threading
    from orangespace_node.database import AccessSession
    from orangespace_node.auth import digest_token
    client, auth, _path, _cert = runtime_client
    manager = client.app.state.tunnels
    started, release = threading.Event(), threading.Event()
    processes = []
    original = manager._start
    def paused_start(reply):
        process = original(reply)
        processes.append(process)
        started.set()
        assert release.wait(3)
        return process
    monkeypatch.setattr(manager, "_start", paused_start)
    with ThreadPoolExecutor(2) as pool:
        creating = pool.submit(client.post, "/v1/tunnels", headers={**auth, "X-OrangeSpace-Lease-Schema": "2"}, json=binding())
        assert started.wait(3)
        logging_out = pool.submit(client.post, "/v1/auth/logout", headers=auth)
        revoked = False
        try:
            deadline = time.monotonic() + 0.5
            while time.monotonic() < deadline:
                with manager.db.session() as session:
                    revoked = session.get(AccessSession, digest_token(auth["Authorization"].split()[1])).revoked_at is not None
                if revoked:
                    break
                time.sleep(0.01)
        finally:
            release.set()
        assert revoked, "logout must revoke DB authority before waiting for a starting child"
        assert creating.result(timeout=5).status_code == 401
        assert logging_out.result(timeout=5).status_code == 204
    assert processes and all(p.poll() is not None for p in processes)
    assert not manager.leases


def test_child_uses_stable_pidfd_and_cannot_dump_credentials(runtime_client):
    import resource
    client, auth, _path, _cert = runtime_client
    value = new_lease(client, auth)
    process = client.app.state.tunnels.leases[value["tunnel_id"]].process
    assert isinstance(getattr(process, "pidfd", None), int)
    assert resource.prlimit(process.pid, resource.RLIMIT_CORE) == (0, 0)
    assert client.delete(f'/v1/tunnels/{value["tunnel_id"]}', headers=auth).status_code == 204
    assert process.pidfd is None


def test_reaper_retries_failed_reap_without_losing_child(runtime_client, monkeypatch):
    client, auth, _path, _cert = runtime_client
    value = new_lease(client, auth)
    manager = client.app.state.tunnels
    lease = manager.leases[value["tunnel_id"]]
    from concurrent.futures import ThreadPoolExecutor
    import threading
    original = lease.process.wait
    calls = []
    cleanup_entered, release = threading.Event(), threading.Event()
    observing, done = threading.Event(), threading.Event()
    def transient_wait(*args, **kwargs):
        if not calls:
            calls.append(True)
            raise subprocess.TimeoutExpired("trusted runtime", 2)
        result = original(*args, **kwargs)
        # Real child exited, but _stop still owns its exact child and pidfd.
        cleanup_entered.set()
        assert release.wait(5), "owned cleanup barrier was not released"
        return result
    def observe():
        observing.set()
        wait_removed(manager, value["tunnel_id"], lease.process)
        done.set()
    try:
        with ThreadPoolExecutor(1) as pool:
            try:
                with manager.lock:
                    monkeypatch.setattr(lease.process, "wait", transient_wait)
                    lease.reply["expires_at"] = int(time.time()) - 1
                assert cleanup_entered.wait(3)
                observer = pool.submit(observe)
                assert observing.wait(3)
                assert not done.wait(0.2), "observer returned before exact child/pidfd release"
            finally:
                release.set()
            observer.result(timeout=4)
        with manager.lock:
            assert value["tunnel_id"] not in manager.leases
            assert manager.children.get(lease.process.pid) is not lease.process
            assert lease.process.poll() is not None and lease.process.pidfd is None
            assert manager.failed and manager.thread.is_alive()
            assert not manager.children
        assert client.post("/v1/tunnels", headers={**auth, "X-OrangeSpace-Lease-Schema": "2"}, json=binding()).status_code == 503
    finally:
        release.set()
        manager.close()


def receive_exact(sock, length):
    result = b""
    while len(result) < length:
        chunk = sock.recv(length - len(result))
        if not chunk:
            raise OSError("closed tunnel stream")
        result += chunk
    return result


def tunneled_probe(port, username, password, lease):
    with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
        sock.settimeout(2)
        sock.sendall(b"\x05\x01\x02")
        assert receive_exact(sock, 2) == b"\x05\x02"
        sock.sendall(b"\x01" + bytes([len(username)]) + username.encode() + bytes([len(password)]) + password.encode())
        assert receive_exact(sock, 2) == b"\x01\x00"
        sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + lease["probe_port"].to_bytes(2, "big"))
        header = receive_exact(sock, 4)
        if header[:2] != b"\x05\x00":
            raise OSError("tunnel connection refused")
        if header[3] == 1:
            receive_exact(sock, 6)
        elif header[3] == 4:
            receive_exact(sock, 18)
        else:
            receive_exact(sock, receive_exact(sock, 1)[0] + 2)
        request = f'POST /v1/tunnels/{lease["tunnel_id"]}/probe HTTP/1.1\r\nHost: localhost\r\nX-OrangeSpace-Probe: {lease["probe_request"]}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
        sock.sendall(request.encode())
        data = b""
        while len(data) < 16384:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        if b"\r\n\r\n" not in data:
            raise OSError("no HTTP proof received")
        head, body = data.split(b"\r\n\r\n", 1)
        assert head.startswith(b"HTTP/1.1 200 ")
        return json.loads(body)


def test_real_tuic_forwarding_probe_and_independent_revocation(runtime_client):
    import secrets
    import threading
    import uvicorn
    client, auth, path, cert = runtime_client
    a, b = new_lease(client, auth), new_lease(client, auth)
    server = uvicorn.Server(uvicorn.Config(client.app, host="127.0.0.1", port=a["probe_port"], lifespan="off", access_log=False, log_config=None, log_level="critical"))
    worker = threading.Thread(target=server.run, daemon=True)
    worker.start()
    helpers = []
    try:
        deadline = time.monotonic() + 3
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.started
        binary = json.loads(path.read_text())["executable"]
        for lease in (a, b):
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            username, password = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            config = {"log": {"disabled": True}, "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": port, "users": [{"username": username, "password": password}]}], "outbounds": [{"type": "tuic", "tag": "lease", "server": lease["endpoint_ip"], "server_port": lease["endpoint_port"], "uuid": lease["tuic_uuid"], "password": lease["tuic_password"], "zero_rtt_handshake": False, "tls": {"enabled": True, "server_name": lease["tls_server_name"], "certificate_path": str(cert)}}], "route": {"final": "lease"}}
            process = subprocess.Popen([binary, "run", "-c", "stdin"], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={})
            helpers.append((process, port, username, password, lease))
            process.stdin.write(json.dumps(config).encode())
            process.stdin.close()
            deadline = time.monotonic() + 3
            while True:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    assert process.poll() is None and time.monotonic() < deadline
                    time.sleep(0.01)
            assert tunneled_probe(port, username, password, lease) == {"tunnel_id": lease["tunnel_id"], "proof": lease["probe_response"]}
            # Node loopback access is restricted to the exact protected probe port.
            from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
            class PrivateTarget(BaseHTTPRequestHandler):
                protocol_version = "HTTP/1.1"
                def do_POST(self):
                    self.send_response(200)
                    self.send_header("Content-Length", "2")
                    self.end_headers()
                    self.wfile.write(b"{}")
                def log_message(self, *args):
                    pass
            private = ThreadingHTTPServer(("127.0.0.1", 0), PrivateTarget)
            private_thread = threading.Thread(target=private.serve_forever, daemon=True)
            private_thread.start()
            try:
                with pytest.raises(OSError):
                    tunneled_probe(port, username, password, {**lease, "probe_port": private.server_port})
            finally:
                private.shutdown()
                private.server_close()
                private_thread.join(timeout=3)
        assert client.delete(f'/v1/tunnels/{a["tunnel_id"]}', headers=auth).status_code == 204
        with pytest.raises((OSError, ValueError)):
            tunneled_probe(*helpers[0][1:])
        assert tunneled_probe(*helpers[1][1:]) == {"tunnel_id": b["tunnel_id"], "proof": b["probe_response"]}
    finally:
        for process, *_ in helpers:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3)
        server.should_exit = True
        worker.join(timeout=5)
        assert not worker.is_alive()


@pytest.mark.parametrize("header", ["Forwarded", "X-Forwarded-For", "X-Forwarded-Proto", "X-Real-IP"])
def test_probe_cannot_be_called_through_public_proxy(runtime_client, header):
    client, auth, _path, _cert = runtime_client
    lease = new_lease(client, auth)
    response = client.post(f'/v1/tunnels/{lease["tunnel_id"]}/probe', headers={"X-OrangeSpace-Probe": lease["probe_request"], header: "untrusted-proxy-value"})
    assert response.status_code == 404


def test_probe_requires_exact_loopback_listener(runtime_client):
    client, auth, _path, _cert = runtime_client
    lease = new_lease(client, auth)
    url = f'/v1/tunnels/{lease["tunnel_id"]}/probe'
    for base_url, peer in (("http://127.0.0.1:1", "127.0.0.1"), (f'http://127.0.0.1:{lease["probe_port"]}', "198.51.100.1")):
        other = TestClient(client.app, base_url=base_url, client=(peer, 50000))
        try:
            assert other.post(url, headers={"X-OrangeSpace-Probe": lease["probe_request"]}).status_code == 404
        finally:
            other.close()


@pytest.mark.parametrize("problem", ["hash", "writable-config", "symlink", "writable-ancestor", "key-public", "bounds", "unknown", "lock"])
def test_runtime_rejects_unprotected_or_ambiguous_settings(runtime_client, config, problem):
    from orangespace_node.tunnels import TunnelManager
    client, _auth, path, _cert = runtime_client
    manager = client.app.state.tunnels
    settings = json.loads(path.read_text())
    if problem != "lock":
        manager.close()
    changed = path
    original_mode = path.parent.stat().st_mode & 0o777
    if problem == "hash":
        settings["executable_sha256"] = "0" * 64
    elif problem == "writable-config":
        path.chmod(0o666)
    elif problem == "symlink":
        changed = path.parent / "link.json"
        changed.symlink_to(path)
    elif problem == "writable-ancestor":
        path.parent.chmod(0o777)
    elif problem == "key-public":
        Path(settings["private_key"]).chmod(0o644)
    elif problem == "bounds":
        settings["port_start"], settings["port_end"] = 10000, 10500
    elif problem == "unknown":
        settings["command_from_request"] = "not accepted"
    path.write_text(json.dumps(settings))
    try:
        with pytest.raises(ValueError, match="invalid protected tunnel configuration"):
            unexpected = TunnelManager(manager.db, replace(config, tunnel_config=changed))
            unexpected.close()
    finally:
        path.parent.chmod(original_mode)


def test_probe_malformed_non_ascii_secret_is_rejected(runtime_client):
    client, auth, _path, _cert = runtime_client
    value = new_lease(client, auth)
    response = client.post(f'/v1/tunnels/{value["tunnel_id"]}/probe', headers={"X-OrangeSpace-Probe": b"\xe9" * 43})
    assert response.status_code == 404
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as error:
        client.app.state.tunnels.probe(value["tunnel_id"], "\xe9" * 43)
    assert error.value.status_code == 404


def test_runtime_secret_values_have_no_debug_representation(runtime_client):
    client, auth, _path, _cert = runtime_client
    value = new_lease(client, auth)
    lease = client.app.state.tunnels.leases[value["tunnel_id"]]
    for key in ("tuic_uuid", "tuic_password", "probe_request", "probe_response"):
        assert str(lease.reply[key]) not in repr(lease.reply)
        assert str(lease.reply[key]) not in repr(lease)


def test_failed_child_keeps_tombstone_and_cleans_process(runtime_client):
    client, auth, path, cert = runtime_client
    cert.write_text("invalid certificate")
    request = binding()
    response = client.post("/v1/tunnels", headers={**auth, "X-OrangeSpace-Lease-Schema": "2"}, json=request)
    assert response.status_code == 503
    assert response.json() == {"detail": "tunnel runtime failed"}
    assert not client.app.state.tunnels.children
    assert not client.app.state.tunnels.leases
    response = client.post("/v1/tunnels", headers={**auth, "X-OrangeSpace-Lease-Schema": "2"}, json=request)
    assert response.status_code == 409


def test_lease_deadline_does_not_extend_when_wall_clock_moves_back(runtime_client, monkeypatch):
    from types import SimpleNamespace
    import orangespace_node.tunnels as tunnels
    from fastapi import HTTPException
    client, auth, _path, _cert = runtime_client
    value = new_lease(client, auth)
    manager = client.app.state.tunnels
    lease = manager.leases[value["tunnel_id"]]
    shifted = SimpleNamespace(time=lambda: time.time() - 1000, monotonic=lambda: time.monotonic() + 31, sleep=time.sleep)
    from orangespace_node.auth import authenticate
    current = authenticate(manager.db, auth["Authorization"].split()[1])
    with manager.lock:
        monkeypatch.setattr(tunnels, "time", shifted)
        with pytest.raises(HTTPException) as error:
            manager.renew(current, value["tunnel_id"])
        assert error.value.status_code == 410
    assert lease.process.poll() is not None


def test_session_deadline_caps_create_and_renew(runtime_client):
    from orangespace_node.auth import digest_token
    from orangespace_node.database import AccessSession
    client, auth, _path, _cert = runtime_client
    expiry = int(time.time()) + 3
    with client.app.state.database.session() as session:
        session.get(AccessSession, digest_token(auth["Authorization"].split()[1])).expires_at = expiry
    lease = new_lease(client, auth)
    assert lease["expires_at"] == expiry
    response = client.post(f'/v1/tunnels/{lease["tunnel_id"]}/renew', headers={**auth, "X-OrangeSpace-Lease-Schema": "2"}, json={})
    assert response.status_code == 200
    assert response.json()["expires_at"] == expiry
    process = client.app.state.tunnels.leases[lease["tunnel_id"]].process
    wait_removed(client.app.state.tunnels, lease["tunnel_id"], process)


def test_allocation_fails_closed_when_its_reap_detects_uncertain_cleanup(runtime_client, monkeypatch):
    from orangespace_node.auth import authenticate
    from orangespace_node.tunnels import TunnelBody
    from fastapi import HTTPException
    client, auth, _path, _cert = runtime_client
    value = new_lease(client, auth)
    manager = client.app.state.tunnels
    current = authenticate(manager.db, auth["Authorization"].split()[1])
    lease = manager.leases[value["tunnel_id"]]
    original = lease.process.wait
    calls = []
    def transient_wait(*args, **kwargs):
        if not calls:
            calls.append(True)
            raise subprocess.TimeoutExpired("trusted runtime", 2)
        return original(*args, **kwargs)
    with manager.lock:
        monkeypatch.setattr(lease.process, "wait", transient_wait)
        lease.reply["expires_at"] = int(time.time()) - 1
        with pytest.raises(HTTPException) as error:
            manager.create(current, TunnelBody(**binding()))
        assert error.value.status_code == 503
    wait_removed(manager, value["tunnel_id"], lease.process)


def test_capacity_is_bounded_and_failed_allocations_do_not_spawn(runtime_client):
    client, auth, _path, _cert = runtime_client
    leases = [new_lease(client, auth, generation=2**53 - 1) for _ in range(4)]
    from orangespace_node.database import TunnelGeneration, TunnelTombstone
    from sqlalchemy import BigInteger
    assert isinstance(TunnelGeneration.__table__.c.generation.type, BigInteger)
    assert isinstance(TunnelTombstone.__table__.c.generation.type, BigInteger)
    with client.app.state.database.session() as session:
        for value in leases:
            assert session.get(TunnelTombstone, value["tunnel_id"]).generation == 2**53 - 1
    response = client.post("/v1/tunnels", headers={**auth, "X-OrangeSpace-Lease-Schema": "2"}, json=binding())
    assert response.status_code == 429
    assert len(client.app.state.tunnels.children) == 4
    response = client.delete(f'/v1/tunnels/{leases[0]["tunnel_id"]}', headers=auth)
    assert response.status_code == 204
    new_lease(client, auth)
    assert len(client.app.state.tunnels.children) == 4
