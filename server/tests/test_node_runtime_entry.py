"""Protected-profile entry point tests; real HTTP uses an owned MySQL schema."""
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from uuid import UUID

import pytest


@pytest.mark.parametrize("fault", ["public", "symlink", "hardlink", "directory", "oversized", "duplicate", "unknown", "relative", "bad-schema", "boolean-port", "public-host", "bad-uuid", "embedded-secret"])
def test_profile_fails_closed_without_echoing_input(tmp_path, fault):
    from orangespace_node.runtime import load_profile

    path = write_profile(tmp_path)
    if fault == "public":
        path.chmod(0o644)
    elif fault == "symlink":
        link = tmp_path / "link.json"
        link.symlink_to(path)
        path = link
    elif fault == "hardlink":
        (tmp_path / "other.json").hardlink_to(path)
    elif fault == "directory":
        path = tmp_path
    elif fault == "oversized":
        path.write_text(" " * 65537)
    elif fault == "duplicate":
        path.write_text('{"schema":1,"schema":1,"secret":"should-not-appear"}')
    else:
        changes = {
            "unknown": {"unexpected": "should-not-appear"},
            "relative": {"dbConfig": "should-not-appear"},
            "bad-schema": {"schema": 2},
            "boolean-port": {"listenPort": True},
            "public-host": {"listenHost": "0.0.0.0"},
            "bad-uuid": {"nodeUUID": "should-not-appear"},
            "embedded-secret": {"database_url": "should-not-appear"},
        }
        path = write_profile(tmp_path, **changes[fault])
    with pytest.raises(ValueError, match="^invalid protected node runtime profile$") as caught:
        load_profile(path)
    assert "should-not-appear" not in str(caught.value)


def write_profile(tmp_path, **changes):
    value = {
        "schema": 1,
        "nodeUUID": "4eef0765-2443-4879-badb-02967baac185",
        "dataRoot": str(tmp_path / "files"),
        "dbConfig": str(tmp_path / "database.json"),
        "tunnelConfig": None,
        "federationConfig": None,
    }
    value.update(changes)
    path = tmp_path / "runtime.json"
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    return path


def test_profile_selects_explicit_identity_and_private_db_path(tmp_path):
    from orangespace_node.runtime import load_profile

    profile = load_profile(write_profile(tmp_path))
    assert profile.node_id == UUID("4eef0765-2443-4879-badb-02967baac185")
    assert profile.data_root == tmp_path / "files"
    assert profile.database_config == tmp_path / "database.json"
    assert profile.host == "127.0.0.1"
    assert profile.port == 19091
    assert profile.tunnel_config is None
    assert profile.federation_config is None

def test_runtime_startup_errors_do_not_disclose_database_input(tmp_path):
    database = tmp_path / "database.json"
    sentinel = "synthetic-runtime-password-do-not-disclose"
    dsn = f"mysql+pymysql://user:{sentinel}@localhost/db?unix_socket=/nonexistent-orangespace-runtime-test.sock"
    database.write_text(json.dumps({"database_url": dsn}))
    database.chmod(0o600)
    profile = write_profile(tmp_path)
    result = subprocess.run([sys.executable, "-m", "orangespace_node.runtime", "--profile", str(profile), "serve"],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode != 0
    assert sentinel not in result.stdout + result.stderr
    assert dsn not in result.stdout + result.stderr
    assert "node runtime failed" in result.stderr


@pytest.mark.parametrize("node_id", ["4eef0765-2443-4879-badb-02967baac185", "f6224bf7-a363-43fb-8c0b-417794c91b7a"])
def test_foreground_real_http_and_graceful_stop(tmp_path, mysql_config_path, node_id):
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    files = tmp_path / "files"
    files.mkdir(mode=0o700)
    marker = files / "owned-file-preserve-control"
    marker.write_bytes(b"existing-owner-data")
    original_owner = marker.stat().st_uid, marker.stat().st_gid
    profile = write_profile(tmp_path, nodeUUID=node_id, dbConfig=str(mysql_config_path), listenPort=port)
    command = [sys.executable, "-m", "orangespace_node.runtime", "--profile", str(profile)]
    log = tmp_path / "runtime.log"
    with log.open("w+") as stream:
        process = subprocess.Popen(command + ["serve"], stdout=stream, stderr=stream,
                                   env={k: v for k, v in os.environ.items() if not k.startswith("ORANGESPACE_")})
        try:
            url = f"http://127.0.0.1:{port}"
            deadline = time.monotonic() + 30
            while True:
                assert process.poll() is None, "foreground exited before readiness"
                try:
                    with urllib.request.urlopen(url + "/healthz", timeout=1) as response:
                        assert response.status == 200
                        assert response.headers["X-OrangeSpace-Node"] == node_id
                        assert json.load(response)["status"] == "ok"
                    break
                except (OSError, urllib.error.URLError):
                    if time.monotonic() >= deadline:
                        raise AssertionError("readiness deadline exceeded")
                    time.sleep(0.1)
            with pytest.raises(urllib.error.HTTPError) as denied:
                urllib.request.urlopen(url + "/v1/files", timeout=3)
            assert denied.value.code == 401
            admin = subprocess.run(command + ["admin", "list-users"], capture_output=True, timeout=20)
            assert admin.returncode == 0
            process.send_signal(signal.SIGTERM)
            assert process.wait(timeout=20) in (0, -signal.SIGTERM)
            stream.seek(0)
            logs = stream.read()
            assert "Application shutdown complete" in logs
            with socket.socket() as check:
                assert check.connect_ex(("127.0.0.1", port)) != 0
            assert marker.read_bytes() == b"existing-owner-data"
            assert (marker.stat().st_uid, marker.stat().st_gid) == original_owner
            print(f"HTTP receipt node={node_id}: health=200 files_unauth=401 admin=0 shutdown=complete port=closed files_owner=preserved")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
