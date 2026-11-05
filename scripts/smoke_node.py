#!/usr/bin/env python3
"""Exercise the real HTTP File API on loopback using temporary users/storage."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import ProxyHandler, Request, build_opener
from uuid import uuid4

from orangespace_node.auth import create_user
from orangespace_node.database import Database


def main():
    with tempfile.TemporaryDirectory(prefix="orangespace-api-") as directory, ExitStack() as stack:
        root = Path(directory)
        database_url = "sqlite:///" + str(root / "node.sqlite3")
        database = Database(database_url)
        passwords = {name: secrets.token_urlsafe(32) for name in ("alice", "bruce")}
        try:
            database.initialize()
            for name, password in passwords.items():
                create_user(database, name, password)
        finally:
            database.close()
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        node_id = str(uuid4())
        environment = os.environ.copy()
        environment.update(ORANGESPACE_NODE_ID=node_id, ORANGESPACE_DATABASE_URL=database_url,
                           ORANGESPACE_DATA_ROOT=str(root / "files"), ORANGESPACE_MAX_UPLOAD_BYTES="2097152")
        log = stack.enter_context((root / "node.log").open("w+"))
        process = subprocess.Popen([sys.executable, "-m", "uvicorn", "orangespace_node.app:create_app", "--factory",
                                    "--host", "127.0.0.1", "--port", str(port), "--no-access-log"],
                                   env=environment, stdout=log, stderr=log)
        try:
            base = f"http://127.0.0.1:{port}"
            opener = build_opener(ProxyHandler({}))

            def request(method, path, data=None, token=None, expected=200, headers=None):
                request_headers = dict(headers or {})
                if token:
                    request_headers["Authorization"] = "Bearer " + token
                if isinstance(data, dict):
                    data = json.dumps(data).encode()
                    request_headers["Content-Type"] = "application/json"
                req = Request(base + path, data=data, method=method, headers=request_headers)
                try:
                    response = opener.open(req, timeout=5)
                except HTTPError as error:
                    response = error
                with response:
                    body = response.read()
                    if response.status != expected:
                        raise AssertionError(f"{method} {path}: expected {expected}, got {response.status}")
                    return body, response.headers

            deadline = time.monotonic() + 10
            while True:
                try:
                    request("GET", "/healthz")
                    break
                except URLError:
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError("file node did not start")
                    time.sleep(0.05)

            def login(name):
                body, _ = request("POST", "/v1/auth/login", {"username": name, "password": passwords[name]})
                return json.loads(body)["access_token"]

            alice, bruce, alice_second_session = login("alice"), login("bruce"), login("alice")
            request("POST", "/v1/directories", {"path": "共享个人区"}, alice, expected=201)
            path = "/v1/files/" + quote("共享个人区/下载.bin", safe="/")
            payload = secrets.token_bytes(1024 * 1024)
            _, headers = request("PUT", path, payload, alice, expected=201)
            if headers["X-OrangeSpace-Node"] != node_id:
                raise AssertionError("wrong node identity")
            if request("GET", path, token=alice_second_session)[0] != payload:
                raise AssertionError("same user's sessions do not share personal files")
            if request("GET", path, token=alice, headers={"Range": "bytes=100-199"}, expected=206)[0] != payload[100:200]:
                raise AssertionError("range download mismatch")
            request("GET", path, token=bruce, expected=404)
            request("PUT", path, b"must not replace", alice, expected=409)
            request("POST", "/v1/auth/logout", token=alice, expected=204)
            request("GET", "/v1/me", token=alice, expected=401)
            request("GET", path, token=alice_second_session)
            request("DELETE", path, token=alice_second_session, expected=204)
            print(json.dumps({"ok": True, "real_http": True, "payload_bytes": len(payload),
                              "personal_area_shared_between_sessions": True, "cross_user_access_denied": True,
                              "token_revocation": True, "atomic_conflict": True, "range_download": True}, indent=2))
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


if __name__ == "__main__":
    main()
