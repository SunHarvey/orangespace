import hashlib
import os
import time
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor

import anyio
from fastapi.testclient import TestClient
import httpx
import pytest
from sqlalchemy import select, update

from orangespace_node.app import create_app
from orangespace_node.auth import digest_token
from orangespace_node.database import AccessSession, User
from orangespace_node.storage import StorageError, TEMP_PREFIX


def test_authentication_is_required_and_no_open_registration(client):
    assert client.get("/v1/files").status_code == 401
    assert client.put("/v1/files/x", content=b"x").status_code == 401
    assert client.get("/v1/me", headers={"Authorization": "Bearer invalid"}).status_code == 401
    assert client.post("/v1/auth/register", json={"username": "eve", "password": "password"}).status_code == 404


def test_user_files_are_private_but_same_user_sessions_share_area(client, tokens, config):
    alice, bruce = tokens["alice"], tokens["bruce"]
    payload = b"private\x00binary\xffcontents"
    response = client.put("/v1/files/report.bin", headers=alice, content=payload)
    assert response.status_code == 201, response.text
    assert response.json()["sha256"] == hashlib.sha256(payload).hexdigest()
    assert response.json()["size"] == len(payload)
    assert response.json()["node_id"] == str(config.node_id)
    assert client.get("/v1/files/report.bin", headers=alice).content == payload
    assert client.get("/v1/files/report.bin", headers=bruce).status_code == 404
    assert client.delete("/v1/files/report.bin", headers=bruce).status_code == 404
    assert client.get("/v1/files", headers=bruce).json()["entries"] == []
    second = client.post("/v1/auth/login", json={"username": "alice", "password": "alice-password-for-tests"}).json()
    assert client.get("/v1/files/report.bin", headers={"Authorization": "Bearer " + second["access_token"]}).content == payload
    # A client-supplied user_id cannot change the authenticated root.
    alice_id = client.get("/v1/me", headers=alice).json()["user_id"]
    assert client.get(f"/v1/files/report.bin?user_id={alice_id}", headers=bruce).status_code == 404
    assert client.put("/v1/files/report.bin", headers=bruce, content=b"bruce's own file").status_code == 201
    assert client.get("/v1/files/report.bin", headers=alice).content == payload
    assert client.get("/v1/files/report.bin", headers=bruce).content == b"bruce's own file"


def test_directories_listing_unicode_download_and_delete(client, tokens):
    auth = tokens["alice"]
    assert client.post("/v1/directories", headers=auth, json={"path": "资料"}).status_code == 201
    assert client.put("/v1/files/资料/报告.txt", headers=auth, content="你好".encode()).status_code == 201
    entries = client.get("/v1/files?path=资料", headers=auth).json()["entries"]
    assert [(entry["name"], entry["kind"]) for entry in entries] == [("报告.txt", "file")]
    download = client.get("/v1/files/资料/报告.txt", headers=auth)
    assert download.content == "你好".encode()
    assert download.headers["cache-control"] == "no-store"
    assert download.headers["content-type"] == "application/octet-stream"
    assert "filename*=UTF-8''" in download.headers["content-disposition"]
    assert client.delete("/v1/files/资料", headers=auth).status_code == 409
    assert client.delete("/v1/files/资料/报告.txt", headers=auth).status_code == 204
    assert client.delete("/v1/files/资料", headers=auth).status_code == 204
    assert client.get("/v1/files", headers=auth).json()["entries"] == []


@pytest.mark.parametrize("bad", ["../bruce/secret", "/etc/passwd", "a/../b", "a//b", "a/./b", "a\\b", "\x00", "a\n", TEMP_PREFIX + "hidden", "x" * 256])
def test_unsafe_paths_rejected(client, tokens, bad):
    response = client.post("/v1/directories", headers=tokens["alice"], json={"path": bad})
    assert response.status_code == 400


def test_symlinks_and_special_files_never_followed(client, tokens, config, tmp_path):
    auth = tokens["alice"]
    user_id = client.get("/v1/me", headers=auth).json()["user_id"]
    client.get("/v1/files", headers=auth)  # Initialize the personal directory.
    root = config.data_root / user_id
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_bytes(b"must stay private")
    (root / "escape").symlink_to(outside, target_is_directory=True)
    (root / "link").symlink_to(outside / "secret")
    os.mkfifo(root / "pipe", 0o600)
    for path in ("escape/secret", "link", "pipe"):
        assert client.get("/v1/files/" + path, headers=auth).status_code == 400
    assert client.put("/v1/files/escape/new", headers=auth, content=b"x").status_code == 400
    assert client.put("/v1/files/link?overwrite=true", headers=auth, content=b"x").status_code == 409
    assert client.delete("/v1/files/link", headers=auth).status_code == 400
    assert client.get("/v1/files", headers=auth).json()["entries"] == []
    assert (outside / "secret").read_bytes() == b"must stay private"
    assert not (outside / "new").exists()


def test_personal_root_cannot_be_replaced_by_symlink(client, tokens, config, tmp_path):
    auth = tokens["alice"]
    user_id = client.get("/v1/me", headers=auth).json()["user_id"]
    (config.data_root / user_id).symlink_to(tmp_path, target_is_directory=True)
    assert client.get("/v1/files", headers=auth).status_code == 400


def test_file_size_limit_cleans_temp_and_preserves_previous_file(client, tokens, config):
    auth = tokens["alice"]
    assert client.put("/v1/files/keep", headers=auth, content=b"old").status_code == 201
    # No Content-Length forces the streaming limit, not just header validation.
    def body():
        yield b"a" * 32
        yield b"b" * 33
    response = client.put("/v1/files/keep?overwrite=true", headers=auth, content=body())
    assert response.status_code == 413
    assert client.get("/v1/files/keep", headers=auth).content == b"old"
    assert not list(config.data_root.rglob(TEMP_PREFIX + "*"))
    assert client.put("/v1/files/oversized", headers=auth, content=b"x" * 65).status_code == 413
    assert client.get("/v1/files/oversized", headers=auth).status_code == 404


def test_failed_and_racing_uploads_never_publish_partial_data(client, tokens, config):
    user_id = client.get("/v1/me", headers=tokens["alice"]).json()["user_id"]
    storage = client.app.state.storage
    abandoned = storage.begin_upload(user_id, "abandoned", 64, False)
    abandoned.write(b"partial")
    abandoned.close()
    assert client.get("/v1/files/abandoned", headers=tokens["alice"]).status_code == 404
    first = storage.begin_upload(user_id, "race", 64, False)
    second = storage.begin_upload(user_id, "race", 64, False)
    first.write(b"complete first")
    second.write(b"complete second")
    def commit(upload):
        try:
            upload.commit()
            return 201
        except StorageError as error:
            return error.status
        finally:
            upload.close()
    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(commit, (first, second)))
    assert sorted(results) == [201, 409]
    assert client.get("/v1/files/race", headers=tokens["alice"]).content in (b"complete first", b"complete second")
    assert not list(config.data_root.rglob(TEMP_PREFIX + "*"))


def test_replace_requires_explicit_overwrite_and_commit(client, tokens):
    auth = tokens["alice"]
    assert client.put("/v1/files/data", headers=auth, content=b"old").status_code == 201
    assert client.put("/v1/files/data", headers=auth, content=b"new").status_code == 409
    assert client.get("/v1/files/data", headers=auth).content == b"old"
    assert client.put("/v1/files/data?overwrite=true", headers=auth, content=b"new").status_code == 201
    assert client.get("/v1/files/data", headers=auth).content == b"new"


def test_tokens_stored_as_digests_and_logout_revokes(client, tokens):
    auth = tokens["alice"]
    raw_token = auth["Authorization"].split(" ")[1]
    with client.app.state.database.session() as db:
        access = db.get(AccessSession, digest_token(raw_token))
        assert access is not None
        assert access.token_digest != raw_token
        user = db.get(User, access.user_id)
        assert user.password_hash.startswith("$argon2id$")
        assert "alice-password" not in user.password_hash
    assert client.post("/v1/auth/logout", headers=auth).status_code == 204
    assert client.get("/v1/me", headers=auth).status_code == 401


def test_expiry_and_disabled_user_invalidate_existing_sessions(client, tokens):
    auth = tokens["alice"]
    with client.app.state.database.session() as db:
        db.execute(update(AccessSession).where(AccessSession.token_digest == digest_token(auth["Authorization"].split()[1])).values(expires_at=int(time.time()) - 1))
    assert client.get("/v1/me", headers=auth).status_code == 401
    with client.app.state.database.session() as db:
        user = db.scalar(select(User).where(User.username == "bruce"))
        user.enabled = False
    assert client.get("/v1/me", headers=tokens["bruce"]).status_code == 401
    assert client.post("/v1/auth/login", json={"username": "bruce", "password": "bruce-password-for-tests"}).status_code == 401


def test_bad_login_is_generic_and_rate_limited(config):
    with TestClient(create_app(replace(config, login_attempts=2))) as client:
        first = client.post("/v1/auth/login", json={"username": "missing", "password": "wrong"})
        second = client.post("/v1/auth/login", json={"username": "missing", "password": "wrong"})
        third = client.post("/v1/auth/login", json={"username": "different", "password": "wrong"})
        assert first.status_code == second.status_code == 401
        assert first.json()["detail"] == "invalid username or password"
        assert third.status_code == 429
        assert "retry-after" in third.headers


def test_account_limiter_normalizes_whitespace_across_peers(config):
    # The login identity strips whitespace, so account throttling must do the
    # same even if requests arrive through different client IP addresses.
    app = create_app(replace(config, login_attempts=2))
    async def scenario():
        async with app.router.lifespan_context(app):
            results = []
            for peer, username in (("192.0.2.1", "alice"), ("192.0.2.2", " Alice "), ("192.0.2.3", "alice  ")):
                transport = httpx.ASGITransport(app=app, client=(peer, 1234))
                async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                    response = await client.post("/v1/auth/login", json={"username": username, "password": "wrong"})
                    results.append(response.status_code)
            assert results == [401, 401, 429]
    anyio.run(scenario)


def test_bounded_json_requests_do_not_echo_secrets(client):
    response = client.post("/v1/auth/login", content=b"x" * 20000)
    assert response.status_code == 413
    response = client.post("/v1/auth/login", json={"username": "alice", "password": "secret", "extra": "value"})
    assert response.status_code == 422
    assert "secret" not in response.text


@pytest.mark.parametrize("header,expected,status", [(None, b"0123456789", 200), ("bytes=2-5", b"2345", 206), ("bytes=7-", b"789", 206), ("bytes=-3", b"789", 206), ("bytes=0-999", b"0123456789", 206)])
def test_download_byte_ranges(client, tokens, header, expected, status):
    auth = tokens["alice"]
    client.put("/v1/files/data", headers=auth, content=b"0123456789")
    response = client.get("/v1/files/data", headers={**auth, **({"Range": header} if header else {})})
    assert response.status_code == status
    assert response.content == expected
    assert int(response.headers["content-length"]) == len(expected)


@pytest.mark.parametrize("header", ["bytes=10-", "bytes=7-2", "bytes=-0", "bytes=1-2,4-5", "bytes=" + "1" * 5000 + "-", "unknown=1-2"])
def test_invalid_range_rejected(client, tokens, header):
    auth = tokens["alice"]
    client.put("/v1/files/data", headers=auth, content=b"0123456789")
    assert client.get("/v1/files/data", headers={**auth, "Range": header}).status_code == 416
