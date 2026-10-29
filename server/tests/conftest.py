from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from orangespace_node.app import create_app
from orangespace_node.auth import create_user
from orangespace_node.config import Settings


@pytest.fixture
def config(tmp_path):
    return Settings(node_id=UUID("4eef0765-2443-4879-badb-02967baac185"), data_root=tmp_path / "files",
                    database_url=f"sqlite:///{tmp_path / 'node.sqlite3'}", max_upload_bytes=64,
                    login_attempts=100)


@pytest.fixture
def client(config):
    with TestClient(create_app(config)) as test_client:
        create_user(test_client.app.state.database, "alice", "alice-password-for-tests")
        create_user(test_client.app.state.database, "bruce", "bruce-password-for-tests")
        yield test_client


@pytest.fixture
def tokens(client):
    result = {}
    for username in ("alice", "bruce"):
        response = client.post("/v1/auth/login", json={"username": username, "password": f"{username}-password-for-tests"})
        assert response.status_code == 200
        result[username] = {"Authorization": "Bearer " + response.json()["access_token"]}
    return result
