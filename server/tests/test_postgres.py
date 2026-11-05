"""Legacy filename retained for test selectors; runtime acceptance is MySQL only."""
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from orangespace_node.app import create_app
from orangespace_node.auth import create_user, digest_token
from orangespace_node.database import AccessSession


def test_mysql_account_sessions_and_private_file_api(config):
    with TestClient(create_app(config)) as client:
        database = client.app.state.database
        create_user(database, "alice", "alice-mysql-test-password")
        create_user(database, "bruce", "bruce-mysql-test-password")
        with pytest.raises(IntegrityError):
            create_user(database, " ALICE ", "duplicate-mysql-test-password")

        def sign_in(username):
            response = client.post("/v1/auth/login", json={
                "username": username,
                "password": f"{username}-mysql-test-password",
            })
            assert response.status_code == 200
            assert response.json()["node_id"] == str(config.node_id)
            return {"Authorization": "Bearer " + response.json()["access_token"]}

        alice = sign_in("alice")
        bruce = sign_in("bruce")
        token_digest = digest_token(alice["Authorization"].split()[1])
        with database.session() as session:
            stored = session.scalar(select(AccessSession).where(AccessSession.token_digest == token_digest))
            assert stored is not None
            assert stored.revoked_at is None
        assert client.get("/v1/me", headers=alice).json()["username"] == "alice"
        assert client.post("/v1/directories", headers=alice, json={"path": "docs"}).status_code == 201
        assert client.put("/v1/files/docs/private.txt", headers=alice, content=b"alice private file").status_code == 201
        assert client.get("/v1/files/docs/private.txt", headers=alice).content == b"alice private file"
        assert client.get("/v1/files/docs/private.txt", headers=bruce).status_code == 404
        assert client.get("/v1/files", headers=bruce).json()["entries"] == []
        assert client.put("/v1/files/private.txt", headers=bruce, content=b"bruce private file").status_code == 201
        assert client.get("/v1/files/private.txt", headers=alice).status_code == 404
        assert client.get("/v1/files/private.txt", headers=bruce).content == b"bruce private file"
        assert client.post("/v1/auth/logout", headers=alice).status_code == 204
        assert client.get("/v1/me", headers=alice).status_code == 401
        with database.session() as session:
            assert session.get(AccessSession, token_digest).revoked_at is not None
