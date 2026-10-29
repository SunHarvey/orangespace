"""Opt-in real PostgreSQL verification, isolated in one fresh disposable schema.

Set ORANGESPACE_TEST_POSTGRES_URL to a PostgreSQL SQLAlchemy URL using psycopg.
The database role needs CREATE SCHEMA, not a dedicated/destructively reset DB.
"""
import os
from uuid import uuid4

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.schema import CreateSchema, DropSchema

from orangespace_node.app import create_app
from orangespace_node.auth import create_user, digest_token
from orangespace_node.config import Settings
from orangespace_node.database import AccessSession


POSTGRES_URL = os.environ.get("ORANGESPACE_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(not POSTGRES_URL, reason="set ORANGESPACE_TEST_POSTGRES_URL for a real PostgreSQL test")


@pytest.fixture
def postgres_config(tmp_path):
    url = make_url(POSTGRES_URL)
    if url.get_backend_name() != "postgresql":
        pytest.fail("ORANGESPACE_TEST_POSTGRES_URL must use PostgreSQL")
    # UUID hex is generated locally; no URL or user-supplied identifier is used
    # in CREATE/DROP. SQLAlchemy quotes the schema name as an identifier.
    schema = "orangespace_test_" + uuid4().hex
    administrator = create_engine(url, pool_pre_ping=True)
    created = False
    try:
        with administrator.begin() as connection:
            connection.execute(CreateSchema(schema))
        created = True
        options = url.query.get("options", "")
        if not isinstance(options, str):
            pytest.fail("PostgreSQL URL must contain at most one options value")
        scoped_url = url.update_query_dict({"options": (options + " -csearch_path=" + schema).strip()})
        yield Settings(
            node_id=uuid4(),
            data_root=tmp_path / "postgres-files",
            database_url=scoped_url.render_as_string(hide_password=False),
            max_upload_bytes=1024,
        )
    finally:
        try:
            if created:
                # Only this invocation's random schema is removed. Never
                # drop_all or touch public/existing application schemas.
                with administrator.begin() as connection:
                    connection.execute(DropSchema(schema, cascade=True))
        finally:
            administrator.dispose()


def test_postgres_account_sessions_and_private_file_api(postgres_config):
    with TestClient(create_app(postgres_config)) as client:
        database = client.app.state.database
        create_user(database, "alice", "alice-postgres-test-password")
        create_user(database, "bruce", "bruce-postgres-test-password")
        # PostgreSQL enforces the unique username index, including the same
        # normalization used by the administrator CLI.
        with pytest.raises(IntegrityError):
            create_user(database, " ALICE ", "duplicate-postgres-test-password")

        def sign_in(username):
            response = client.post("/v1/auth/login", json={
                "username": username,
                "password": f"{username}-postgres-test-password",
            })
            assert response.status_code == 200
            assert response.json()["node_id"] == str(postgres_config.node_id)
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
