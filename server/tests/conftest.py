import json
import os
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.schema import CreateSchema, DropSchema

from orangespace_common.database import create_mysql_engine, load_database_url
from orangespace_common.node_migrations import upgrade
from orangespace_node.app import create_app
from orangespace_node.auth import create_user
from orangespace_node.config import Settings


@pytest.fixture
def mysql_config_path(tmp_path):
    """Own exactly one fresh schema; never migrate/reset the supplied database."""
    source = os.environ.get("ORANGESPACE_TEST_MYSQL_CONFIG")
    if not source:
        pytest.skip("requires protected MySQL config path: ORANGESPACE_TEST_MYSQL_CONFIG")
    base = make_url(load_database_url(source))
    administrator = create_mysql_engine(base.set(database="information_schema").render_as_string(hide_password=False))
    schema = "orangespace_node_test_" + uuid4().hex
    created = False
    engine = None
    path = tmp_path / "database.json"
    try:
        with administrator.begin() as connection:
            connection.execute(CreateSchema(schema))
        created = True
        scoped = base.set(database=schema).render_as_string(hide_password=False)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump({"database_url": scoped}, stream)
        engine = create_mysql_engine(scoped)
        upgrade(engine)
        engine.dispose()
        yield path
    finally:
        if engine is not None:
            engine.dispose()
        try:
            if created:
                with administrator.begin() as connection:
                    connection.execute(DropSchema(schema))
                with administrator.connect() as connection:
                    assert connection.scalar(text("SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=:schema"), {"schema": schema}) == 0
        finally:
            administrator.dispose()
            path.unlink(missing_ok=True)


@pytest.fixture
def config(tmp_path, mysql_config_path):
    return Settings(node_id=UUID("4eef0765-2443-4879-badb-02967baac185"), data_root=tmp_path / "files",
                    database_url=load_database_url(mysql_config_path), max_upload_bytes=64,
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
