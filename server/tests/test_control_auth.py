"""Real MySQL-only control-plane tracer bullet. No SQLite fallback."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text


@pytest.fixture(scope='module')
def control():
    assert importlib.util.find_spec('orangespace_control.app') is not None, 'control HTTP application missing'
    from orangespace_control.config import load_config
    from orangespace_common.mysql import create_mysql_engine
    from orangespace_control.app import create_app
    from orangespace_control.cli import bootstrap_admin
    from alembic.config import Config
    from alembic import command
    config_path = os.environ.get('ORANGESPACE_CONTROL_TEST_CONFIG')
    if not config_path:
        pytest.skip('real isolated MySQL protected config not supplied')
    from dataclasses import replace
    from sqlalchemy.engine import make_url
    source = load_config(config_path)
    owner = create_mysql_engine(source.database_url)
    schema = 'osp_control_test_' + uuid.uuid4().hex
    engine = None
    created = False
    try:
        with owner.begin() as conn:
            conn.execute(text(f'CREATE DATABASE `{schema}` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin'))
            created = True
        config = replace(source, database_url=make_url(source.database_url).set(database=schema).render_as_string(hide_password=False))
        engine = create_mysql_engine(config.database_url)
        cfg = Config(str(Path(__file__).parents[1] / 'alembic-control.ini'))
        with engine.connect() as connection:
            cfg.attributes['connection'] = connection
            command.upgrade(cfg, 'head')
        name = 'admin_' + uuid.uuid4().hex[:12]
        password = 'Correct-test-only-' + uuid.uuid4().hex
        admin = bootstrap_admin(engine, name, password)
        with TestClient(create_app(config, engine=engine), raise_server_exceptions=False) as client:
            yield client, engine, name, password, admin, config_path
    finally:
        if engine is not None:
            engine.dispose()
        if created:
            with owner.begin() as conn:
                conn.execute(text(f'DROP DATABASE `{schema}`'))
                assert conn.execute(text('SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name=:name'), {'name': schema}).scalar_one() == 0
        owner.dispose()


def login(client, name, password):
    response = client.post('/control/v1/auth/login', json={'schema': 1, 'username': name, 'password': password})
    assert response.status_code == 200, response.text
    assert response.headers['cache-control'] == 'no-store'
    data = response.json()
    assert set(data) == {'schema', 'access_token', 'token_type', 'central_session_id', 'expires_at', 'user', 'nodes', 'nodes_next_cursor'}
    assert set(data['user']) == {'central_user_id', 'username', 'role', 'enabled', 'user_epoch', 'created_at'}
    assert len(data['access_token']) == 43
    return data, {'Authorization': 'Bearer ' + data['access_token']}


def test_mysql_migration_bootstrap_login_session(control):
    client, engine, name, password, admin, _ = control
    result, auth = login(client, name.upper(), password)
    assert result['user']['central_user_id'] == admin['central_user_id']
    assert result['user']['username'] == name
    assert result['user']['role'] == 'admin'
    response = client.get('/control/v1/session', headers=auth)
    assert response.status_code == 200
    assert response.json()['central_session_id'] == result['central_session_id']
    assert client.get('/control/v1/session').status_code == 401
    assert client.post('/control/v1/auth/login', json={'schema': 1, 'username': name, 'password': password + 'wrong'}).status_code == 401
    with engine.connect() as conn:
        tables = set(conn.execute(text('SHOW TABLES')).scalars())
        assert {'control_users', 'control_sessions', 'control_nodes', 'control_identity_mappings', 'control_grants', 'control_audit_events'} <= tables
        hashes = conn.execute(text('SELECT password_hash FROM control_users')).scalars().all()
        assert all(value.startswith('$argon2id$') for value in hashes)
        tokens = conn.execute(text('SELECT token_digest FROM control_sessions')).scalars().all()
        assert all(isinstance(value, bytes) and len(value) == 32 for value in tokens)
        assert result['access_token'].encode() not in tokens
        assert conn.execute(text('SELECT @@transaction_isolation')).scalar() == 'READ-COMMITTED'
