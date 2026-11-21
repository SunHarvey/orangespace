"""Node with memory-only state and no database (real Centre on MySQL, ASGI).

A model child stands in for sing-box: this proves authority and bookkeeping,
not forwarding.
"""
import json
import secrets
from types import SimpleNamespace
from uuid import UUID, uuid4
import pytest
from fastapi.testclient import TestClient
from test_control_auth import control, login
from test_control_users import make_user
from test_control_exchange import ISSUE
from orangespace_control import cli
from orangespace_control.enrollment import digest
from orangespace_control.schema_v1 import nodes
from orangespace_node.app import create_app
from orangespace_node.config import Settings
from orangespace_node.database import MEMORY

LEASE = {'X-OrangeSpace-Lease-Schema': '2'}


def memory_node(control, tmp_path, monkeypatch):
    from orangespace_node import federation
    client, engine, name, password, _, _ = control
    _, admin = login(client, name, password)
    user, uname, upass = make_user(client, admin)
    _, auth = login(client, uname, upass)
    machine, nid, alias = secrets.token_urlsafe(32), uuid4(), 'n' + uuid4().hex[:12]
    with engine.begin() as conn:
        conn.execute(nodes.insert().values(id=nid.bytes, alias=alias, display_name='memory node',
            api_origin='https://node.test', tls_server_name='node.test', public_key=b'p' * 32,
            key_fingerprint=b'k' * 32, machine_token_digest=digest(b'node-machine', machine),
            state='active', node_epoch=1, config_revision=1))
    cli.grant(engine, uname, alias, ['tunnel', 'files.read', 'files.write'], True)
    path = tmp_path / 'federation.json'
    path.write_text(json.dumps(dict(origin='https://centre.test', token=machine, node_id=str(nid),
                                    node_epoch=1, config_revision=1, node_api_origin='https://node.test')))
    path.chmod(0o600)
    monkeypatch.setattr(federation.Federation, '_post',
                        lambda self, route, data: client.post(route, json=data, headers={'Authorization': 'Bearer ' + machine}))
    settings = Settings(node_id=nid, data_root=tmp_path / 'files', database_url=MEMORY, federation_config=path)
    epochs = dict(user_epoch=1, node_epoch=1, mapping_epoch=1, grant_epoch=1)

    def credential(node):
        ticket = client.post(ISSUE, headers=auth, json=dict(schema=1, node_id=str(nid), expected_epochs=epochs)).json()
        r = node.post('/federation/v1/sessions/exchange', json=dict(schema=1, exchange_id=ticket['exchange_id'], exchange_token=ticket['exchange_token']))
        assert r.status_code == 200, r.text
        return {'Authorization': 'Bearer ' + r.json()['node_credential']['access_token']}
    return settings, user, credential


def model_runtime(node, monkeypatch):
    manager = node.app.state.tunnels
    manager.config = SimpleNamespace(max_leases=4, port_start=21000, port_end=21003, lease_seconds=30,
                                     endpoint_ip='127.0.0.1', tls_server_name='node.test', probe_port=20000)
    monkeypatch.setattr(manager, '_start', lambda reply, deadline=None: SimpleNamespace(poll=lambda: None))
    monkeypatch.setattr(manager, '_stop', lambda process: None)
    return manager


def test_memory_node_uses_centre_identity_files_and_leases(control, tmp_path, monkeypatch):
    settings, user, credential = memory_node(control, tmp_path, monkeypatch)
    sandbox = str(uuid4())
    first = dict(tunnel_id=str(uuid4()), sandbox_id=sandbox, generation=1)
    with TestClient(create_app(settings)) as node:
        assert node.app.state.database.memory
        h = credential(node)
        me = node.get('/v1/me', headers=h).json()
        assert me['user_id'] == user['central_user_id']
        assert node.put('/v1/files/notes.txt', headers=h, content=b'kept on disk').status_code == 201
        assert node.post('/v1/auth/login', json=dict(username='x' * 3, password='y' * 12)).status_code == 403
        model_runtime(node, monkeypatch)
        made = node.post('/v1/tunnels', headers=dict(h, **LEASE), json=first)
        assert made.status_code == 200, made.text
        assert node.post('/v1/tunnels/' + first['tunnel_id'] + '/renew', headers=dict(h, **LEASE), json={}).status_code == 200

    # Restart: every node-side session and lease is gone; files stay on disk.
    with TestClient(create_app(settings)) as node:
        assert node.get('/v1/me', headers=h).status_code == 401
        h2 = credential(node)
        assert [e['name'] for e in node.get('/v1/files', headers=h2).json()['entries']] == ['notes.txt']
        model_runtime(node, monkeypatch)
        # The node forgot the old tunnel; the Centre did not.
        assert node.post('/v1/tunnels', headers=dict(h2, **LEASE), json=first).status_code == 409
        assert node.post('/v1/tunnels', headers=dict(h2, **LEASE), json=dict(first, tunnel_id=str(uuid4()))).status_code == 409
        second = dict(first, tunnel_id=str(uuid4()), generation=2)
        assert node.post('/v1/tunnels', headers=dict(h2, **LEASE), json=second).status_code == 200


def test_memory_state_requires_federation_and_no_database_config(tmp_path, monkeypatch):
    with pytest.raises(ValueError):
        Settings(node_id=uuid4(), data_root=tmp_path, database_url=MEMORY)
    monkeypatch.setenv('ORANGESPACE_NODE_STATE', 'memory')
    monkeypatch.setenv('ORANGESPACE_NODE_ID', str(uuid4()))
    monkeypatch.setenv('ORANGESPACE_DATA_ROOT', str(tmp_path))
    monkeypatch.setenv('ORANGESPACE_DATABASE_CONFIG', str(tmp_path / 'database.json'))
    monkeypatch.setenv('ORANGESPACE_FEDERATION_CONFIG', str(tmp_path / 'federation.json'))
    with pytest.raises(ValueError):
        Settings.from_env()
    monkeypatch.delenv('ORANGESPACE_DATABASE_CONFIG')
    assert Settings.from_env().database_url == MEMORY
    monkeypatch.setenv('ORANGESPACE_NODE_STATE', 'disk')
    with pytest.raises(ValueError):
        Settings.from_env()
