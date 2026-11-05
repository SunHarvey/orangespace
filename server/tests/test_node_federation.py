"""Real isolated MySQL + centre ASGI; no TLS bypass in production."""
import json
from dataclasses import replace
from uuid import UUID
import pytest
from fastapi.testclient import TestClient
from test_control_auth import control
from test_control_exchange import setup, ISSUE
from orangespace_node.app import create_app
from orangespace_node.auth import create_user
from orangespace_control.schema_v1 import grants


def test_real_exchange_identity_revocation_cleanup(control, config, tmp_path, monkeypatch):
    from orangespace_node import federation
    c, engine, user, machine, payload, legacy, gid, logged = setup(control)
    path = tmp_path / 'federation.json'
    path.write_text(json.dumps(dict(origin='https://centre.test', token=machine['Authorization'][7:], node_id=payload['node_id'], node_epoch=1, config_revision=1, node_api_origin='https://node.test')))
    path.chmod(0o600)
    settings = replace(config, node_id=UUID(payload['node_id']), federation_config=path)
    # Explicit test-only centre ASGI adapter: real centre handlers + real MySQL.
    def post(self, route, data):
        return c.post(route, json=data, headers=machine)
    monkeypatch.setattr(federation.Federation, '_post', post)
    with TestClient(create_app(settings)) as n:
        local = create_user(n.app.state.database, 'localuser', 'local-password-for-tests')
        from orangespace_control.schema_v1 import mappings
        with engine.begin() as db:
            db.execute(mappings.update().where(mappings.c.node_id == UUID(payload['node_id']).bytes).values(legacy_user_id=UUID(local.id).bytes))
        ticket = c.post(ISSUE, headers=user, json=payload).json()
        body = dict(schema=1, exchange_id=ticket['exchange_id'], exchange_token=ticket['exchange_token'])
        r = n.post('/federation/v1/sessions/exchange', json=body)
        assert r.status_code == 200, r.text
        credential = r.json()['node_credential']
        assert set(credential) == {'schema','node_id','api_origin','access_token','expires_at'}
        assert credential['access_token'] != ticket['exchange_token']
        h = {'Authorization':'Bearer '+credential['access_token']}
        assert n.get('/v1/me',headers=h).json()['user_id'] == local.id
        # These counters prove pre-manager denial, not actual forwarding.
        calls = []
        def unexpected_manager(*args, **kwargs):
            calls.append(True)
            raise AssertionError('federated permit gate reached manager')
        monkeypatch.setattr(n.app.state.tunnels, 'create', unexpected_manager)
        monkeypatch.setattr(n.app.state.tunnels, 'renew', unexpected_manager)
        from fastapi import Depends
        from orangespace_node.app import identity
        @n.app.get('/unmapped', dependencies=[Depends(identity)])
        def unmapped():
            return {}
        assert n.get('/unmapped', headers=h).status_code == 403
        # A mounted deployment must enforce the same file scopes as a root app.
        assert n.put('/v1/files/no-write.txt',headers=h,content=b'fixture').status_code == 403
        from fastapi import FastAPI
        parent = FastAPI()
        prefix = '/nodes/' + payload['node_id']
        parent.mount(prefix, n.app)
        with TestClient(parent) as mounted:
            mounted_write = mounted.put(prefix+'/v1/files/no-write.txt',headers=h,content=b'fixture')
            assert mounted_write.status_code == 403, mounted_write.status_code
            for client, root in ((n, ''), (mounted, prefix)):
                assert client.get(root+'/v1/files', headers=h).status_code == 200
                assert client.get(root+'/v1/files/missing.txt', headers=h).status_code == 404
                assert client.get(root+'/v1/session', headers=h).status_code == 200
                for route in ('/v1/tunnels', '/v1/tunnels/00000000-0000-4000-8000-000000000001/renew'):
                    assert client.post(root+route, headers=dict(h, **{'X-OrangeSpace-Lease-Schema':'2'}), json={}).status_code == 403
            assert calls == []
        assert n.post('/federation/v1/sessions/exchange',json=body).status_code == 409
        assert n.post('/v1/auth/login',json={}).status_code == 403
        assert n.post('/v1/tunnels',headers=h,json={}).status_code == 403
        from orangespace_node.auth import login as local_login
        old, _ = local_login(n.app.state.database, 'localuser', 'local-password-for-tests', 60)
        assert n.get('/v1/me', headers={'Authorization':'Bearer '+old}).status_code == 401
        ticket_b = c.post(ISSUE, headers=user, json=payload).json()
        body_b = dict(schema=1, exchange_id=ticket_b['exchange_id'], exchange_token=ticket_b['exchange_token'])
        rb = n.post('/federation/v1/sessions/exchange',json=body_b)
        assert rb.status_code == 200
        hb = {'Authorization':'Bearer '+rb.json()['node_credential']['access_token']}
        assert n.post('/federation/v1/sessions/exchange-cleanup',json=body).status_code == 200
        assert n.get('/v1/me',headers=hb).status_code == 200
        for bad in (True, 1.0):
            assert n.post('/federation/v1/sessions/exchange',json=dict(body,schema=bad)).status_code == 422
        def unavailable(self, route, data):
            raise OSError('test-only unavailable centre')
        monkeypatch.setattr(federation.Federation, '_post', unavailable)
        assert n.get('/v1/me',headers=hb).status_code == 503
        monkeypatch.setattr(federation.Federation, '_post', post)
        with engine.begin() as db:
            db.execute(grants.update().where(grants.c.id==gid).values(enabled=False,grant_epoch=2))
        assert n.get('/v1/me',headers=hb).status_code in (401,410)
        assert n.post('/federation/v1/sessions/exchange-cleanup',json=body).json() == {'schema':1,'local_session_state':'revoked'}
        assert n.get('/v1/me',headers=h).status_code == 401
