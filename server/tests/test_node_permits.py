"""Real MySQL + Centre/Node ASGI; model child, NOT helper forwarding."""
import json
from dataclasses import replace
from types import SimpleNamespace
from uuid import UUID, uuid4
import pytest
from fastapi.testclient import TestClient
from test_control_auth import control
from test_control_exchange import setup, ISSUE
from orangespace_node.app import create_app
from orangespace_node.auth import create_user
from orangespace_control.schema_v1 import grants, mappings
from orangespace_node.database import TunnelGrant


def test_permit_create_renew_real_authority(control, config, tmp_path, monkeypatch):
    from orangespace_node import federation
    c, engine, user, machine, payload, legacy, gid, logged = setup(control)
    with engine.begin() as db:
        db.execute(grants.update().where(grants.c.id == gid).values(scopes=['tunnel']))
    path = tmp_path / 'federation.json'
    path.write_text(json.dumps(dict(origin='https://centre.test', token=machine['Authorization'][7:], node_id=payload['node_id'], node_epoch=1, config_revision=1, node_api_origin='https://node.test')))
    path.chmod(0o600)
    seen = []
    def post(self, route, data):
        seen.append((route, data))
        return c.post(route, json=data, headers=machine)
    monkeypatch.setattr(federation.Federation, '_post', post)
    with TestClient(create_app(replace(config, node_id=UUID(payload['node_id']), federation_config=path))) as n:
        local = create_user(n.app.state.database, 'permituser', 'local-password-for-tests')
        with engine.begin() as db:
            db.execute(mappings.update().where(mappings.c.node_id == UUID(payload['node_id']).bytes).values(legacy_user_id=UUID(local.id).bytes))
        ticket = c.post(ISSUE, headers=user, json=payload).json()
        r = n.post('/federation/v1/sessions/exchange', json=dict(schema=1, exchange_id=ticket['exchange_id'], exchange_token=ticket['exchange_token']))
        assert r.status_code == 200
        h = {'Authorization':'Bearer '+r.json()['node_credential']['access_token'], 'X-OrangeSpace-Lease-Schema':'2'}
        manager = n.app.state.tunnels
        manager.config = SimpleNamespace(max_leases=4, port_start=21000, port_end=21003, lease_seconds=30, endpoint_ip='127.0.0.1', tls_server_name='node.test', probe_port=20000)
        starts = []
        def start(reply, deadline=None):
            starts.append(reply['tunnel_id'])
            return SimpleNamespace(poll=lambda: None)
        monkeypatch.setattr(manager, '_start', start)
        monkeypatch.setattr(manager, '_stop', lambda p: None)
        b = dict(tunnel_id=str(uuid4()), sandbox_id=str(uuid4()), generation=1)
        # Local grant remains a veto despite valid Centre permit.
        assert n.post('/v1/tunnels', headers=h, json=b).status_code == 403
        assert starts == []
        with manager.db.session() as db:
            db.add(TunnelGrant(user_id=local.id, enabled=True, epoch=1))
        made = n.post('/v1/tunnels', headers=h, json=b)
        assert made.status_code == 200, made.text
        assert 0 < made.json()['remaining_ttl_ms'] <= 30000
        old = manager.leases[b['tunnel_id']].deadline
        renewed = n.post('/v1/tunnels/'+b['tunnel_id']+'/renew', headers=h, json={})
        assert renewed.status_code == 200, renewed.text
        permits = [d for route,d in seen if route.endswith('/lease-permits')]
        assert [d['operation'] for d in permits] == ['create','create','renew']
        assert all((d['tunnel_id'],d['sandbox_id'],d['generation']) == (b['tunnel_id'],b['sandbox_id'],1) for d in permits)
        assert len({d['request_id'] for d in permits}) == 3
        # Response corruption is denied before any manager mutation.
        import httpx
        import time
        original_deadline = manager.leases[b['tunnel_id']].deadline
        bad_values = [('schema', True), ('schema', 1.0), ('permit_id', str(UUID(int=0))),
                      ('request_id', str(uuid4())), ('epochs', {'user_epoch':True}),
                      ('remaining_ttl_ms', 30001), ('remaining_ttl_ms', 0),
                      ('remaining_ttl_ms', 1.0), ('expires_at', True), ('extra', 1)]
        for key, value in bad_values:
            def corrupted(self, route, data):
                response = post(self, route, data)
                if route.endswith('/lease-permits'):
                    return httpx.Response(200, json=dict(response.json(), **{key:value}))
                return response
            monkeypatch.setattr(federation.Federation, '_post', corrupted)
            denied = n.post('/v1/tunnels/'+b['tunnel_id']+'/renew', headers=h, json={})
            assert denied.status_code == 503, (key, denied.text)
            assert manager.leases[b['tunnel_id']].deadline == original_deadline
        def exhausted(self, route, data):
            response = post(self, route, data)
            if route.endswith('/lease-permits'):
                time.sleep(0.01)
                return httpx.Response(200, json=dict(response.json(), remaining_ttl_ms=1))
            return response
        monkeypatch.setattr(federation.Federation, '_post', exhausted)
        assert n.post('/v1/tunnels/'+b['tunnel_id']+'/renew', headers=h, json={}).status_code == 503
        assert manager.leases[b['tunnel_id']].deadline == original_deadline
        monkeypatch.setattr(federation.Federation, '_post', post)
        assert n.post('/v1/tunnels', headers={'Authorization':h['Authorization']}, json=b).status_code == 426
        # Same tuple, newer authority: the old HTTP completion must not overwrite it.
        token = h['Authorization'][7:]
        current = n.app.state.federation.authenticate(token, 'tunnel')
        binding, snapshot = manager.renewal_snapshot(current, b['tunnel_id'])
        manager.renew(current, b['tunnel_id'])
        newer = manager.leases[b['tunnel_id']].deadline
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as stale:
            manager.renew(current, b['tunnel_id'], time.monotonic()+20, snapshot)
        assert stale.value.status_code == 409
        assert manager.leases[b['tunnel_id']].deadline == newer
        with engine.begin() as db:
            db.execute(grants.update().where(grants.c.id == gid).values(enabled=False, grant_epoch=2))
        deadline = manager.leases[b['tunnel_id']].deadline
        denied = n.post('/v1/tunnels/'+b['tunnel_id']+'/renew', headers=h, json={})
        assert denied.status_code in (401,403,410)
        assert manager.leases[b['tunnel_id']].deadline == deadline
        assert len(starts) == 1
