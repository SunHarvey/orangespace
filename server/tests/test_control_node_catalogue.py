"""Real MySQL catalogue authorization; seeded rows do not prove node enrollment."""
import hashlib
import time
from uuid import uuid4
from test_control_auth import control, login
from test_control_users import make_user
from orangespace_control.schema_v1 import nodes, mappings, grants
from orangespace_control.security import canonical, show


def test_node_catalogue_filters_mapping_grant_state_expiry_and_revocation(control):
    client, engine, name, password, _, _ = control
    _, admin = login(client, name, password)
    user, uname, upass = make_user(client, admin)
    _, ordinary = login(client, uname, upass)
    response = client.get('/control/v1/me/nodes', headers=ordinary)
    assert response.status_code == 200
    assert response.json()['items'] == []
    principal = canonical(user['central_user_id'])
    allowed = None
    with engine.begin() as conn:
        for case in ('allowed', 'disabled', 'pending', 'expired'):
            nid = uuid4().bytes
            key = uuid4().bytes + uuid4().bytes
            conn.execute(nodes.insert().values(id=nid, alias='node_' + uuid4().hex[:16],
                display_name=case, api_origin='https://node.example.test', tls_server_name='node.example.test',
                public_key=key, key_fingerprint=hashlib.sha256(key).digest(),
                state='pending' if case == 'pending' else 'active', node_epoch=1, config_revision=1))
            conn.execute(mappings.insert().values(id=uuid4().bytes, node_id=nid,
                legacy_user_id=uuid4().bytes, central_user_id=principal, state='approved',
                mapping_epoch=1, evidence_digest=hashlib.sha256(b'trusted test fixture inventory').digest(), reason='test fixture'))
            conn.execute(grants.insert().values(id=uuid4().bytes, user_id=principal, node_id=nid,
                enabled=case != 'disabled', grant_epoch=1, scopes=['tunnel'],
                valid_until=int(time.time()) - 1 if case == 'expired' else None))
            if case == 'allowed':
                allowed = nid
    response = client.get('/control/v1/me/nodes', headers=ordinary)
    assert response.status_code == 200
    assert [row['node_id'] for row in response.json()['items']] == [show(allowed)]
    assert 'machine_token_digest' not in response.text
    assert client.get('/control/v1/admin/nodes', headers=ordinary).status_code == 403
    listing = client.get('/control/v1/admin/nodes', headers=admin)
    assert listing.status_code == 200
    assert len(listing.json()['items']) == 4
    assert 'machine_token_digest' not in listing.text
    assert client.get('/control/v1/me/nodes?central_user_id=' + user['central_user_id'], headers=ordinary).status_code == 422
    with engine.begin() as conn:
        conn.execute(grants.update().where(grants.c.node_id == allowed).values(enabled=False, grant_epoch=2))
    assert client.get('/control/v1/me/nodes', headers=ordinary).json()['items'] == []
    session, _ = login(client, uname, upass)
    assert session['nodes'] == []
