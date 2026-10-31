"""Real MySQL grants; explicit verified-node seeds, never deployment evidence."""
import hashlib
from uuid import uuid4
from sqlalchemy import select, func
from test_control_auth import control, login
from test_control_users import make_user
from orangespace_control.schema_v1 import nodes, mappings, grants, audit
from orangespace_control.security import canonical, show, now


def fixture(control):
    client, engine, name, password, _, _ = control
    _, admin = login(client, name, password)
    user, uname, upass = make_user(client, admin)
    _, ordinary = login(client, uname, upass)
    nid = uuid4().bytes
    key = b'k' * 32
    with engine.begin() as conn:
        conn.execute(nodes.insert().values(id=nid, alias='n_' + uuid4().hex, display_name='verified fixture', api_origin='https://node.example.test', tls_server_name='node.example.test', public_key=key, key_fingerprint=hashlib.sha256(key).digest(), machine_token_digest=hashlib.sha256(uuid4().bytes).digest(), state='active', node_epoch=1, config_revision=1))
    path = '/control/v1/admin/users/' + user['central_user_id'] + '/nodes/' + show(nid) + '/grant'
    return client, engine, admin, user, ordinary, nid, path


def payload(epoch=0, **changes):
    return dict(dict(schema=1, expected_grant_epoch=epoch, enabled=True, scopes=['tunnel'], valid_until=None, reason='grant fixture'), **changes)


def test_grant_creation_rbac_and_mapping_gate(control):
    client, engine, admin, user, ordinary, nid, path = fixture(control)
    assert client.put(path, headers=admin, json=payload()).status_code == 200
    assert client.get('/control/v1/me/nodes', headers=ordinary).json()['items'] == []
    assert client.put(path, headers=ordinary, json=payload()).status_code == 403
    assert client.get('/control/v1/admin/grants', headers=ordinary).status_code == 403
    assert client.get('/control/v1/admin/grants').status_code == 401
    assert client.put(path, headers=admin, json=payload()).status_code == 409


def approve_fixture(engine, user, nid):
    with engine.begin() as conn:
        conn.execute(mappings.insert().values(id=uuid4().bytes, node_id=nid, legacy_user_id=uuid4().bytes,
            central_user_id=canonical(user['central_user_id']), state='approved', mapping_epoch=1,
            evidence_digest=hashlib.sha256(b'explicit verified fixture inventory').digest(), reason='verified fixture only'))


def test_scoped_revoke_expiry_and_other_node_survives(control):
    from orangespace_control.authorization_schema import events
    client, engine, admin, user, ordinary, nid, path = fixture(control)
    approve_fixture(engine, user, nid)
    first = client.put(path, headers=admin, json=payload()).json()
    other = uuid4().bytes
    with engine.begin() as conn:
        source = dict(conn.execute(select(nodes).where(nodes.c.id == nid)).mappings().one())
        source.update(id=other, alias='n_' + uuid4().hex, machine_token_digest=hashlib.sha256(uuid4().bytes).digest())
        conn.execute(nodes.insert().values(**source))
    approve_fixture(engine, user, other)
    bpath = path.replace(show(nid), show(other))
    b = client.put(bpath, headers=admin, json=payload()).json()
    assert len(client.get('/control/v1/me/nodes', headers=ordinary).json()['items']) == 2
    result = client.put(path, headers=admin, json=payload(1, enabled=False)).json()
    assert result['grant_epoch'] == 2
    assert result['revocation']['cleanup_state'] == 'pending'
    assert result['revocation']['enforcement_deadline'] == result['revocation']['committed_at'] + 30
    assert client.get('/control/v1/session', headers=ordinary).status_code == 200
    assert [r['node_id'] for r in client.get('/control/v1/me/nodes', headers=ordinary).json()['items']] == [show(other)]
    with engine.connect() as conn:
        event = conn.execute(select(events).where(events.c.grant_id == canonical(first['grant_id']))).mappings().one()
        assert event['user_id'] == canonical(user['central_user_id']) and event['node_id'] == nid
        assert event['before_epoch'] == 1 and event['after_epoch'] == 2 and event['delivery_state'] == 'pending'
        assert conn.execute(select(grants.c.grant_epoch).where(grants.c.id == canonical(b['grant_id']))).scalar_one() == 1
        assert conn.scalar(select(func.count()).select_from(audit).where(audit.c.object_id == canonical(first['grant_id']))) == 2
    assert client.put(bpath, headers=admin, json=payload(1, valid_until=now()-1)).status_code == 200
    assert client.get('/control/v1/me/nodes', headers=ordinary).json()['items'] == []
    foreign, fname, fpass = make_user(client, admin)
    _, foreign_auth = login(client, fname, fpass)
    assert client.get('/control/v1/me/nodes', headers=foreign_auth).json()['items'] == []
    assert client.put(path, headers=foreign_auth, json=payload(2)).status_code == 403


def test_strict_input_and_registered_node_gate(control):
    client, engine, admin, user, ordinary, nid, path = fixture(control)
    for field, values in {'expected_grant_epoch': [True, 0.0, -1], 'enabled': [1], 'scopes': [True, 1.0, ['tunnel','tunnel'], ['other'], [True], 'tunnel'], 'valid_until': [True, 1.0, -1], 'reason': ['', 'x'*513]}.items():
        for value in values:
            assert client.put(path, headers=admin, json=payload(**{field:value})).status_code == 422
    assert client.put(path, headers=admin, content='{"schema":1,"schema":1}').status_code == 422
    assert client.put(path, headers=admin, json={**payload(), 'unknown': 1}).status_code == 422
    with engine.begin() as conn:
        conn.execute(nodes.update().where(nodes.c.id == nid).values(machine_token_digest=None))
    assert client.put(path, headers=admin, json=payload()).status_code == 409
    assert client.put(path.replace(show(nid), str(uuid4())), headers=admin, json=payload()).status_code == 404


def test_concurrent_cas_first_insert_and_update_and_pagination(control):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from fastapi.testclient import TestClient
    client, engine, admin, user, ordinary, nid, path = fixture(control)
    for epoch in (0, 1):
        gate = Barrier(2)
        def update():
            # One portal per worker: synchronous SQL cannot serialize these
            # requests merely by sharing the original client's event loop.
            with TestClient(client.app, raise_server_exceptions=False) as peer:
                gate.wait(timeout=10)
                return peer.put(path, headers=admin, json=payload(epoch)).status_code
        with ThreadPoolExecutor(2) as pool:
            assert sorted(pool.map(lambda _: update(), range(2))) == [200, 409]
    with engine.connect() as conn:
        assert conn.scalar(select(func.count()).select_from(grants).where(grants.c.user_id == canonical(user['central_user_id']), grants.c.node_id == nid)) == 1
    all_ids, cursor = [], None
    while True:
        response = client.get('/control/v1/admin/grants?limit=1' + ('&cursor='+cursor if cursor else ''), headers=admin)
        assert response.status_code == 200
        data = response.json()
        all_ids.extend(r['grant_id'] for r in data['items'])
        cursor = data['next_cursor']
        if cursor is None:
            break
    assert len(all_ids) == len(set(all_ids))
    with engine.connect() as conn:
        assert len(all_ids) == conn.scalar(select(func.count()).select_from(grants))
