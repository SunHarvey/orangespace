"""Real MySQL permit-history views; never evidence of node forwarding."""
from uuid import uuid4

from sqlalchemy import select
from test_control_auth import control, login
from test_control_permits import prepared, PERMIT
from orangespace_control.permit_schema import permits
from orangespace_control.security import canonical, now

LEASES = '/control/v1/leases'


def test_lease_view_lists_real_permits_not_runtime_leases(control):
    client, engine, admin, machine, body, _, logged = prepared(control)
    first = client.post(PERMIT, headers=machine, json=body)
    assert first.status_code == 200
    assert client.post(PERMIT, headers=machine, json=body).json()['permit_id'] == first.json()['permit_id']
    renewed = client.post(PERMIT, headers=machine, json=dict(body, request_id=str(uuid4()), operation='renew'))
    assert renewed.status_code == 200
    ids = {first.json()['permit_id'], renewed.json()['permit_id']}
    with engine.begin() as conn:
        conn.execute(permits.update().where(permits.c.id == canonical(first.json()['permit_id'])).values(expires_at=now()-1))
    result = client.get(LEASES, headers=admin)
    assert result.status_code == 200
    assert result.headers['cache-control'] == 'no-store'
    data = result.json()
    assert data['view'] == 'permit_history'
    assert data['deduplication'] == 'permit_id'
    assert data['single_lease_stop_supported'] is False
    rows = {r['permit_id']: r for r in data['items'] if r['permit_id'] in ids}
    assert set(rows) == ids  # retry is one row; renewal remains a distinct issuance.
    assert rows[first.json()['permit_id']]['state'] == 'expired'
    assert rows[renewed.json()['permit_id']]['state'] == 'issued'
    for item in rows.values():
        assert item['recorded_state'] == 'issued'
        assert item['central_user_id'] == logged['user']['central_user_id']
        assert item['central_session_id'] == logged['central_session_id']
        assert item['federation_session_id'] == body['federation_session_id']
        assert item['sandbox_id'] == body['sandbox_id']
        assert item['tunnel_id'] == body['tunnel_id']
        assert item['generation'] == body['generation']
        assert item['forwarding_state'] == 'unknown'
        assert item['cleanup_state'] == 'unknown'
        assert 'remaining_ttl_ms' not in item  # stored original budget is not a live budget.
    with engine.connect() as conn:
        records = conn.execute(select(permits.c.state).where(permits.c.id.in_([canonical(i) for i in ids]))).scalars().all()
    assert records == ['issued', 'issued']  # GET does not mutate history.


def test_lease_view_rbac_pagination_and_strict_query(control):
    from test_control_users import make_user
    from test_control_exchange import ISSUE, CONSUME
    from orangespace_control.schema_v1 import mappings, grants, sessions
    from orangespace_control.security import uid

    client, engine, admin, machine, body, _, logged = prepared(control)
    foreign = client.post(PERMIT, headers=machine, json=body)
    assert foreign.status_code == 200
    account, name, password = make_user(client, admin)
    own_login, ordinary = login(client, name, password)
    user_id = canonical(account['central_user_id'])
    # Node identity comes from the authenticated permit's persisted binding.
    with engine.connect() as conn:
        nid = conn.scalar(select(permits.c.node_id).where(permits.c.id == canonical(foreign.json()['permit_id'])))
    with engine.begin() as conn:
        conn.execute(mappings.insert().values(id=uid(), node_id=nid, legacy_user_id=uid(), central_user_id=user_id, state='approved', mapping_epoch=1, evidence_digest=b'e'*32, reason='owned fixture'))
        conn.execute(grants.insert().values(id=uid(), user_id=user_id, node_id=nid, enabled=True, grant_epoch=1, scopes=['tunnel'], valid_until=now()+300))
    from orangespace_control.security import show
    ticket = client.post(ISSUE, headers=ordinary, json=dict(schema=1, node_id=show(nid), expected_epochs=body['expected_epochs']))
    assert ticket.status_code == 201
    ticket = ticket.json()
    federation = client.post(CONSUME, headers=machine, json=dict(schema=1, exchange_id=ticket['exchange_id'], exchange_token=ticket['exchange_token'], request_id=str(uuid4())))
    assert federation.status_code == 200
    own_body = dict(body, federation_session_id=federation.json()['federation']['federation_session_id'])
    expected = set()
    for operation in ('create', 'renew', 'renew'):
        issued = client.post(PERMIT, headers=machine, json=dict(own_body, operation=operation, request_id=str(uuid4())))
        assert issued.status_code == 200
        expected.add(issued.json()['permit_id'])
    assert client.get(LEASES).status_code == 401
    assert client.get(LEASES, headers=machine).status_code == 401
    assert client.get(LEASES+'?central_user_id='+logged['user']['central_user_id'], headers=ordinary).status_code == 403
    for query in ('limit=0', 'limit=101', 'limit=01', 'limit=1e1', 'limit=1&limit=2', 'cursor=bad', 'central_user_id=bad', 'scope=all', 'node_id='+show(nid)):
        assert client.get(LEASES+'?'+query, headers=ordinary).status_code == 422
    seen, cursor = [], None
    while True:
        result = client.get(LEASES, headers=ordinary, params=dict(limit='1', **({'cursor': cursor} if cursor else {})))
        assert result.status_code == 200
        data = result.json()
        assert all(row['central_user_id'] == account['central_user_id'] for row in data['items'])
        assert all(row['central_session_id'] == own_login['central_session_id'] for row in data['items'])
        seen.extend(row['permit_id'] for row in data['items'])
        cursor = data['next_cursor']
        if cursor is None:
            break
        assert len(seen) <= len(expected)
    assert len(seen) == len(expected) and set(seen) == expected
    filtered = client.get(LEASES, headers=admin, params={'central_user_id': account['central_user_id']})
    assert {r['permit_id'] for r in filtered.json()['items']} == expected
    all_rows = client.get(LEASES, headers=admin).json()['items']
    assert expected | {foreign.json()['permit_id']} <= {r['permit_id'] for r in all_rows}
    unknown = client.get(LEASES, headers=admin, params={'central_user_id': str(uuid4())})
    assert unknown.status_code == 200 and unknown.json()['items'] == []
    text = filtered.text
    for secret in (password, ordinary['Authorization'][7:], machine['Authorization'][7:], ticket['exchange_token']):
        assert secret not in text
    with engine.begin() as conn:
        conn.execute(sessions.update().where(sessions.c.id == canonical(own_login['central_session_id'])).values(revoked_at=now()))
    assert client.get(LEASES, headers=ordinary).status_code == 401
    assert client.get(LEASES, headers=admin, params={'central_user_id': account['central_user_id']}).status_code == 200


def test_sandboxes_are_explicitly_unavailable_not_invented(control):
    client, _, name, password, _, _ = control
    _, admin = login(client, name, password)
    assert client.get('/control/v1/sandboxes').status_code == 401
    response = client.get('/control/v1/sandboxes', headers=admin)
    assert response.status_code == 501
    assert response.json()['error']['code'] == 'not_implemented'
    assert response.headers['cache-control'] == 'no-store'
    assert 'items' not in response.json()
