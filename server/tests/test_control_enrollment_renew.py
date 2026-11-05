"""Admin expiry recovery: real isolated MySQL + Control ASGI, no live state."""
import pytest
from sqlalchemy import select
from test_control_auth import control, login
from test_control_enrollment import registration_case, completion
from orangespace_control.enrollment_schema import enrollments, challenges
from orangespace_control.schema_v1 import nodes, audit
from orangespace_control.security import canonical, now
from orangespace_control.enrollment import decode, digest
from test_control_users import make_user


def test_renew_denials_leave_row_and_audit_unchanged(control, monkeypatch):
    client, engine, _, _, old, _, _ = registration_case(control)
    _, admin = login(client, control[2], control[3])
    _, name, password = make_user(client, admin)
    _, ordinary = login(client, name, password)
    route = '/control/v1/admin/node-enrollments/'+old['enrollment_id']+'/renew'
    payload = dict(schema=1,expected_expires_at=old['expires_at'],reason='approved recovery')
    assert client.post(route,json=payload).status_code == 401
    assert client.post(route,json=payload,headers=ordinary).status_code == 403
    assert client.post(route,json=payload,headers=admin).status_code == 409  # active
    monkeypatch.setattr('orangespace_control.enrollment.now',lambda: old['expires_at'])
    for value in (True, 1.0, '1', -1, 9007199254740992):
        assert client.post(route,json=dict(payload,expected_expires_at=value),headers=admin).status_code == 422
    for bad in (dict(payload,schema=1.0), dict(payload,reason=' '),dict(payload,extra=1)):
        assert client.post(route,json=bad,headers=admin).status_code == 422
    assert client.post(route,json=dict(payload,expected_expires_at=old['expires_at']-1),headers=admin).status_code == 409
    with engine.connect() as conn:
        row = conn.execute(select(enrollments).where(enrollments.c.id == canonical(old['enrollment_id']))).mappings().one()
        assert row['token_digest'] == digest(b'enrollment',old['enrollment_token'])
        assert row['expires_at'] == old['expires_at']
        assert not conn.execute(select(audit).where(audit.c.action == 'node.enrollment.renew',audit.c.object_id == canonical(old['node_id']))).first()


def test_renew_audit_failure_rolls_back_all_mutation(control, monkeypatch):
    from orangespace_control.security import ControlError
    client, engine, _, _, old, root, request = registration_case(control)
    _, admin = login(client, control[2], control[3])
    challenge = client.post(root+'/challenge',json=request)
    assert challenge.status_code == 200
    monkeypatch.setattr('orangespace_control.enrollment.now',lambda: old['expires_at'])
    def fail_audit(*args):
        raise ControlError(503,'unavailable')
    monkeypatch.setattr('orangespace_control.enrollment.record_audit',fail_audit)
    response = client.post('/control/v1/admin/node-enrollments/'+old['enrollment_id']+'/renew',headers=admin,
        json=dict(schema=1,expected_expires_at=old['expires_at'],reason='approved recovery'))
    assert response.status_code == 503
    with engine.connect() as conn:
        row = conn.execute(select(enrollments).where(enrollments.c.id == canonical(old['enrollment_id']))).mappings().one()
        assert row['token_digest'] == digest(b'enrollment',old['enrollment_token'])
        assert row['expires_at'] == old['expires_at'] and row['challenge_count'] == 1
        assert conn.execute(select(challenges.c.consumed_at).where(challenges.c.id == canonical(challenge.json()['challenge_id']))).scalar_one() is None


def test_expired_same_identity_renew_rotates_secret_and_completes(control, monkeypatch):
    client, engine, key, creation, old, root, request = registration_case(control)
    _, admin = login(client, control[2], control[3])
    old_challenge = client.post(root+'/challenge', json=request).json()
    eid = canonical(old['enrollment_id'])
    # Advance only protocol time: no direct expiry edits, no waiting 600 seconds.
    stamp = old['expires_at']
    monkeypatch.setattr('orangespace_control.enrollment.now', lambda: stamp)
    assert client.post(root+'/challenge', json=request).status_code == 410
    assert client.post('/control/v1/admin/node-enrollments', headers=admin, json=creation).status_code == 409
    with engine.connect() as conn:
        before = dict(conn.execute(select(enrollments).where(enrollments.c.id == eid)).mappings().one())
    route = '/control/v1/admin/node-enrollments/'+old['enrollment_id']+'/renew'
    payload = dict(schema=1, expected_expires_at=stamp, reason='administrator retry after expiry')
    renewed = client.post(route, headers=admin, json=payload)
    assert renewed.status_code == 200
    assert renewed.headers['cache-control'] == 'no-store'
    fresh = renewed.json()
    assert set(fresh) == {'schema','enrollment_id','node_id','enrollment_token','expires_at'}
    assert fresh['enrollment_id'] == old['enrollment_id'] and fresh['node_id'] == old['node_id']
    assert fresh['expires_at'] == stamp+600
    assert fresh['enrollment_token'] != old['enrollment_token']
    assert len(decode(fresh['enrollment_token'],32)) == 32
    assert client.post(root+'/challenge', json=request).status_code == 401
    assert client.post(root+'/complete', json=completion(key, creation, old, old_challenge)).status_code == 401
    with engine.connect() as conn:
        after = dict(conn.execute(select(enrollments).where(enrollments.c.id == eid)).mappings().one())
        for field in before.keys()-{'expires_at','token_digest','challenge_count'}:
            assert before[field] == after[field]
        assert after['challenge_count'] == 0
        assert after['token_digest'] == digest(b'enrollment', fresh['enrollment_token'])
        assert all(v is not None for v in conn.execute(select(challenges.c.consumed_at).where(challenges.c.enrollment_id == eid)).scalars())
        event = conn.execute(select(audit).where(audit.c.action == 'node.enrollment.renew', audit.c.object_id == canonical(old['node_id']))).mappings().one()
        assert event['before_revision'] is None and event['after_revision'] is None
        assert old['enrollment_token'] not in str(event) and fresh['enrollment_token'] not in str(event)
    assert client.post(root+'/complete', json=completion(key, creation, fresh, old_challenge)).status_code == 409
    challenge = client.post(root+'/challenge', json=dict(request,enrollment_token=fresh['enrollment_token']))
    assert challenge.status_code == 200
    response = client.post(root+'/complete', json=completion(key, creation, fresh, challenge.json()))
    assert response.status_code == 201
    with engine.connect() as conn:
        node = conn.execute(select(nodes).where(nodes.c.id == canonical(old['node_id']))).mappings().one()
        assert node['state'] == 'pending' and node['public_key'] == key.public_key().public_bytes_raw()
    monkeypatch.setattr('orangespace_control.enrollment.now', lambda: stamp+601)
    assert client.post(route, headers=admin, json=dict(payload,expected_expires_at=fresh['expires_at'])).status_code == 409
