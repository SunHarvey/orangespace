"""Real MySQL: renewable central sessions and rotating refresh credentials."""
import secrets
import uuid
from sqlalchemy import select, update
from test_control_auth import control, login
from orangespace_control.schema_v1 import nodes, mappings, grants, sessions, audit, rates
from orangespace_control.refresh_schema import refresh_tokens
from orangespace_control.security import uid, canonical, now
from orangespace_control.enrollment import digest

LOGIN = '/control/v1/auth/login'
REFRESH = '/control/v1/auth/refresh'
EPOCHS = dict(user_epoch=1, node_epoch=1, mapping_epoch=1, grant_epoch=1)


def renewable(control):
    client, engine, name, password, *_ = control
    with engine.begin() as c:
        c.execute(rates.delete())
    r = client.post(LOGIN, json={'schema': 1, 'username': name, 'password': password, 'renewable': True})
    assert r.status_code == 200, r.text
    data = r.json()
    assert set(data) == {'schema', 'access_token', 'token_type', 'central_session_id', 'expires_at', 'user', 'nodes',
                         'nodes_next_cursor', 'session_deadline', 'refresh_token', 'refresh_expires_at'}
    assert len(data['refresh_token']) == 43 and data['refresh_token'] != data['access_token']
    assert data['expires_at'] < data['refresh_expires_at'] <= data['session_deadline']
    return data


def refresh(client, token):
    return client.post(REFRESH, json={'schema': 1, 'refresh_token': token})


def bearer(token):
    return {'Authorization': 'Bearer ' + token}


def alive(client, token):
    return client.get('/control/v1/session', headers=bearer(token)).status_code == 200


def rotated(client, token):
    r = refresh(client, token)
    assert r.status_code == 200, r.text
    assert r.headers['cache-control'] == 'no-store'
    data = r.json()
    assert set(data) == {'schema', 'access_token', 'token_type', 'central_session_id', 'expires_at', 'session_deadline',
                         'user', 'refresh_token', 'refresh_expires_at'}
    return data


def test_refresh_rotates_both_credentials_once(control):
    client, engine, *_ = control
    first = renewable(control)
    second = rotated(client, first['refresh_token'])
    assert second['central_session_id'] == first['central_session_id']
    assert second['session_deadline'] == first['session_deadline']
    assert second['access_token'] != first['access_token'] and second['refresh_token'] != first['refresh_token']
    assert not alive(client, first['access_token']) and alive(client, second['access_token'])
    with engine.connect() as c:
        stored = c.execute(select(refresh_tokens.c.token_digest)).scalars().all()
    assert all(len(value) == 32 for value in stored)
    assert second['refresh_token'].encode() not in stored

    # The response was lost: the same credential once more inside the grace
    # window gives a new pair and retires the undelivered one.
    third = rotated(client, first['refresh_token'])
    assert not alive(client, second['access_token']) and alive(client, third['access_token'])

    # Someone held the retired credential after all: the session ends.
    assert refresh(client, second['refresh_token']).status_code == 401
    assert not alive(client, third['access_token'])
    assert refresh(client, third['refresh_token']).status_code == 401
    with engine.connect() as c:
        actions = c.execute(select(audit.c.action).where(audit.c.object_id == canonical(first['central_session_id']))).scalars().all()
    assert 'session.refresh_reuse' in actions


def test_reuse_after_grace_revokes_session(control):
    client, engine, *_ = control
    first = renewable(control)
    second = rotated(client, first['refresh_token'])
    with engine.begin() as c:
        c.execute(update(refresh_tokens).where(refresh_tokens.c.session_id == canonical(first['central_session_id']),
                                               refresh_tokens.c.used_at.is_not(None)).values(used_at=now() - 120))
    assert refresh(client, first['refresh_token']).status_code == 401
    assert not alive(client, second['access_token'])
    assert refresh(client, second['refresh_token']).status_code == 401


def test_refresh_brings_back_an_expired_session_until_its_deadline(control):
    client, engine, *_ = control
    first = renewable(control)
    sid = canonical(first['central_session_id'])
    with engine.begin() as c:
        c.execute(update(sessions).where(sessions.c.id == sid).values(expires_at=now() - 1))
    assert not alive(client, first['access_token'])
    second = rotated(client, first['refresh_token'])
    assert alive(client, second['access_token'])
    assert now() < second['expires_at'] <= second['session_deadline']

    with engine.begin() as c:
        c.execute(update(refresh_tokens).where(refresh_tokens.c.session_id == sid).values(expires_at=now() - 1, deadline=now() - 1))
    assert refresh(client, second['refresh_token']).status_code == 401


def test_logout_and_bad_input_stop_refresh(control):
    client, engine, *_ = control
    first = renewable(control)
    r = client.delete('/control/v1/sessions/' + first['central_session_id'], headers=bearer(first['access_token']))
    assert r.status_code == 202, r.text
    assert refresh(client, first['refresh_token']).status_code == 401
    assert refresh(client, secrets.token_urlsafe(32)).status_code == 401
    assert refresh(client, 'short').status_code == 422
    assert client.post(REFRESH, json={'schema': 1, 'refresh_token': first['refresh_token'], 'extra': 1}).status_code == 422
    _, _, name, password, *_ = control
    with engine.begin() as c:
        c.execute(rates.delete())
    assert client.post(LOGIN, json={'schema': 1, 'username': name, 'password': password, 'renewable': 'yes'}).status_code == 422
    # Without the opt-in the login response is unchanged and nothing can renew it.
    plain, _ = login(client, name, password)
    with engine.connect() as c:
        assert c.execute(select(refresh_tokens).where(refresh_tokens.c.session_id == canonical(plain['central_session_id']))).first() is None


def seed_node(control):
    _, engine, _, _, admin, _ = control
    nid, machine = uid(), secrets.token_urlsafe(32)
    user = canonical(admin['central_user_id'])
    with engine.begin() as c:
        c.execute(nodes.insert().values(id=nid, alias=uuid.uuid4().hex, display_name='fixture', api_origin='https://fixture.test',
                                        tls_server_name='fixture.test', public_key=b'p' * 32, key_fingerprint=b'k' * 32,
                                        machine_token_digest=digest(b'node-machine', machine), state='active', node_epoch=1, config_revision=1))
        c.execute(mappings.insert().values(id=uid(), node_id=nid, legacy_user_id=uid(), central_user_id=user, state='approved',
                                           mapping_epoch=1, evidence_digest=b'e' * 32, reason='explicit approved mapping fixture'))
        c.execute(grants.insert().values(id=uid(), user_id=user, node_id=nid, enabled=True, grant_epoch=1, scopes=['files.read'], valid_until=None))
    return str(uuid.UUID(bytes=nid)), bearer(machine)


def federate(client, access, node_id, machine):
    r = client.post('/control/v1/node-exchanges', headers=bearer(access), json=dict(schema=1, node_id=node_id, expected_epochs=EPOCHS))
    assert r.status_code == 201, r.text
    ticket = r.json()
    r = client.post('/control/v1/internal/node-exchanges/consume', headers=machine,
                    json=dict(schema=1, exchange_id=ticket['exchange_id'], exchange_token=ticket['exchange_token'], request_id=str(uuid.uuid4())))
    assert r.status_code == 200, r.text
    return r.json()['federation']


def validate(client, machine, federation):
    return client.post('/control/v1/internal/federation-sessions/validate', headers=machine,
                       json=dict(schema=1, federation_session_id=federation['federation_session_id'], expected_epochs=EPOCHS, required_scope='files.read'))


def test_node_federation_follows_the_renewed_session(control):
    client, engine, name, password, *_ = control
    node_id, machine = seed_node(control)
    with engine.begin() as c:
        c.execute(rates.delete())
    plain, _ = login(client, name, password)
    assert federate(client, plain['access_token'], node_id, machine)['expires_at'] == plain['expires_at']

    first = renewable(control)
    federation = federate(client, first['access_token'], node_id, machine)
    assert federation['expires_at'] == first['session_deadline']
    assert validate(client, machine, federation).status_code == 200

    # The node identity is only as live as the central session behind it.
    with engine.begin() as c:
        c.execute(update(sessions).where(sessions.c.id == canonical(first['central_session_id'])).values(expires_at=now() - 1))
    assert validate(client, machine, federation).status_code == 410
    second = rotated(client, first['refresh_token'])
    assert validate(client, machine, federation).status_code == 200
    client.delete('/control/v1/sessions/' + first['central_session_id'], headers=bearer(second['access_token']))
    assert validate(client, machine, federation).status_code == 410


def test_operator_revokes_every_session_of_a_user(control):
    from orangespace_control.cli import revoke_user_sessions
    client, engine, name, *_ = control
    first, second = renewable(control), renewable(control)
    receipt = revoke_user_sessions(engine, name)
    assert receipt['cleanup_state'] == 'pending'
    # Both sessions end, and neither refresh credential (a remembered sign-in)
    # brings one back.
    for data in (first, second):
        assert not alive(client, data['access_token'])
        assert refresh(client, data['refresh_token']).status_code == 401
    with engine.connect() as c:
        user_id = c.execute(select(sessions.c.user_id).where(sessions.c.id == canonical(first['central_session_id']))).scalar_one()
        actions = c.execute(select(audit.c.action).where(audit.c.object_id == user_id)).scalars().all()
    assert 'user.revoke_sessions' in actions
    # A new password sign-in works again.
    assert alive(client, renewable(control)['access_token'])
    try:
        revoke_user_sessions(engine, 'no-such-user')
    except ValueError as error:
        assert str(error) == 'unknown user'
    else:
        raise AssertionError('unknown user accepted')
