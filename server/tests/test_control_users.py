from test_control_auth import control, login


def make_user(client, auth):
    import uuid
    name = 'usr_' + uuid.uuid4().hex[:16]
    password = 'User-test-password-123'
    result = client.post('/control/v1/admin/users', headers=auth, json={'schema': 1, 'username': name, 'password': password, 'role': 'user'})
    assert result.status_code == 201
    return result.json()['user'], name, password


def test_disable_epoch_revocation_and_last_admin(control):
    client, engine, name, password, admin, _ = control
    _, auth = login(client, name, password)
    user, uname, upass = make_user(client, auth)
    _, old = login(client, uname, upass)
    path = '/control/v1/admin/users/' + user['central_user_id']
    payload = {'schema': 1, 'expected_user_epoch': 1, 'enabled': False, 'reason': 'disable test'}
    response = client.patch(path, headers=auth, json=payload)
    assert response.status_code == 200
    assert response.json()['user']['user_epoch'] == 2
    assert response.json()['revocation']['cleanup_state'] == 'pending'
    assert client.get('/control/v1/session', headers=old).status_code == 401
    assert client.patch(path, headers=auth, json=payload).status_code == 409
    payload.update(expected_user_epoch=2, enabled=True)
    assert client.patch(path, headers=auth, json=payload).status_code == 200
    assert client.get('/control/v1/session', headers=old).status_code == 401
    assert client.patch('/control/v1/admin/users/' + admin['central_user_id'], headers=auth, json={**payload, 'expected_user_epoch': 1, 'enabled': False}).status_code == 409
    _, ordinary = login(client, uname, upass)
    assert client.patch(path, headers=ordinary, json=payload).status_code == 403
    for bad in [True, 1.0, 1e0, 0]:
        assert client.patch(path, headers=auth, json={**payload, 'expected_user_epoch': bad}).status_code == 422
    assert client.patch(path, headers=auth, json={**payload, 'enabled': 1}).status_code == 422


def test_password_reset_invalidates_all_sessions(control):
    client, engine, name, password, _, _ = control
    _, auth = login(client, name, password)
    user, uname, upass = make_user(client, auth)
    _, first = login(client, uname, upass)
    _, second = login(client, uname, upass)
    path = '/control/v1/admin/users/' + user['central_user_id'] + '/reset-password'
    payload = {'schema': 1, 'expected_user_epoch': 1, 'password': 'Replacement-test-password-456', 'reason': 'reset test'}
    assert client.post(path, headers=first, json=payload).status_code == 403
    response = client.post(path, headers=auth, json=payload)
    assert response.status_code == 200
    assert response.json()['user']['user_epoch'] == 2
    assert response.json()['revocation']['cleanup_state'] == 'pending'
    assert 'password' not in response.text
    for old in [first, second]:
        assert client.get('/control/v1/session', headers=old).status_code == 401
    assert client.post('/control/v1/auth/login', json={'schema': 1, 'username': uname, 'password': upass}).status_code == 401
    login(client, uname, payload['password'])
    assert client.post(path, headers=auth, json=payload).status_code == 409
    from sqlalchemy import text
    with engine.connect() as conn:
        assert conn.execute(text("SELECT COUNT(*) FROM control_audit_events WHERE action='user.reset_password' AND object_id=UNHEX(REPLACE(:id,'-',''))"), {'id': user['central_user_id']}).scalar_one() == 1


def test_session_delete_ownership(control):
    client, _, name, password, _, _ = control
    admin_session, auth = login(client, name, password)
    user, uname, upass = make_user(client, auth)
    first, ordinary = login(client, uname, upass)
    second, another = login(client, uname, upass)
    foreign = '/control/v1/sessions/' + admin_session['central_session_id']
    assert client.delete(foreign, headers=ordinary).status_code == 404
    own = '/control/v1/sessions/' + first['central_session_id']
    response = client.delete(own, headers=ordinary)
    assert response.status_code == 202
    assert response.json()['cleanup_state'] == 'pending'
    assert response.json()['enforcement_deadline'] == response.json()['committed_at'] + 30
    assert client.get('/control/v1/session', headers=ordinary).status_code == 401
    assert client.get('/control/v1/session', headers=another).status_code == 200
    assert client.delete('/control/v1/sessions/' + second['central_session_id'], headers=auth).status_code == 202
    assert client.get('/control/v1/session', headers=another).status_code == 401


def test_session_listing_scoped_paginated(control):
    client, _, name, password, admin, _ = control
    _, auth = login(client, name, password)
    user, uname, upass = make_user(client, auth)
    login(client, uname, upass)
    _, ordinary = login(client, uname, upass)
    response = client.get('/control/v1/sessions?limit=1', headers=ordinary)
    assert response.status_code == 200
    assert len(response.json()['items']) == 1
    assert response.json()['next_cursor']
    assert response.json()['items'][0]['central_user_id'] == user['central_user_id']
    assert 'token' not in response.text
    assert client.get('/control/v1/sessions?central_user_id=' + admin['central_user_id'], headers=ordinary).status_code == 403
    assert client.get('/control/v1/sessions?limit=1&limit=2', headers=auth).status_code == 422
    filtered = client.get('/control/v1/sessions?central_user_id=' + user['central_user_id'], headers=auth)
    assert len(filtered.json()['items']) == 2


def test_create_list_rbac_strict(control):
    client, engine, name, password, admin, _ = control
    import uuid
    _, auth = login(client, name, password)
    username = 'usr_' + uuid.uuid4().hex[:16]
    body = {'schema': 1, 'username': username, 'password': 'User-only-test-password-123', 'role': 'user'}
    response = client.post('/control/v1/admin/users', headers=auth, json=body)
    assert response.status_code == 201
    assert 'password' not in response.text
    user_id = response.json()['user']['central_user_id']
    listing = client.get('/control/v1/admin/users', headers=auth)
    assert listing.status_code == 200
    assert user_id in [u['central_user_id'] for u in listing.json()['items']]
    _, user_auth = login(client, username, body['password'])
    assert client.get('/control/v1/admin/users', headers=user_auth).status_code == 403
    assert client.post('/control/v1/admin/users', headers=user_auth, json=body).status_code == 403
    assert client.post('/control/v1/admin/users', headers=auth, json=body).status_code == 409
    for raw in ['{"schema":1,"schema":1,"username":"aaa","password":"secret","role":"user"}', '{"schema":1.0,"username":"aaa","password":"secret","role":"user"}']:
        response = client.post('/control/v1/admin/users', headers={**auth, 'Content-Type': 'application/json'}, content=raw)
        assert response.status_code == 422
        assert response.headers['cache-control'] == 'no-store'
    assert client.get('/control/v1/admin/users?limit=1e1', headers=auth).status_code == 422
    from sqlalchemy import text
    with engine.connect() as conn:
        assert conn.execute(text("SELECT COUNT(*) FROM control_audit_events WHERE action='user.create' AND object_id=UNHEX(REPLACE(:id,'-',''))"), {'id': user_id}).scalar() == 1


def test_audit_is_admin_only_paginated_and_secret_free(control):
    client, _, name, password, _, _ = control
    _, auth = login(client, name, password)
    user, uname, upass = make_user(client, auth)
    _, ordinary = login(client, uname, upass)
    endpoint = '/control/v1/admin/audit-events'
    assert client.get(endpoint, headers=ordinary).status_code == 403
    response = client.get(endpoint + '?limit=1', headers=auth)
    assert response.status_code == 200
    data = response.json()
    assert len(data['items']) == 1
    assert data['next_cursor'] is not None
    assert set(data['items'][0]) == {'event_id', 'actor_kind', 'actor_id', 'action', 'object_kind', 'object_id', 'request_id', 'reason', 'created_at'}
    following = client.get(endpoint + '?limit=1&cursor=' + data['next_cursor'], headers=auth)
    assert following.status_code == 200
    assert following.json()['items'][0]['event_id'] != data['items'][0]['event_id']
    serialized = client.get(endpoint + '?limit=100', headers=auth).text
    for secret in (password, upass, auth['Authorization'][7:], ordinary['Authorization'][7:]):
        assert secret not in serialized
    assert client.get(endpoint + '?limit=1&limit=2', headers=auth).status_code == 422
