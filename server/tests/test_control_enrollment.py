"""Local registration protocol on real isolated MySQL; not deployed-node acceptance."""
import base64
import hashlib
from uuid import uuid4
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_control_auth import control, login


def b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip('=')


def test_enroll_possession_pending_activate_and_domains(control):
    client, engine, name, password, _, _ = control
    _, admin = login(client, name, password)
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw()
    fingerprint = hashlib.sha256(public).hexdigest()
    nid = str(uuid4())
    create = dict(schema=1, node_id=nid, alias='node_'+uuid4().hex[:16], display_name='test', api_origin='https://node.example.test', tls_server_name='node.example.test', expected_key_fingerprint=fingerprint, reason='independent key verification')
    route = '/control/v1/admin/node-enrollments'
    assert client.post(route, json=create).status_code == 401
    response = client.post(route, json=create, headers=admin)
    assert response.status_code == 201
    enrollment = response.json()
    assert set(enrollment) == {'schema','enrollment_id','enrollment_token','node_id','expires_at'}
    root = '/control/v1/node-enrollments/' + enrollment['enrollment_id']
    challenge_input = dict(schema=1, enrollment_token=enrollment['enrollment_token'], node_id=nid, public_key=b64(public))
    wrong = dict(challenge_input, public_key=b64(Ed25519PrivateKey.generate().public_key().public_bytes_raw()))
    assert client.post(root+'/challenge', json=wrong).status_code == 401
    challenge = client.post(root+'/challenge', json=challenge_input)
    assert challenge.status_code == 200
    challenge = challenge.json()
    assert set(challenge) == {'schema','challenge_id','nonce','expires_at'}
    values = [enrollment['enrollment_id'],nid,fingerprint,create['api_origin'],challenge['challenge_id'],challenge['nonce'],str(challenge['expires_at'])]
    message = b'OrangeSpace-enroll-v1\n' + b''.join(str(len(v.encode())).encode()+b':'+v.encode() for v in values)
    complete = dict(schema=1,enrollment_token=enrollment['enrollment_token'],challenge_id=challenge['challenge_id'],signature=b64(key.sign(message)))
    assert client.post(root+'/complete', json=dict(complete,signature=b64(Ed25519PrivateKey.generate().sign(message)))).status_code == 401
    response = client.post(root+'/complete', json=complete)
    assert response.status_code == 201
    machine = response.json()
    assert set(machine) == {'schema','node_id','node_epoch','node_access_token','config_revision'}
    assert client.post(root+'/complete', json=complete).status_code == 409
    assert client.get('/control/v1/admin/nodes',headers=admin).json()['items'][0]['state'] == 'pending'
    bearer = {'Authorization':'Bearer '+machine['node_access_token']}
    assert client.get('/control/v1/session',headers=bearer).status_code == 401
    heartbeat = dict(schema=1,node_id=nid,node_epoch=1,config_revision=1,request_id=str(uuid4()),observed_at=1)
    assert client.post('/control/v1/internal/heartbeat',json=heartbeat,headers=admin).status_code == 401
    assert client.post('/control/v1/internal/heartbeat',json=heartbeat,headers=bearer).status_code == 401
    activate = dict(schema=1,expected_node_epoch=1,expected_config_revision=1,reason='verified deployment independently')
    response = client.post('/control/v1/admin/nodes/'+nid+'/activate',json=activate,headers=admin)
    assert response.status_code == 200
    assert client.post('/control/v1/internal/heartbeat',json=heartbeat,headers=bearer).status_code == 200
    assert client.post('/control/v1/internal/heartbeat',json=dict(heartbeat,node_id=str(uuid4())),headers=bearer).status_code == 401
    assert client.post('/control/v1/admin/nodes/'+nid+'/activate',json=activate,headers=admin).status_code == 409


def registration_case(control, node_id=None):
    client, engine, name, password, _, _ = control
    _, admin = login(client, name, password)
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw()
    creation = dict(schema=1, node_id=str(uuid4()) if node_id is None else node_id, alias='node_'+uuid4().hex[:16],
        display_name='challenge fencing', api_origin='https://node.example.test',
        tls_server_name='node.example.test', expected_key_fingerprint=hashlib.sha256(public).hexdigest(), reason='test approved key')
    response = client.post('/control/v1/admin/node-enrollments', headers=admin, json=creation)
    assert response.status_code == 201
    enrollment = response.json()
    root = '/control/v1/node-enrollments/' + enrollment['enrollment_id']
    request = dict(schema=1, enrollment_token=enrollment['enrollment_token'], node_id=creation['node_id'], public_key=b64(public))
    return client, engine, key, creation, enrollment, root, request


def completion(key, creation, enrollment, challenge):
    values = [enrollment['enrollment_id'], creation['node_id'], creation['expected_key_fingerprint'],
              creation['api_origin'], challenge['challenge_id'], challenge['nonce'], str(challenge['expires_at'])]
    message = b'OrangeSpace-enroll-v1\n' + b''.join(str(len(v.encode())).encode()+b':'+v.encode() for v in values)
    return dict(schema=1, enrollment_token=enrollment['enrollment_token'], challenge_id=challenge['challenge_id'], signature=b64(key.sign(message)))


def test_new_challenge_invalidates_previous_proof(control):
    client, _, key, creation, enrollment, root, request = registration_case(control)
    old = client.post(root+'/challenge', json=request)
    assert old.status_code == 200
    fresh = client.post(root+'/challenge', json=request)
    assert fresh.status_code == 200
    stale_payload = completion(key, creation, enrollment, old.json())
    assert client.post(root+'/complete', json=stale_payload).status_code == 409
    fresh_payload = completion(key, creation, enrollment, fresh.json())
    assert client.post(root+'/complete', json=fresh_payload).status_code == 201
    assert client.post(root+'/complete', json=fresh_payload).status_code == 409


def test_concurrent_completion_consumes_once_on_real_mysql(control):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from dataclasses import replace
    from fastapi.testclient import TestClient
    from orangespace_control.app import create_app
    from orangespace_control.config import load_config
    client, engine, key, creation, enrollment, root, request = registration_case(control)
    challenge = client.post(root+'/challenge', json=request)
    assert challenge.status_code == 200
    payload = completion(key, creation, enrollment, challenge.json())
    config = replace(load_config(control[-1]), database_url=engine.url.render_as_string(hide_password=False))
    # Separate ASGI portals ensure this is database arbitration rather than one
    # event loop serializing both synchronous SQL transactions.
    barrier = Barrier(2)
    def consume(_):
        with TestClient(create_app(config, engine=engine), raise_server_exceptions=False) as peer:
            barrier.wait(timeout=10)
            return peer.post(root+'/complete', json=payload).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = sorted(pool.map(consume, range(2)))
    assert statuses == [201, 409]


def test_expired_enrollment_and_challenge_records_deny_without_creating_node(control):
    from sqlalchemy import select
    from orangespace_control.enrollment_schema import enrollments, challenges
    from orangespace_control.schema_v1 import nodes
    from orangespace_control.security import canonical, now
    client, engine, key, creation, enrollment, root, request = registration_case(control)
    challenge = client.post(root+'/challenge', json=request)
    assert challenge.status_code == 200
    payload = completion(key, creation, enrollment, challenge.json())
    with engine.begin() as conn:
        conn.execute(challenges.update().where(challenges.c.id == canonical(challenge.json()['challenge_id'])).values(expires_at=now()-1))
    assert client.post(root+'/complete', json=payload).status_code == 410
    with engine.begin() as conn:
        conn.execute(enrollments.update().where(enrollments.c.id == canonical(enrollment['enrollment_id'])).values(expires_at=now()-1))
    assert client.post(root+'/challenge', json=request).status_code == 410
    with engine.connect() as conn:
        assert conn.execute(select(nodes.c.id).where(nodes.c.id == canonical(creation['node_id']))).first() is None
