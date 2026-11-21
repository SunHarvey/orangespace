"""Operator commands on the Centre host (real MySQL): same locks and audit as the console."""
import hashlib
from uuid import uuid4
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select
from test_control_auth import control, login
from test_control_enrollment import b64, completion
from orangespace_control import cli
from orangespace_control.schema_v1 import audit, mappings
from orangespace_control.security import ControlError, canonical


def test_operator_enrolls_activates_and_grants_a_node(control):
    client, engine, *_ = control
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw()
    node_id, alias = str(uuid4()), 'node_' + uuid4().hex[:12]
    fingerprint = hashlib.sha256(public).hexdigest()
    creation = dict(node_id=node_id, expected_key_fingerprint=fingerprint, api_origin='https://198.51.100.7:8443')
    enrollment = cli.enroll_node(engine, node_id, alias, 'Operator node', creation['api_origin'], '198.51.100.7', fingerprint)
    root = '/control/v1/node-enrollments/' + enrollment['enrollment_id']
    challenge = client.post(root + '/challenge', json=dict(schema=1, enrollment_token=enrollment['enrollment_token'], node_id=node_id, public_key=b64(public)))
    assert challenge.status_code == 200
    assert client.post(root + '/complete', json=completion(key, creation, enrollment, challenge.json())).status_code == 201
    assert [n['state'] for n in cli.list_nodes(engine) if n['alias'] == alias] == ['pending']
    assert cli.activate(engine, alias)['state'] == 'active'
    with pytest.raises(ControlError):
        cli.activate(engine, alias)  # only a pending node can be activated

    user = cli.create_user(engine, 'op_' + uuid4().hex[:12], 'operator-test-password', 'user')
    assert user['role'] == 'user'
    granted = cli.grant(engine, user['username'], alias, ['tunnel', 'files.read'], True)
    assert granted['grant_epoch'] == 1 and granted['scopes'] == ['tunnel', 'files.read']
    with engine.connect() as conn:
        mapping = conn.execute(select(mappings).where(mappings.c.node_id == canonical(node_id))).mappings().one()
        assert (mapping['state'], mapping['legacy_user_id']) == ('approved', canonical(user['central_user_id']))
        actions = set(conn.scalars(select(audit.c.action)))
    assert {'node.enrollment', 'node.activate', 'user.create', 'grant.put', 'mapping.provision'} <= actions
    # Re-granting changes the grant epoch but never re-provisions the identity.
    assert cli.grant(engine, user['username'], alias, ['tunnel'], False)['grant_epoch'] == 2
    with engine.connect() as conn:
        assert len(conn.execute(select(mappings.c.id).where(mappings.c.node_id == canonical(node_id))).all()) == 1
    with pytest.raises(ValueError):
        cli.grant(engine, user['username'], 'no-such-node', ['tunnel'], True)
    with pytest.raises(ControlError):
        cli.grant(engine, user['username'], alias, ['root'], True)
