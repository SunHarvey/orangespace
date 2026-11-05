"""Identity introspection is not permission to perform a file/tunnel action."""
import pytest
from orangespace_control.schema_v1 import grants
from test_control_auth import control
from test_control_federation_validation import issued, VALIDATE


@pytest.mark.parametrize('scopes', [['files.read'], ['tunnel'], ['files.write']])
def test_identity_only_scope_does_not_imply_work_authority(control, scopes):
    client, engine, user, machine, _, gid, _, _, _, original, request, _ = issued(control)
    # Fixture-only scope control; tests the live scope result, not a cached list.
    with engine.begin() as conn:
        conn.execute(grants.update().where(grants.c.id == gid).values(scopes=scopes))
    identity = dict(request, required_scope=None)
    accepted = client.post(VALIDATE, headers=machine, json=identity)
    assert accepted.status_code == 200
    assert accepted.json() == dict(schema=1, federation=original, scopes=scopes)
    forbidden = next(scope for scope in ['files.read', 'files.write', 'tunnel'] if scope not in scopes)
    assert client.post(VALIDATE, headers=machine, json=dict(request, required_scope=forbidden)).status_code == 403
    assert client.post(VALIDATE, headers=user, json=identity).status_code == 401
    for bad in [False, 0, 1.0, [], {}, '']:
        assert client.post(VALIDATE, headers=machine, json=dict(request, required_scope=bad)).status_code == 422
    missing = dict(identity)
    del missing['required_scope']
    assert client.post(VALIDATE, headers=machine, json=missing).status_code == 422
    with engine.begin() as conn:
        conn.execute(grants.update().where(grants.c.id == gid).values(enabled=False))
    assert client.post(VALIDATE, headers=machine, json=identity).status_code == 410
