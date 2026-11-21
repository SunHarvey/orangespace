"""Centre-owned tunnel anti-replay (real MySQL, ASGI). Nodes remember nothing."""
from uuid import uuid4
from test_control_auth import control
from test_control_exchange import ISSUE, CONSUME
from test_control_permits import prepared, PERMIT


def permit(c, m, b, **change):
    return c.post(PERMIT, headers=m, json=dict(b, request_id=str(uuid4()), **change))


def test_tunnel_id_single_use_and_generation_only_rises(control):
    c, e, u, m, b, g, l = prepared(control)
    first = b['tunnel_id']
    assert c.post(PERMIT, headers=m, json=b).status_code == 200
    # Same tunnel again (a replay after a node restart) and a non-increasing generation.
    assert permit(c, m, b).status_code == 409
    assert permit(c, m, b, tunnel_id=str(uuid4())).status_code == 409
    assert permit(c, m, b, operation='renew').status_code == 200
    second = str(uuid4())
    assert permit(c, m, b, tunnel_id=second, generation=2).status_code == 200
    # The superseded tunnel can no longer renew; the current one can.
    assert permit(c, m, b, operation='renew').status_code == 410
    assert permit(c, m, b, tunnel_id=second, generation=2, operation='renew').status_code == 200
    # An old tunnel ID stays burned even with a higher generation.
    assert permit(c, m, b, tunnel_id=first, generation=3).status_code == 409
    # Another sandbox has its own generation sequence.
    assert permit(c, m, b, tunnel_id=str(uuid4()), sandbox_id=str(uuid4()), generation=1).status_code == 200


def test_renew_needs_the_create_from_the_same_federation_session(control):
    c, e, u, m, b, g, l = prepared(control)
    assert permit(c, m, b, operation='renew').status_code == 410
    assert c.post(PERMIT, headers=m, json=b).status_code == 200
    ticket = c.post(ISSUE, headers=u, json=dict(schema=1, node_id=granted_node(e, g), expected_epochs=b['expected_epochs'])).json()
    other = c.post(CONSUME, headers=m, json=dict(schema=1, exchange_id=ticket['exchange_id'],
                   exchange_token=ticket['exchange_token'], request_id=str(uuid4()))).json()['federation']
    assert permit(c, m, b, operation='renew', federation_session_id=other['federation_session_id']).status_code == 410
    assert permit(c, m, b, operation='renew').status_code == 200


def granted_node(engine, grant_id):
    from sqlalchemy import select
    from orangespace_control.schema_v1 import grants
    from orangespace_control.security import show
    with engine.connect() as conn:
        return show(conn.execute(select(grants.c.node_id).where(grants.c.id == grant_id)).scalar_one())
