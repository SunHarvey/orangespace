"""Real MySQL checks for durable exchange request and relational identity."""
from uuid import uuid4

from sqlalchemy import inspect
from test_control_auth import control
from test_control_exchange import setup, ISSUE, CONSUME


def test_machine_request_id_cannot_be_retargeted_to_another_exchange(control):
    client, _, user, machine, payload, _, _, _ = setup(control)
    first = client.post(ISSUE, headers=user, json=payload)
    second = client.post(ISSUE, headers=user, json=payload)
    assert first.status_code == 201 and second.status_code == 201
    rid = str(uuid4())
    def consume(ticket):
        data = ticket.json()
        return client.post(CONSUME, headers=machine, json=dict(
            schema=1, exchange_id=data['exchange_id'],
            exchange_token=data['exchange_token'], request_id=rid))
    original = consume(first)
    assert original.status_code == 200
    assert consume(second).status_code == 409
    assert consume(first).json() == original.json()
    assert original.json()['federation']['expires_at'] > first.json()['expires_at']


def test_two_portals_cannot_retarget_machine_request(control):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from fastapi.testclient import TestClient
    from sqlalchemy import select, func
    from orangespace_control.exchange_schema import exchanges, federations
    from orangespace_control.security import canonical
    client, engine, user, machine, payload, *_ = setup(control)
    tickets = [client.post(ISSUE, headers=user, json=payload).json() for _ in range(2)]
    rid = str(uuid4())
    barrier = Barrier(2)
    requests = [dict(schema=1, exchange_id=t['exchange_id'],
                     exchange_token=t['exchange_token'], request_id=rid) for t in tickets]
    def consume(data):
        with TestClient(client.app, raise_server_exceptions=False) as portal:
            barrier.wait(timeout=10)
            return portal.post(CONSUME, headers=machine, json=data)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(consume, requests))
    assert sorted(r.status_code for r in results) == [200, 409]
    winner = next(i for i, r in enumerate(results) if r.status_code == 200)
    original = results[winner].json()
    assert original['federation']['expires_at'] > tickets[winner]['expires_at']
    assert client.post(CONSUME, headers=machine, json=requests[winner]).json() == original
    with engine.connect() as conn:
        ids = [canonical(t['exchange_id']) for t in tickets]
        assert conn.scalar(select(func.count()).select_from(federations).where(federations.c.exchange_id.in_(ids))) == 1
        assert conn.scalar(select(func.count()).select_from(exchanges).where(exchanges.c.id.in_(ids), exchanges.c.request_id == canonical(rid))) == 1


def test_request_binding_has_real_mysql_unique_constraint(control):
    import pytest
    from sqlalchemy import select
    from sqlalchemy.exc import IntegrityError
    from orangespace_control.exchange_schema import exchanges
    from orangespace_control.security import canonical
    client, engine, user, _, payload, *_ = setup(control)
    tickets = [client.post(ISSUE, headers=user, json=payload) for _ in range(2)]
    assert all(t.status_code == 201 for t in tickets)  # Multiple NULL request IDs.
    ids = [canonical(t.json()['exchange_id']) for t in tickets]
    rid = uuid4().bytes
    with engine.begin() as conn:
        conn.execute(exchanges.update().where(exchanges.c.id == ids[0]).values(request_id=rid))
    with pytest.raises(IntegrityError):
        with engine.begin() as conn:
            conn.execute(exchanges.update().where(exchanges.c.id == ids[1]).values(request_id=rid))
    expected = ('node_id', 'request_id')
    assert expected in {tuple(k['column_names']) for k in inspect(engine).get_unique_constraints(exchanges.name)}
    assert expected in {tuple(c.columns.keys()) for c in exchanges.constraints if c.__class__.__name__ == 'UniqueConstraint'}


def test_exchange_relations_have_actual_mysql_foreign_keys(control):
    _, engine, *_ = control
    inspector = inspect(engine)
    required = {
        'control_node_exchanges': {
            'central_session_id': 'control_sessions',
            'central_user_id': 'control_users',
            'node_id': 'control_nodes',
            'mapping_id': 'control_identity_mappings',
            'grant_id': 'control_grants',
        },
        'control_federation_sessions': {'exchange_id': 'control_node_exchanges'},
    }
    for table, relations in required.items():
        keys = inspector.get_foreign_keys(table)
        actual = {tuple(k['constrained_columns']): k['referred_table'] for k in keys}
        assert all(actual.get((column,)) == target for column, target in relations.items())
        assert all(k.get('options', {}).get('ondelete', 'RESTRICT').upper() not in ('CASCADE', 'SET NULL') for k in keys)
