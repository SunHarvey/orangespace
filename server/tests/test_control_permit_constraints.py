"""Post-implementation real-MySQL constraint evidence; not forwarding evidence."""
from uuid import uuid4

import pytest
from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import IntegrityError

from test_control_auth import control
from test_control_permits import PERMIT, prepared
from orangespace_control.exchange_schema import federations
from orangespace_control.permit_schema import permits
from orangespace_control.security import canonical


def test_real_permit_unique_foreign_keys_and_restrict_preserve_history(control):
    client, engine, _, machine, body, _, _ = prepared(control)
    result = client.post(PERMIT, headers=machine, json=body)
    assert result.status_code == 200
    permit_id = canonical(result.json()['permit_id'])
    with engine.connect() as conn:
        original = dict(conn.execute(select(permits).where(permits.c.id == permit_id)).mappings().one())
        foreign_keys = set(conn.execute(text(
            'SELECT COLUMN_NAME, REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME '
            'FROM information_schema.KEY_COLUMN_USAGE '
            "WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='control_lease_permits' "
            'AND REFERENCED_TABLE_NAME IS NOT NULL'
        )).all())
        rules = conn.execute(text(
            'SELECT DELETE_RULE FROM information_schema.REFERENTIAL_CONSTRAINTS '
            "WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='control_lease_permits'"
        )).scalars().all()
        unique_columns = conn.execute(text(
            'SELECT COLUMN_NAME, NON_UNIQUE FROM information_schema.STATISTICS '
            "WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='control_lease_permits' "
            "AND INDEX_NAME='uq_permit_node_request' ORDER BY SEQ_IN_INDEX"
        )).all()
        federation_before = dict(conn.execute(select(federations).where(
            federations.c.id == original['federation_session_id']
        )).mappings().one())
    assert foreign_keys == {
        ('node_id', 'control_nodes', 'id'),
        ('federation_session_id', 'control_federation_sessions', 'id'),
    }
    assert rules == ['RESTRICT', 'RESTRICT']
    assert unique_columns == [('node_id', 0), ('request_id', 0)]

    # New PK avoids attributing a duplicate-PK failure to the scoped request key.
    with pytest.raises(IntegrityError) as duplicate:
        with engine.begin() as conn:
            conn.execute(permits.insert().values(**dict(original, id=uuid4().bytes)))
    assert duplicate.value.orig.args[0] == 1062
    assert 'uq_permit_node_request' in duplicate.value.orig.args[1]

    for field in ('node_id', 'federation_session_id'):
        invalid = dict(original, id=uuid4().bytes, request_id=uuid4().bytes)
        invalid[field] = uuid4().bytes
        with pytest.raises(IntegrityError) as missing_parent:
            with engine.begin() as conn:
                conn.execute(permits.insert().values(**invalid))
        assert missing_parent.value.orig.args[0] == 1452

    with pytest.raises(IntegrityError) as restricted:
        with engine.begin() as conn:
            conn.execute(delete(federations).where(
                federations.c.id == original['federation_session_id']
            ))
    assert restricted.value.orig.args[0] == 1451
    assert 'control_lease_permits' in restricted.value.orig.args[1]
    with engine.connect() as conn:
        assert conn.scalar(select(func.count()).select_from(permits)) == 1
        assert dict(conn.execute(select(permits).where(
            permits.c.id == permit_id
        )).mappings().one()) == original
        assert dict(conn.execute(select(federations).where(
            federations.c.id == original['federation_session_id']
        )).mappings().one()) == federation_before
