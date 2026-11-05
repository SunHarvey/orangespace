"""Real MySQL restricts session deletion without discarding replay history."""
from uuid import uuid4

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.exc import IntegrityError

from orangespace_common.database import create_mysql_engine, load_database_url
from orangespace_node.database import AccessSession, User
from orangespace_node.federation import bindings


def test_bound_session_delete_rejected_preserves_exchange(mysql_config_path):
    engine = create_mysql_engine(load_database_url(mysql_config_path))
    uid, exchange = str(uuid4()), str(uuid4())
    digest = 'a' * 64
    federation = {'federation_session_id': str(uuid4()), 'expires_at': 9007199254740991}
    try:
        with engine.begin() as conn:
            conn.execute(User.__table__.insert().values(id=uid, username='fk-owner', password_hash='unused', enabled=True, created_at=1))
            conn.execute(AccessSession.__table__.insert().values(token_digest=digest, user_id=uid, expires_at=9007199254740991))
            conn.execute(bindings.insert().values(exchange_id=exchange, token_digest=digest, cleanup_digest='b'*64, federation=federation))
        with pytest.raises(IntegrityError):
            with engine.begin() as conn:
                conn.execute(delete(AccessSession).where(AccessSession.token_digest == digest))
        with engine.connect() as conn:
            row = conn.execute(select(bindings).where(bindings.c.exchange_id == exchange)).mappings().one()
            assert row['token_digest'] == digest
            assert row['cleanup_digest'] == 'b'*64
            assert row['federation'] == federation
            assert conn.scalar(select(AccessSession.token_digest).where(AccessSession.token_digest == digest)) == digest
            assert conn.scalar(text("SELECT DELETE_RULE FROM information_schema.REFERENTIAL_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='federation_bindings'")) == 'RESTRICT'
    finally:
        engine.dispose()
