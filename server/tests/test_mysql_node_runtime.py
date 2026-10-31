"""MySQL node migration acceptance in an exactly owned temporary schema."""
from uuid import uuid4

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError


def test_compatibility_factory_is_the_same_object():
    from orangespace_common.database import create_mysql_engine
    from orangespace_common.mysql import create_mysql_engine as compatibility_factory
    assert compatibility_factory is create_mysql_engine


def test_real_node_upgrade_constraints_and_roundtrip(mysql_config_path):
    from orangespace_common.database import create_mysql_engine, load_database_url
    from orangespace_common.node_migrations import downgrade, upgrade as upgrade_node, verify_schema
    from orangespace_node.database import Base
    from orangespace_node.federation import bindings
    # The fixture creates this unique schema; never downgrade the supplied base DB.
    engine = create_mysql_engine(load_database_url(mysql_config_path))
    try:
        downgrade(engine, 'node_0001')
        uid = str(uuid4())
        insert = text("INSERT INTO users (id, username, password_hash, enabled, created_at) VALUES (:id, :name, 'unused-test-hash', 1, 1)")
        with engine.begin() as conn:
            for name in ('case', 'Case', 'cáse', 'case '):
                conn.execute(insert, {'id': str(uuid4()), 'name': name})
            conn.execute(insert, {'id': uid, 'name': 'owner'})
            conn.execute(text('INSERT INTO access_sessions (token_digest,user_id,expires_at) VALUES (:d,:u,9999999999)'), {'d': 'e'*64, 'u': uid})
            conn.execute(text('INSERT INTO tunnel_grants VALUES (:u,0,1)'), {'u': uid})
            conn.execute(text('INSERT INTO tunnel_generations VALUES (:u,:s,9)'), {'u': uid, 's': str(uuid4())})
            conn.execute(text('INSERT INTO tunnel_tombstones VALUES (:t,:u,:d,:s,9)'), {'t': str(uuid4()), 'u': uid, 'd': '0'*64, 's': str(uuid4())})
        tables = tuple(Base.metadata.tables)
        with engine.connect() as conn:
            before = {table: conn.execute(text('SELECT * FROM '+table+' ORDER BY 1')).all() for table in tables}
        upgrade_node(engine)
        verify_schema(engine)
        with engine.connect() as conn:
            assert {table: conn.execute(text('SELECT * FROM '+table+' ORDER BY 1')).all() for table in tables} == before
            assert conn.scalar(text('SELECT COUNT(*) FROM federation_bindings')) == 0
            assert conn.scalar(text('SELECT VERSION()')).startswith('8.4.')
            assert conn.scalar(text('SELECT @@transaction_isolation')) == 'READ-COMMITTED'
            rows = conn.execute(text("SELECT TABLE_NAME,ENGINE,TABLE_COLLATION FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME != 'alembic_version'")).all()
            assert {row[0] for row in rows} == set(Base.metadata.tables) | {bindings.name}
            assert all(row[1:] == ('InnoDB', 'utf8mb4_0900_bin') for row in rows)
            assert conn.scalar(text("SELECT PAD_ATTRIBUTE FROM information_schema.COLLATIONS WHERE COLLATION_NAME='utf8mb4_0900_bin'")) == 'NO PAD'
        with pytest.raises(IntegrityError):
            with engine.begin() as conn:
                conn.execute(insert, {'id': str(uuid4()), 'name': 'owner'})
        with pytest.raises(IntegrityError):
            with engine.begin() as conn:
                conn.execute(text('INSERT INTO tunnel_grants VALUES (:id,1,1)'), {'id': str(uuid4())})
        with engine.begin() as conn:
            conn.execute(text('DELETE FROM users WHERE id=:id'), {'id': uid})
            assert conn.scalar(text('SELECT COUNT(*) FROM tunnel_generations WHERE user_id=:id'), {'id': uid}) == 1
            assert conn.scalar(text('SELECT COUNT(*) FROM tunnel_tombstones WHERE user_id=:id'), {'id': uid}) == 1
        # Only this fixture-owned schema is destructively downgraded.
        downgrade(engine)
        assert set(inspect(engine).get_table_names()) <= {'alembic_version'}
        with pytest.raises(RuntimeError):
            verify_schema(engine)
        upgrade_node(engine)
        verify_schema(engine)
    finally:
        engine.dispose()
