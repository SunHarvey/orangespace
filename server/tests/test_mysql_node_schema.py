"""Node migration gates; real MySQL coverage is in test_mysql.py."""
import pytest
from sqlalchemy import BigInteger
from sqlalchemy.dialects.mysql import dialect
from sqlalchemy.schema import CreateTable

from orangespace_node.database import Base, User


def test_node_schema_uses_exact_strings_bigint_and_innodb():
    for table in Base.metadata.tables.values():
        ddl = str(CreateTable(table).compile(dialect=dialect()))
        assert "ENGINE=InnoDB" in ddl
        assert "utf8mb4_0900_bin" in ddl
    assert isinstance(User.__table__.c.created_at.type, BigInteger)


def test_mysql_state_is_never_created_on_initialize(mysql_config_path):
    """A node on MySQL only verifies migrations; an empty schema stays empty."""
    from sqlalchemy import inspect
    from orangespace_common.database import create_mysql_engine, load_database_url
    from orangespace_common.node_migrations import downgrade
    from orangespace_node.database import Database
    url = load_database_url(mysql_config_path)
    engine = create_mysql_engine(url)
    try:
        downgrade(engine)  # Only the fixture-owned schema.
        before = set(inspect(engine).get_table_names())
        assert before <= {"alembic_version"}
        db = Database(url)
        try:
            with pytest.raises(RuntimeError):
                db.initialize()
        finally:
            db.close()
        assert set(inspect(engine).get_table_names()) == before
    finally:
        engine.dispose()


def test_memory_state_creates_only_its_own_tables():
    from sqlalchemy import inspect
    from orangespace_node.database import MEMORY, Database
    from orangespace_node.federation import metadata
    db = Database(MEMORY)
    try:
        db.initialize()
        assert set(inspect(db.engine).get_table_names()) == set(Base.metadata.tables) | set(metadata.tables)
    finally:
        db.close()
