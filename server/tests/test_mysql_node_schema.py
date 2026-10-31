"""Node migration gates; real MySQL coverage is in test_mysql.py."""
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


def test_initialize_checks_migration_not_create_all():
    import inspect
    from orangespace_node.database import Database
    source = inspect.getsource(Database.initialize)
    assert "create_all" not in source
    assert "verify_schema" in source
