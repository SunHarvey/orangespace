"""Explicit node schema operations; startup is strictly read-only."""
from importlib.resources import files

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

REVISION = "node_0002"


def migration_config(engine: Engine) -> Config:
    config = Config()
    config.set_main_option("script_location", str(files("node_migrations")))
    config.attributes["engine"] = engine
    return config


def upgrade(engine: Engine, revision: str = "head") -> None:
    command.upgrade(migration_config(engine), revision)


def downgrade(engine: Engine, revision: str = "base") -> None:
    command.downgrade(migration_config(engine), revision)


def verify_schema(engine: Engine) -> None:
    with engine.connect() as connection:
        if "alembic_version" not in inspect(connection).get_table_names():
            raise RuntimeError("node database requires explicit Alembic migration")
        revisions = connection.execute(text("SELECT version_num FROM alembic_version")).scalars().all()
        if revisions != [REVISION]:
            raise RuntimeError("node database Alembic revision mismatch")


def main() -> None:
    import argparse
    from orangespace_common.database import create_mysql_engine, load_database_url
    parser = argparse.ArgumentParser(description="Explicit node MySQL schema migration (DDL is not transactional)")
    parser.add_argument("action", choices=("upgrade", "downgrade", "verify"))
    parser.add_argument("--database-config", required=True, help="protected JSON path, never a DSN")
    parser.add_argument("--revision", help="Alembic target; default head for upgrade, base for downgrade")
    args = parser.parse_args()
    engine = None
    try:
        engine = create_mysql_engine(load_database_url(args.database_config))
        if args.action == "verify":
            verify_schema(engine)
        elif args.action == "upgrade":
            upgrade(engine, args.revision or "head")
        else:
            downgrade(engine, args.revision or "base")
    except Exception:
        parser.exit(1, "node database operation failed; inspect protected operator diagnostics\n")
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    main()
