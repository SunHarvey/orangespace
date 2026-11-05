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
        if engine.dialect.name == "sqlite":
            schema = inspect(connection)
            expected = {"users", "access_sessions", "tunnel_grants", "tunnel_generations",
                        "tunnel_tombstones", "federation_bindings", "alembic_version"}
            if set(schema.get_table_names()) != expected:
                raise RuntimeError("node local schema table mismatch")
            primary_keys = {
                "users": ["id"], "access_sessions": ["token_digest"],
                "tunnel_grants": ["user_id"], "tunnel_generations": ["user_id", "sandbox_id"],
                "tunnel_tombstones": ["tunnel_id"], "federation_bindings": ["exchange_id"],
            }
            for table, columns in primary_keys.items():
                if schema.get_pk_constraint(table)["constrained_columns"] != columns:
                    raise RuntimeError("node local schema primary key mismatch")
            foreign_keys = {
                "access_sessions": ("user_id", "users", "id", "CASCADE"),
                "tunnel_grants": ("user_id", "users", "id", "CASCADE"),
                "federation_bindings": ("token_digest", "access_sessions", "token_digest", "RESTRICT"),
            }
            for table, (column, target, target_column, deletion) in foreign_keys.items():
                keys = schema.get_foreign_keys(table)
                if not any(k["constrained_columns"] == [column] and k["referred_table"] == target
                           and k["referred_columns"] == [target_column]
                           and k["options"].get("ondelete") == deletion for k in keys):
                    raise RuntimeError("node local schema foreign key mismatch")
            for table in ("tunnel_generations", "tunnel_tombstones"):
                if schema.get_foreign_keys(table):
                    raise RuntimeError("node local schema replay history must be independent")
            for table, columns in (("users", ["username"]), ("federation_bindings", ["token_digest"])):
                if not any(k["column_names"] == columns for k in schema.get_unique_constraints(table)):
                    raise RuntimeError("node local schema unique constraint mismatch")
            if connection.exec_driver_sql("PRAGMA quick_check").scalar() != "ok":
                raise RuntimeError("node local schema integrity failure")
            if connection.exec_driver_sql("PRAGMA foreign_key_check").first() is not None:
                raise RuntimeError("node local schema foreign key violation")


def main() -> None:
    import argparse
    from orangespace_common.database import load_database_url
    from orangespace_node.local_store import create_node_engine
    parser = argparse.ArgumentParser(description="Explicit Node schema migration")
    parser.add_argument("action", choices=("upgrade", "downgrade", "verify"))
    parser.add_argument("--database-config", required=True, help="protected JSON path, never a DSN")
    parser.add_argument("--revision", help="Alembic target; default head for upgrade, base for downgrade")
    args = parser.parse_args()
    engine = None
    try:
        engine = create_node_engine(load_database_url(args.database_config), provision=args.action == "upgrade")
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
