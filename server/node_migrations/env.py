from alembic import context

from orangespace_common.database import load_database_url
from orangespace_node.local_store import create_node_engine

config = context.config
engine = config.attributes.get("engine")
owned = engine is None
if owned:
    path = config.get_main_option("database_config")
    if not path:
        raise RuntimeError("pass -x is not supported; set database_config to a protected file path")
    engine = create_node_engine(load_database_url(path))
try:
    if context.is_offline_mode():
        raise RuntimeError("node migrations require an online connection")
    with engine.connect() as connection:
        context.configure(connection=connection, transactional_ddl=engine.dialect.name == "sqlite")
        with context.begin_transaction():
            context.run_migrations()
finally:
    if owned:
        engine.dispose()
