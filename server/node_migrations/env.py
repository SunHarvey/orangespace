from alembic import context

from orangespace_common.database import create_mysql_engine, load_database_url

config = context.config
engine = config.attributes.get("engine")
owned = engine is None
if owned:
    path = config.get_main_option("database_config")
    if not path:
        raise RuntimeError("pass -x is not supported; set database_config to a protected file path")
    engine = create_mysql_engine(load_database_url(path))
try:
    if context.is_offline_mode():
        raise RuntimeError("node migrations require a verified MySQL connection")
    with engine.connect() as connection:
        context.configure(connection=connection, transactional_ddl=False)
        with context.begin_transaction():
            context.run_migrations()
finally:
    if owned:
        engine.dispose()
