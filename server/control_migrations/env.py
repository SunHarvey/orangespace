"""Control migration environment: protected config path or owned connection."""
from alembic import context
from orangespace_control.schema_v1 import metadata

cfg = context.config


def migrate(connection):
    if connection.dialect.name != 'mysql':
        raise RuntimeError('control migrations require MySQL')
    context.configure(connection=connection, target_metadata=metadata, version_table='control_alembic_version', compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    raise RuntimeError('control migrations require an actual MySQL connection')
connection = cfg.attributes.get('connection')
if connection is not None:
    migrate(connection)
else:
    from orangespace_control.config import load_config
    from orangespace_common.mysql import create_mysql_engine
    path = context.get_x_argument(as_dictionary=True).get('config')
    if not path:
        raise RuntimeError('supply -x config=/protected/control.json')
    engine = create_mysql_engine(load_config(path).database_url)
    try:
        with engine.connect() as conn:
            migrate(conn)
    finally:
        engine.dispose()
