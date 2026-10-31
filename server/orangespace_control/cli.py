"""Explicit migration/bootstrap entry point. Secrets never come from argv/env."""
import argparse
import getpass
import sys
from sqlalchemy import select, text
from .schema_v1 import users
from .security import PASSWORDS, authority_lock, record_audit, uid, now, username, user_dto


def check_migration(engine):
    with engine.connect() as conn:
        if conn.execute(text('SELECT version_num FROM control_alembic_version')).scalar_one() != 'control_0006':
            raise RuntimeError('control migration required')


def bootstrap_admin(engine, name, password):
    check_migration(engine)
    name = username(name)
    if not isinstance(password, str) or not 12 <= len(password) <= 1024:
        raise ValueError('invalid password')
    encoded = PASSWORDS.hash(password)
    with engine.begin() as conn:
        authority_lock(conn)
        if conn.execute(select(users.c.id).where(users.c.role == 'admin')).first():
            raise ValueError('administrator already bootstrapped')
        identity = uid()
        conn.execute(users.insert().values(id=identity, username=name, password_hash=encoded, role='admin', enabled=True, user_epoch=1, created_at=now()))
        record_audit(conn, identity, 'user.bootstrap', identity, None, 1, 'interactive bootstrap', uid())
        return user_dto(conn.execute(select(users).where(users.c.id == identity)).mappings().one())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    sub = parser.add_subparsers(dest='command', required=True)
    bootstrap = sub.add_parser('bootstrap-admin')
    bootstrap.add_argument('--username', required=True)
    sub.add_parser('serve')
    args = parser.parse_args()
    from .config import load_config
    from orangespace_common.database import create_mysql_engine
    config = load_config(args.config)
    engine = create_mysql_engine(config.database_url)
    try:
        if args.command == 'bootstrap-admin':
            password = getpass.getpass('Password: ') if sys.stdin.isatty() else sys.stdin.readline(1026).rstrip('\n')
            bootstrap_admin(engine, args.username, password)
            print('administrator bootstrapped')
        else:
            import uvicorn
            from .app import create_app
            uvicorn.run(create_app(config, engine=engine), host='127.0.0.1', port=8090, access_log=False)
    except Exception:
        print('control operation failed', file=sys.stderr)
        return 1
    finally:
        engine.dispose()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
