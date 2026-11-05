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


def parse_args(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    sub = parser.add_subparsers(dest='command', required=True)
    bootstrap = sub.add_parser('bootstrap-admin')
    bootstrap.add_argument('--username', required=True)
    serve = sub.add_parser('serve')
    serve.add_argument('--host', default='127.0.0.1')
    serve.add_argument('--port', type=int, default=8090)
    serve.add_argument('--dist', help='public console build directory, never a configuration directory')
    serve.add_argument('--ssl-certfile')
    serve.add_argument('--ssl-keyfile')
    args = parser.parse_args(argv)
    if args.command == 'serve':
        if not 1 <= args.port <= 65535:
            parser.error('port must be between 1 and 65535')
        if bool(args.ssl_certfile) != bool(args.ssl_keyfile):
            parser.error('TLS certificate and key must be provided together')
    return args


def main():
    args = parse_args()
    engine = None
    try:
        from .config import load_config
        from orangespace_common.database import create_mysql_engine
        config = load_config(args.config)
        engine = create_mysql_engine(config.database_url)
        if args.command == 'bootstrap-admin':
            password = getpass.getpass('Password: ') if sys.stdin.isatty() else sys.stdin.readline(1026).rstrip('\n')
            bootstrap_admin(engine, args.username, password)
            print('administrator bootstrapped')
        else:
            import uvicorn
            from .app import create_app
            from .runtime import install_console
            app = create_app(config, engine=engine)
            install_console(app, args.dist)
            uvicorn.run(app, host=args.host, port=args.port, access_log=False,
                        ssl_certfile=args.ssl_certfile, ssl_keyfile=args.ssl_keyfile)
    except Exception:
        print('control operation failed', file=sys.stderr)
        return 1
    finally:
        if engine is not None:
            engine.dispose()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
