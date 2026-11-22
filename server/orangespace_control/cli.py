"""Explicit migration/bootstrap/operator entry point. Secrets never come from argv/env.

Operator commands run on the Centre host as its service account (the trusted
administrator's shell); each one takes the same authority lock and writes the
same audit records as the matching console action, with no actor account.
"""
import argparse
import getpass
import json
import sys
from sqlalchemy import select, text
from .schema_v1 import users, nodes, grants
from .security import PASSWORDS, authority_lock, record_audit, uid, now, username, user_dto


def check_migration(engine):
    with engine.connect() as conn:
        if conn.execute(text('SELECT version_num FROM control_alembic_version')).scalar_one() != 'control_0008':
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


def _password():
    if not sys.stdin.isatty():
        return sys.stdin.readline(1026).rstrip('\n')
    first = getpass.getpass('Password: ')
    if getpass.getpass('Repeat password: ') != first:
        raise ValueError('passwords differ')
    return first


def create_user(engine, name, password, role):
    check_migration(engine)
    name = username(name)
    if role not in ('admin', 'user') or not isinstance(password, str) or not 12 <= len(password) <= 1024:
        raise ValueError('invalid user')
    encoded = PASSWORDS.hash(password)
    with engine.begin() as conn:
        authority_lock(conn)
        identity = uid()
        conn.execute(users.insert().values(id=identity, username=name, password_hash=encoded, role=role, enabled=True, user_epoch=1, created_at=now()))
        record_audit(conn, None, 'user.create', identity, None, 1, 'operator creation', uid())
        return user_dto(conn.execute(select(users).where(users.c.id == identity)).mappings().one())


def enroll_node(engine, node_id, alias, display_name, api_origin, tls_server_name, fingerprint):
    from .enrollment import create_enrollment
    check_migration(engine)
    with engine.begin() as conn:
        authority_lock(conn)
        return create_enrollment(conn, None, dict(node_id=node_id, alias=alias, display_name=display_name,
            api_origin=api_origin, tls_server_name=tls_server_name, expected_key_fingerprint=fingerprint,
            reason='operator enrollment'), uid())


def _node(conn, alias):
    row = conn.execute(select(nodes).where(nodes.c.alias == alias).with_for_update()).mappings().first()
    if row is None:
        raise ValueError('unknown node')
    return row


def activate(engine, alias):
    from .enrollment import activate_node
    check_migration(engine)
    with engine.begin() as conn:
        authority_lock(conn)
        node = _node(conn, alias)
        return activate_node(conn, None, node['id'], dict(expected_node_epoch=node['node_epoch'],
            expected_config_revision=node['config_revision'], reason='operator activation'), uid())


def grant(engine, name, alias, scopes, enabled):
    from .authorization import apply_grant, check_grant
    check_migration(engine)
    with engine.begin() as conn:
        authority_lock(conn)
        user = conn.execute(select(users).where(users.c.username == username(name)).with_for_update()).mappings().first()
        if user is None:
            raise ValueError('unknown user')
        node = _node(conn, alias)
        old = conn.execute(select(grants).where(grants.c.user_id == user['id'], grants.c.node_id == node['id']).with_for_update()).mappings().first()
        data = dict(expected_grant_epoch=old['grant_epoch'] if old else 0, enabled=enabled, scopes=scopes,
                    valid_until=None, reason='operator grant')
        check_grant(data)
        return apply_grant(conn, None, user['id'], node['id'], data, uid())


def list_nodes(engine):
    from .security import show
    check_migration(engine)
    with engine.connect() as conn:
        return [dict(node_id=show(r['id']), alias=r['alias'], state=r['state'], api_origin=r['api_origin'],
                     node_epoch=r['node_epoch'], config_revision=r['config_revision'])
                for r in conn.execute(select(nodes).order_by(nodes.c.alias)).mappings()]


def revoke_user_sessions(engine, name):
    """Sign a user out everywhere (a lost device): every live session and its
    refresh credential stop working; remembered sign-ins must sign in again."""
    from .security import revoke_sessions
    check_migration(engine)
    with engine.begin() as conn:
        authority_lock(conn)
        user = conn.execute(select(users).where(users.c.username == username(name)).with_for_update()).mappings().first()
        if user is None:
            raise ValueError('unknown user')
        receipt = revoke_sessions(conn, user['id'])
        record_audit(conn, None, 'user.revoke_sessions', user['id'], user['user_epoch'], user['user_epoch'],
                     'operator revocation', uid())
        return receipt


def parse_args(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    sub = parser.add_subparsers(dest='command', required=True)
    bootstrap = sub.add_parser('bootstrap-admin')
    bootstrap.add_argument('--username', required=True)
    user = sub.add_parser('create-user')
    user.add_argument('--username', required=True)
    user.add_argument('--role', choices=('user', 'admin'), default='user')
    enroll = sub.add_parser('enroll-node')
    for option in ('--node-id', '--alias', '--display-name', '--api-origin', '--tls-server-name', '--key-fingerprint'):
        enroll.add_argument(option, required=True)
    sub.add_parser('activate-node').add_argument('--alias', required=True)
    permit = sub.add_parser('grant')
    permit.add_argument('--username', required=True)
    permit.add_argument('--alias', required=True)
    permit.add_argument('--scopes', default='tunnel,files.read,files.write')
    permit.add_argument('--disable', action='store_true')
    sub.add_parser('list-nodes')
    sub.add_parser('revoke-sessions').add_argument('--username', required=True)
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
        elif args.command == 'create-user':
            print(json.dumps(create_user(engine, args.username, _password(), args.role)))
        elif args.command == 'enroll-node':
            # The one-time token goes to stdout only, for piping to the node.
            print(json.dumps(enroll_node(engine, args.node_id, args.alias, args.display_name,
                                         args.api_origin, args.tls_server_name, args.key_fingerprint)))
        elif args.command == 'activate-node':
            print(json.dumps(activate(engine, args.alias)))
        elif args.command == 'grant':
            scopes = [s for s in args.scopes.split(',') if s]
            print(json.dumps(grant(engine, args.username, args.alias, scopes, not args.disable)))
        elif args.command == 'revoke-sessions':
            print(json.dumps(revoke_user_sessions(engine, args.username)))
        elif args.command == 'list-nodes':
            print(json.dumps(list_nodes(engine), indent=1))
        else:
            import uvicorn
            from .app import create_app
            from .runtime import install_console
            app = create_app(config, engine=engine)
            install_console(app, args.dist)
            uvicorn.run(app, host=args.host, port=args.port, access_log=False,
                        ssl_certfile=args.ssl_certfile, ssl_keyfile=args.ssl_keyfile)
    except Exception as error:
        from .security import ControlError
        # Only fixed, secret-free reasons are shown.
        detail = error.code if isinstance(error, ControlError) else str(error) if isinstance(error, ValueError) and str(error) in (
            'administrator already bootstrapped', 'invalid password', 'passwords differ', 'invalid user',
            'unknown node', 'unknown user', 'invalid username') else None
        print('control operation failed' + (': ' + detail if detail else ''), file=sys.stderr)
        return 1
    finally:
        if engine is not None:
            engine.dispose()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
