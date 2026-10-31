"""Narrow control HTTP tracer bullet backed only by migrated MySQL."""
import json
import re
import secrets
from fastapi import FastAPI, Request
from starlette.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from .config import unique_object
from .schema_v1 import users, sessions
from .security import (ControlError, PASSWORDS, DUMMY_HASH, verify, now, uid, show,
                       canonical, username, user_dto, token_digest, authenticate,
                       authority_lock, throttle, eligible_nodes, record_audit)
from .cli import check_migration


def create_app(config, engine=None):
    if engine is None:
        from orangespace_common.database import create_mysql_engine
        engine = create_mysql_engine(config.database_url)
    check_migration(engine)  # Never perform DDL or create_all on startup.
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.engine = engine

    @app.middleware('http')
    async def boundary(request, call_next):
        request.state.request_id = uid()
        try:
            response = await call_next(request)
        except ControlError as exc:
            response = error(request, exc.status, exc.code)
        except IntegrityError:
            response = error(request, 409, 'conflict')
        except SQLAlchemyError:
            response = error(request, 503, 'dependency_failed')
        except Exception:
            response = error(request, 503, 'dependency_failed')
        response.headers['Cache-Control'] = 'no-store'
        return response

    def error(request, status, code):
        return JSONResponse({'schema': 1, 'error': {'code': code, 'request_id': show(request.state.request_id)}}, status_code=status)

    @app.exception_handler(404)
    @app.exception_handler(405)
    async def not_found(request, exc):
        return error(request, exc.status_code, 'not_found')

    async def body(request, fields):
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > 16384:
                raise ControlError(422, 'invalid_input')
        try:
            value = json.loads(raw, object_pairs_hook=unique_object, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            if not isinstance(value, dict) or set(value) != {'schema', *fields}:
                raise ValueError()
            if type(value['schema']) is not int:
                raise ValueError()
            if value['schema'] != 1:
                raise ControlError(426, 'unsupported_schema')
            return value
        except (ValueError, TypeError, UnicodeError):
            raise ControlError(422, 'invalid_input') from None

    def credentials(value):
        try:
            name = username(value['username'])
            password = value['password']
            if not isinstance(password, str) or not 12 <= len(password) <= 1024:
                raise ValueError()
            return name, password
        except ValueError:
            raise ControlError(422, 'invalid_input') from None

    def auth(conn, request, admin=False):
        authority_lock(conn)
        user, session = authenticate(conn, request.headers.get('authorization'))
        if admin and user['role'] != 'admin':
            raise ControlError(403, 'forbidden')
        return user, session

    @app.post('/control/v1/auth/login')
    async def login(request: Request):
        data = await body(request, {'username', 'password'})
        name, password = credentials(data)
        throttle(engine, name, request.client.host if request.client else 'unknown')
        with engine.begin() as conn:
            authority_lock(conn)
            user = conn.execute(select(users).where(users.c.username == name).with_for_update()).mappings().first()
            valid = verify(password, user['password_hash'] if user else DUMMY_HASH)
            if not user or not valid or not user['enabled']:
                raise ControlError(401, 'unauthenticated')
            token, sid, expiry = secrets.token_urlsafe(32), uid(), now() + config.session_ttl_seconds
            conn.execute(sessions.insert().values(id=sid, user_id=user['id'], token_digest=token_digest(token), user_epoch=user['user_epoch'], expires_at=expiry))
            nodes, cursor = eligible_nodes(conn, user['id'])
            return {'schema': 1, 'access_token': token, 'token_type': 'bearer', 'central_session_id': show(sid), 'expires_at': expiry, 'user': user_dto(user), 'nodes': nodes, 'nodes_next_cursor': cursor}

    @app.get('/control/v1/session')
    async def session(request: Request):
        with engine.begin() as conn:
            user, session = auth(conn, request)
            return {'schema': 1, 'central_session_id': show(session['id']), 'expires_at': session['expires_at'], 'user': user_dto(user)}

    @app.get('/control/v1/admin/users')
    async def list_users(request: Request):
        with engine.begin() as conn:
            auth(conn, request, True)
            try:
                pairs = list(request.query_params.multi_items())
                params = dict(pairs)
                if len(params) != len(pairs) or set(params) - {'limit', 'cursor'}:
                    raise ValueError()
                limit = params.get('limit', '50')
                if not re.fullmatch(r'[1-9][0-9]{0,2}', limit) or not 1 <= int(limit) <= 100:
                    raise ValueError()
                limit = int(limit)
                query = select(users)
                if 'cursor' in params:
                    query = query.where(users.c.id > canonical(params['cursor']))
            except (ValueError, TypeError):
                raise ControlError(422, 'invalid_input') from None
            rows = conn.execute(query.order_by(users.c.id).limit(limit + 1)).mappings().all()
            return {'schema': 1, 'items': [user_dto(row) for row in rows[:limit]], 'next_cursor': show(rows[limit-1]['id']) if len(rows) > limit else None}

    @app.post('/control/v1/admin/users', status_code=201)
    async def create_user(request: Request):
        data = await body(request, {'username', 'password', 'role'})
        name, password = credentials(data)
        if data['role'] not in ('admin', 'user'):
            raise ControlError(422, 'invalid_input')
        with engine.begin() as conn:
            actor, _ = auth(conn, request, True)
            identity = uid()
            conn.execute(users.insert().values(id=identity, username=name, password_hash=PASSWORDS.hash(password), role=data['role'], enabled=True, user_epoch=1, created_at=now()))
            record_audit(conn, actor['id'], 'user.create', identity, None, 1, 'administrator creation', request.state.request_id)
            user = conn.execute(select(users).where(users.c.id == identity)).mappings().one()
            return {'schema': 1, 'user': user_dto(user)}

    def identity(value):
        try:
            return canonical(value)
        except (ValueError, TypeError, AttributeError):
            raise ControlError(422, 'invalid_input') from None

    def mutation(data):
        epoch = data['expected_user_epoch']
        reason = data['reason']
        if type(epoch) is not int or not 1 <= epoch < 9007199254740991 or not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 512:
            raise ControlError(422, 'invalid_input')

    def revoke(conn, user_id, session_id=None):
        from .schema_v1 import revocations
        stamp, rid = now(), uid()
        query = sessions.update().where(sessions.c.user_id == user_id, sessions.c.revoked_at.is_(None))
        if session_id is not None:
            query = query.where(sessions.c.id == session_id)
        conn.execute(query.values(revoked_at=stamp))
        conn.execute(revocations.insert().values(id=rid, user_id=user_id, session_id=session_id, committed_at=stamp, enforcement_deadline=stamp + 30, cleanup_state='pending'))
        return {'schema': 1, 'revocation_id': show(rid), 'committed_at': stamp, 'enforcement_deadline': stamp + 30, 'cleanup_state': 'pending'}

    @app.patch('/control/v1/admin/users/{user_id}')
    async def patch_user(user_id: str, request: Request):
        data = await body(request, {'expected_user_epoch', 'enabled', 'reason'})
        mutation(data)
        if type(data['enabled']) is not bool:
            raise ControlError(422, 'invalid_input')
        target = identity(user_id)
        with engine.begin() as conn:
            actor, _ = auth(conn, request, True)
            user = conn.execute(select(users).where(users.c.id == target).with_for_update()).mappings().first()
            if not user:
                raise ControlError(404, 'not_found')
            if user['user_epoch'] != data['expected_user_epoch']:
                raise ControlError(409, 'conflict')
            if not data['enabled'] and user['enabled'] and user['role'] == 'admin':
                enabled_admins = conn.execute(select(users.c.id).where(users.c.role == 'admin', users.c.enabled.is_(True)).with_for_update()).all()
                if len(enabled_admins) <= 1:
                    raise ControlError(409, 'last_administrator')
            revision = user['user_epoch'] + 1
            conn.execute(users.update().where(users.c.id == target).values(enabled=data['enabled'], user_epoch=revision))
            receipt = revoke(conn, target) if not data['enabled'] else None
            record_audit(conn, actor['id'], 'user.enabled', target, user['user_epoch'], revision, data['reason'], request.state.request_id)
            current = conn.execute(select(users).where(users.c.id == target)).mappings().one()
            return {'schema': 1, 'user': user_dto(current), 'revocation': receipt}

    @app.post('/control/v1/admin/users/{user_id}/reset-password')
    async def reset_password(user_id: str, request: Request):
        data = await body(request, {'expected_user_epoch', 'password', 'reason'})
        mutation(data)
        password = data['password']
        if not isinstance(password, str) or not 12 <= len(password) <= 1024:
            raise ControlError(422, 'invalid_input')
        target = identity(user_id)
        with engine.begin() as conn:
            actor, _ = auth(conn, request, True)
            user = conn.execute(select(users).where(users.c.id == target).with_for_update()).mappings().first()
            if not user:
                raise ControlError(404, 'not_found')
            if user['user_epoch'] != data['expected_user_epoch']:
                raise ControlError(409, 'conflict')
            revision = user['user_epoch'] + 1
            conn.execute(users.update().where(users.c.id == target).values(password_hash=PASSWORDS.hash(password), user_epoch=revision))
            receipt = revoke(conn, target)
            record_audit(conn, actor['id'], 'user.reset_password', target, user['user_epoch'], revision, data['reason'], request.state.request_id)
            current = conn.execute(select(users).where(users.c.id == target)).mappings().one()
            return {'schema': 1, 'user': user_dto(current), 'revocation': receipt}

    @app.delete('/control/v1/sessions/{session_id}', status_code=202)
    async def delete_session(session_id: str, request: Request):
        target = identity(session_id)
        if request.query_params or await request.body():
            raise ControlError(422, 'invalid_input')
        with engine.begin() as conn:
            actor, _ = auth(conn, request)
            session = conn.execute(select(sessions).where(sessions.c.id == target).with_for_update()).mappings().first()
            if not session or (actor['role'] != 'admin' and session['user_id'] != actor['id']):
                raise ControlError(404, 'not_found')
            receipt = revoke(conn, session['user_id'], target)
            record_audit(conn, actor['id'], 'session.revoke', target, session['user_epoch'], session['user_epoch'], 'session revocation', request.state.request_id)
            return receipt

    def page(request, extra=()):
        try:
            pairs = list(request.query_params.multi_items())
            params = dict(pairs)
            if len(params) != len(pairs) or set(params) - {'limit', 'cursor', *extra}:
                raise ValueError()
            limit = params.get('limit', '50')
            if not re.fullmatch(r'[1-9][0-9]{0,2}', limit) or not 1 <= int(limit) <= 100:
                raise ValueError()
            cursor = canonical(params['cursor']) if 'cursor' in params else None
            return int(limit), cursor, params
        except (ValueError, TypeError, AttributeError):
            raise ControlError(422, 'invalid_input') from None

    @app.get('/control/v1/sessions')
    async def list_sessions(request: Request):
        limit, cursor, params = page(request, ('central_user_id',))
        with engine.begin() as conn:
            actor, _ = auth(conn, request)
            subject = identity(params['central_user_id']) if 'central_user_id' in params else None
            if actor['role'] != 'admin':
                if subject is not None and subject != actor['id']:
                    raise ControlError(403, 'forbidden')
                subject = actor['id']
            query = select(sessions, users.c.enabled.label('user_enabled'),
                           users.c.user_epoch.label('current_user_epoch')).select_from(sessions.join(users))
            if subject is not None:
                query = query.where(sessions.c.user_id == subject)
            if cursor is not None:
                query = query.where(sessions.c.id > cursor)
            rows = conn.execute(query.order_by(sessions.c.id).limit(limit + 1)).mappings().all()
            stamp = now()
            items = [{'central_session_id': show(row['id']), 'central_user_id': show(row['user_id']),
                      'expires_at': row['expires_at'], 'revoked_at': row['revoked_at'],
                      'active': bool(row['user_enabled'] and row['revoked_at'] is None
                                     and row['expires_at'] > stamp and row['user_epoch'] == row['current_user_epoch'])}
                     for row in rows[:limit]]
            return {'schema': 1, 'items': items,
                    'next_cursor': show(rows[limit - 1]['id']) if len(rows) > limit else None}

    @app.get('/control/v1/admin/audit-events')
    async def list_audit(request: Request):
        from .schema_v1 import audit
        limit, cursor, _ = page(request)
        with engine.begin() as conn:
            auth(conn, request, True)
            query = select(audit)
            if cursor is not None:
                query = query.where(audit.c.id > cursor)
            rows = conn.execute(query.order_by(audit.c.id).limit(limit + 1)).mappings().all()
            items = [{'event_id': show(row['id']),
                      'actor_kind': 'user' if row['actor_id'] is not None else 'system',
                      'actor_id': show(row['actor_id']) if row['actor_id'] is not None else None,
                      'action': row['action'], 'object_kind': row['action'].split('.', 1)[0],
                      'object_id': show(row['object_id']), 'request_id': show(row['request_id']),
                      'reason': row['reason'], 'created_at': row['created_at']}
                     for row in rows[:limit]]
            return {'schema': 1, 'items': items,
                    'next_cursor': show(rows[limit - 1]['id']) if len(rows) > limit else None}

    @app.get('/control/v1/me/nodes')
    async def my_nodes(request: Request):
        limit, cursor, _ = page(request)
        with engine.begin() as conn:
            actor, _ = auth(conn, request)
            items, following = eligible_nodes(conn, actor['id'], limit, cursor)
            return {'schema': 1, 'items': items, 'next_cursor': following}

    @app.get('/control/v1/admin/nodes')
    async def list_nodes(request: Request):
        from .schema_v1 import nodes
        limit, cursor, _ = page(request)
        with engine.begin() as conn:
            auth(conn, request, True)
            query = select(nodes)
            if cursor is not None:
                query = query.where(nodes.c.id > cursor)
            rows = conn.execute(query.order_by(nodes.c.id).limit(limit + 1)).mappings().all()
            stamp = now()
            items = [{'node_id': show(row['id']), 'alias': row['alias'], 'display_name': row['display_name'],
                      'api_origin': row['api_origin'], 'tls_server_name': row['tls_server_name'],
                      'state': row['state'], 'node_epoch': row['node_epoch'],
                      'config_revision': row['config_revision'], 'key_fingerprint': row['key_fingerprint'].hex(),
                      'last_seen_at': row['last_seen_at'],
                      'online': bool(row['state'] == 'active' and row['last_seen_at'] is not None
                                     and 0 <= stamp - row['last_seen_at'] < 30)}
                     for row in rows[:limit]]
            return {'schema': 1, 'items': items,
                    'next_cursor': show(rows[limit - 1]['id']) if len(rows) > limit else None}

    from .enrollment import install_routes
    install_routes(app, engine, body, auth, page, identity)
    from .authorization import install_routes as install_authorization
    install_authorization(app, engine, body, auth, page, identity)
    from .exchange import install_routes as install_exchange
    install_exchange(app, engine, body, auth, identity)
    return app
