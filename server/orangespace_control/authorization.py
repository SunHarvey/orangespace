"""Scoped grant authority; DB receipts never assert actual node cleanup."""
from fastapi import Request
from sqlalchemy import select
from .schema_v1 import users, nodes, grants, MAX_INT
from .security import ControlError, now, uid, show, record_audit


def grant_dto(row):
    return {'grant_id': show(row['id']), 'grant_epoch': row['grant_epoch'],
            'enabled': bool(row['enabled']), 'scopes': row['scopes'], 'valid_until': row['valid_until']}


def install_routes(app, engine, body, auth, page, identity):
    @app.get('/control/v1/admin/grants')
    async def listing(request: Request):
        limit, cursor, _ = page(request)
        with engine.begin() as conn:
            auth(conn, request, True)
            query = select(grants)
            if cursor is not None:
                query = query.where(grants.c.id > cursor)
            rows = conn.execute(query.order_by(grants.c.id).limit(limit + 1)).mappings().all()
            return {'schema': 1, 'items': [dict(grant_dto(r), central_user_id=show(r['user_id']), node_id=show(r['node_id'])) for r in rows[:limit]], 'next_cursor': show(rows[limit-1]['id']) if len(rows) > limit else None}

    @app.put('/control/v1/admin/users/{user_id}/nodes/{node_id}/grant')
    async def put(user_id: str, node_id: str, request: Request):
        data = await body(request, {'expected_grant_epoch', 'enabled', 'scopes', 'valid_until', 'reason'})
        epoch, scopes, expiry, reason = (data[k] for k in ('expected_grant_epoch', 'scopes', 'valid_until', 'reason'))
        if (request.query_params or type(epoch) is not int or not 0 <= epoch < MAX_INT
                or type(data['enabled']) is not bool or not isinstance(scopes, list) or len(scopes) > 3
                or any(type(s) is not str or s not in ('files.read', 'files.write', 'tunnel') for s in scopes)
                or len(set(scopes)) != len(scopes)
                or (expiry is not None and (type(expiry) is not int or not 0 <= expiry <= MAX_INT))
                or not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 512):
            raise ControlError(422, 'invalid_input')
        target, node = identity(user_id), identity(node_id)
        with engine.begin() as conn:
            actor, _ = auth(conn, request, True)  # same global authority lock as all other mutations
            if conn.execute(select(users.c.id).where(users.c.id == target).with_for_update()).first() is None:
                raise ControlError(404, 'not_found')
            registered = conn.execute(select(nodes).where(nodes.c.id == node).with_for_update()).mappings().first()
            if not registered:
                raise ControlError(404, 'not_found')
            if registered['public_key'] is None or registered['machine_token_digest'] is None or registered['state'] == 'revoked':
                raise ControlError(409, 'node_not_registered')
            old = conn.execute(select(grants).where(grants.c.user_id == target, grants.c.node_id == node).with_for_update()).mappings().first()
            if (old['grant_epoch'] if old else 0) != epoch:
                raise ControlError(409, 'conflict')
            gid = old['id'] if old else uid()
            values = dict(enabled=data['enabled'], scopes=scopes, valid_until=expiry, grant_epoch=epoch + 1)
            if old:
                conn.execute(grants.update().where(grants.c.id == gid).values(**values))
            else:
                conn.execute(grants.insert().values(id=gid, user_id=target, node_id=node, **values))
            receipt = None
            if old:
                # Every epoch change invalidates the prior exact grant, never the user's other nodes/sessions.
                from .authorization_schema import events
                rid, stamp = uid(), now()
                conn.execute(events.insert().values(id=rid, user_id=target, node_id=node, grant_id=gid,
                    before_epoch=epoch, after_epoch=epoch + 1, committed_at=stamp,
                    enforcement_deadline=stamp + 30, cleanup_state='pending', delivery_state='pending'))
                receipt = dict(schema=1, revocation_id=show(rid), committed_at=stamp, enforcement_deadline=stamp + 30, cleanup_state='pending')
            record_audit(conn, actor['id'], 'grant.put', gid, epoch, epoch + 1, reason, request.state.request_id)
            return dict(schema=1, grant_id=show(gid), **values, revocation=receipt)
