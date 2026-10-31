"""C1 possession enrollment; no outbound URL fetching and no secret logging."""
import base64
import hashlib
import re
import secrets
from urllib.parse import urlsplit
from fastapi import Request
from sqlalchemy import select
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from .enrollment_schema import enrollments, challenges
from .schema_v1 import nodes
from .security import ControlError, uid, show, now, authority_lock, record_audit, throttle


def digest(domain, token):
    return hashlib.sha256(b'OrangeSpace-control-' + domain + b'-v1\0' + token.encode('ascii')).digest()


def decode(value, size):
    try:
        if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]+', value):
            raise ValueError()
        raw = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
        if len(raw) != size or base64.urlsafe_b64encode(raw).decode().rstrip('=') != value:
            raise ValueError()
        return raw
    except (ValueError, TypeError):
        raise ControlError(422, 'invalid_input') from None


def install_routes(app, engine, body, auth, page, identity):
    def reason(data):
        if not isinstance(data['reason'], str) or not 1 <= len(data['reason'].strip()) <= 512:
            raise ControlError(422, 'invalid_input')

    def enrollment(conn, eid, token):
        decode(token, 32)
        row = conn.execute(select(enrollments).where(enrollments.c.id == eid).with_for_update()).mappings().first()
        if row is None or not secrets.compare_digest(row['token_digest'], digest(b'enrollment', token)):
            raise ControlError(401, 'unauthenticated')
        if row['consumed_at'] is not None:
            raise ControlError(409, 'conflict')
        if row['expires_at'] <= now():
            raise ControlError(410, 'expired')
        return row

    @app.post('/control/v1/admin/node-enrollments', status_code=201)
    async def create(request: Request):
        data = await body(request, {'node_id','alias','display_name','api_origin','tls_server_name','expected_key_fingerprint','reason'})
        nid = identity(data['node_id'])
        reason(data)
        try:
            if not isinstance(data['alias'], str) or not re.fullmatch(r'[a-z0-9][a-z0-9_.-]{0,63}', data['alias']):
                raise ValueError()
            if not isinstance(data['display_name'], str) or not 1 <= len(data['display_name']) <= 128:
                raise ValueError()
            origin = data['api_origin']
            parsed = urlsplit(origin)
            if not isinstance(origin, str) or len(origin) > 512 or parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.path or parsed.query or parsed.fragment or parsed.port == 0 or origin != 'https://' + parsed.netloc or any(ord(c) <= 32 for c in origin):
                raise ValueError()
            tls = data['tls_server_name']
            if not isinstance(tls, str) or not 1 <= len(tls) <= 253 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', tls) or any(not label or len(label) > 63 or label.startswith('-') or label.endswith('-') for label in tls.split('.')):
                raise ValueError()
            fingerprint = data['expected_key_fingerprint']
            if not isinstance(fingerprint, str) or not re.fullmatch('[0-9a-f]{64}', fingerprint):
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise ControlError(422, 'invalid_input') from None
        with engine.begin() as conn:
            actor, _ = auth(conn, request, True)
            if conn.execute(select(nodes.c.id).where((nodes.c.id == nid) | (nodes.c.alias == data['alias']))).first():
                raise ControlError(409, 'conflict')
            eid, token, expiry = uid(), secrets.token_urlsafe(32), now() + 600
            conn.execute(enrollments.insert().values(id=eid,node_id=nid,alias=data['alias'],display_name=data['display_name'],api_origin=origin,tls_server_name=tls,fingerprint=bytes.fromhex(fingerprint),token_digest=digest(b'enrollment',token),expires_at=expiry,challenge_count=0))
            record_audit(conn,actor['id'],'node.enrollment',nid,None,1,data['reason'],request.state.request_id)
            return dict(schema=1,enrollment_id=show(eid),enrollment_token=token,node_id=show(nid),expires_at=expiry)

    @app.get('/control/v1/admin/node-enrollments')
    async def listing(request: Request):
        limit, cursor, _ = page(request)
        with engine.begin() as conn:
            auth(conn,request,True)
            query = select(enrollments)
            if cursor is not None:
                query = query.where(enrollments.c.id > cursor)
            rows = conn.execute(query.order_by(enrollments.c.id).limit(limit+1)).mappings().all()
            return dict(schema=1,items=[dict(enrollment_id=show(r['id']),node_id=show(r['node_id']),expires_at=r['expires_at'],consumed_at=r['consumed_at']) for r in rows[:limit]],next_cursor=show(rows[limit-1]['id']) if len(rows)>limit else None)

    @app.post('/control/v1/node-enrollments/{eid}/challenge')
    async def challenge(eid: str, request: Request):
        data = await body(request, {'enrollment_token','node_id','public_key'})
        target, nid, key = identity(eid), identity(data['node_id']), decode(data['public_key'],32)
        throttle(engine, 'enrollment:'+eid, request.client.host if request.client else 'unknown')
        with engine.begin() as conn:
            authority_lock(conn)
            row = enrollment(conn,target,data['enrollment_token'])
            if row['node_id'] != nid or not secrets.compare_digest(row['fingerprint'],hashlib.sha256(key).digest()):
                raise ControlError(401,'unauthenticated')
            if row['challenge_count'] >= 5:
                raise ControlError(429,'rate_limited')
            cid, nonce, expiry = uid(), secrets.token_urlsafe(32), min(now()+60,row['expires_at'])
            # The enrollment row is locked under the authority boundary. Publish
            # only one live challenge; an older proof must not consume it later.
            conn.execute(challenges.update().where(
                challenges.c.enrollment_id == target,
                challenges.c.consumed_at.is_(None)).values(consumed_at=now()))
            conn.execute(enrollments.update().where(enrollments.c.id == target).values(challenge_count=row['challenge_count']+1))
            conn.execute(challenges.insert().values(id=cid,enrollment_id=target,public_key=key,nonce=nonce,expires_at=expiry))
            return dict(schema=1,challenge_id=show(cid),nonce=nonce,expires_at=expiry)

    @app.post('/control/v1/node-enrollments/{eid}/complete',status_code=201)
    async def complete(eid: str, request: Request):
        data = await body(request, {'enrollment_token','challenge_id','signature'})
        target, cid, signature = identity(eid), identity(data['challenge_id']), decode(data['signature'],64)
        throttle(engine, 'enrollment:'+eid, request.client.host if request.client else 'unknown')
        with engine.begin() as conn:
            authority_lock(conn)
            row = enrollment(conn,target,data['enrollment_token'])
            challenge = conn.execute(select(challenges).where(challenges.c.id == cid,challenges.c.enrollment_id == target).with_for_update()).mappings().first()
            if challenge is None:
                raise ControlError(401,'unauthenticated')
            if challenge['consumed_at'] is not None:
                raise ControlError(409,'conflict')
            if challenge['expires_at'] <= now():
                raise ControlError(410,'expired')
            values = [show(target),show(row['node_id']),row['fingerprint'].hex(),row['api_origin'],show(cid),challenge['nonce'],str(challenge['expires_at'])]
            message = b'OrangeSpace-enroll-v1\n'+b''.join(str(len(v.encode('utf8'))).encode('ascii')+b':'+v.encode('utf8') for v in values)
            try:
                Ed25519PublicKey.from_public_bytes(challenge['public_key']).verify(signature,message)
            except (InvalidSignature,ValueError):
                raise ControlError(401,'unauthenticated') from None
            token = secrets.token_urlsafe(32)
            conn.execute(nodes.insert().values(id=row['node_id'],alias=row['alias'],display_name=row['display_name'],api_origin=row['api_origin'],tls_server_name=row['tls_server_name'],public_key=challenge['public_key'],key_fingerprint=row['fingerprint'],machine_token_digest=digest(b'node-machine',token),state='pending',node_epoch=1,config_revision=1))
            conn.execute(enrollments.update().where(enrollments.c.id == target).values(consumed_at=now()))
            conn.execute(challenges.update().where(challenges.c.id == cid).values(consumed_at=now()))
            record_audit(conn,None,'node.possession',row['node_id'],None,1,'enrollment possession verified',request.state.request_id)
            return dict(schema=1,node_id=show(row['node_id']),node_epoch=1,node_access_token=token,config_revision=1)

    @app.post('/control/v1/admin/nodes/{nid}/activate')
    async def activate(nid: str,request: Request):
        data = await body(request, {'expected_node_epoch','expected_config_revision','reason'})
        target = identity(nid)
        reason(data)
        for field in ('expected_node_epoch','expected_config_revision'):
            if type(data[field]) is not int or not 1 <= data[field] <= 9007199254740991:
                raise ControlError(422,'invalid_input')
        with engine.begin() as conn:
            actor,_ = auth(conn,request,True)
            row = conn.execute(select(nodes).where(nodes.c.id == target).with_for_update()).mappings().first()
            if row is None:
                raise ControlError(404,'not_found')
            if row['state'] != 'pending' or row['public_key'] is None or row['machine_token_digest'] is None or row['node_epoch'] != data['expected_node_epoch'] or row['config_revision'] != data['expected_config_revision']:
                raise ControlError(409,'conflict')
            conn.execute(nodes.update().where(nodes.c.id == target).values(state='active'))
            record_audit(conn,actor['id'],'node.activate',target,row['node_epoch'],row['node_epoch'],data['reason'],request.state.request_id)
            return dict(schema=1,node_id=show(target),state='active',node_epoch=row['node_epoch'],config_revision=row['config_revision'])

    @app.post('/control/v1/internal/heartbeat')
    async def heartbeat(request: Request):
        data = await body(request, {'node_id','node_epoch','config_revision','request_id','observed_at'})
        target = identity(data['node_id'])
        identity(data['request_id'])
        for field in ('node_epoch','config_revision','observed_at'):
            if type(data[field]) is not int or not (0 if field == 'observed_at' else 1) <= data[field] <= 9007199254740991:
                raise ControlError(422,'invalid_input')
        authorization = request.headers.get('authorization','')
        if not authorization.startswith('Bearer '):
            raise ControlError(401,'unauthenticated')
        token = authorization[7:]
        decode(token,32)
        with engine.begin() as conn:
            authority_lock(conn)
            row = conn.execute(select(nodes).where(nodes.c.machine_token_digest == digest(b'node-machine',token)).with_for_update()).mappings().first()
            if row is None or row['id'] != target or row['state'] != 'active' or row['public_key'] is None or row['node_epoch'] != data['node_epoch'] or row['config_revision'] != data['config_revision']:
                raise ControlError(401,'unauthenticated')
            stamp = now()
            conn.execute(nodes.update().where(nodes.c.id == target).values(last_seen_at=stamp))
            return dict(schema=1,server_time=stamp,commands=[])

    from .identity import install_routes as install_identity
    install_identity(app, engine, body, auth, page, identity)
