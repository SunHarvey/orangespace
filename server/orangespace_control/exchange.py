"""One-time exchange, identity only: no node token, permit or transport proof."""
import secrets
from fastapi import Request
from sqlalchemy import select
from .schema_v1 import users, sessions, nodes, mappings, grants
from .exchange_schema import exchanges, federations
from .security import ControlError, authority_lock, now, uid, show
from .enrollment import decode, digest

EPOCHS=('user_epoch','node_epoch','mapping_epoch','grant_epoch')

def install_routes(app,engine,body,auth,identity):
    def row(conn,table,condition):
        return conn.execute(select(table).where(condition).with_for_update()).mappings().first()

    def live(conn,user,session,node,mapping,grant):
        stamp=now()
        if (not all((user,session,node,mapping,grant)) or not user['enabled']
            or session['revoked_at'] is not None or session['expires_at']<=stamp
            or session['user_epoch']!=user['user_epoch'] or session['user_id']!=user['id']
            or node['state']!='active' or node['public_key'] is None or node['machine_token_digest'] is None
            or mapping['state']!='approved' or mapping['central_user_id']!=user['id'] or mapping['node_id']!=node['id']
            or not grant['enabled'] or not grant['scopes'] or grant['user_id']!=user['id'] or grant['node_id']!=node['id']
            or (grant['valid_until'] is not None and grant['valid_until']<=stamp)):
            raise ControlError(410,'terminated')
        return dict(user_epoch=user['user_epoch'],node_epoch=node['node_epoch'],mapping_epoch=mapping['mapping_epoch'],grant_epoch=grant['grant_epoch'])

    @app.post('/control/v1/node-exchanges',status_code=201)
    async def issue(request: Request):
        data=await body(request,{'node_id','expected_epochs'})
        nid=identity(data['node_id']);expected=data['expected_epochs']
        if not isinstance(expected,dict) or set(expected)!=set(EPOCHS) or any(type(expected[k]) is not int or not 1<=expected[k]<=9007199254740991 for k in EPOCHS):
            raise ControlError(422,'invalid_input')
        with engine.begin() as conn:
            user,session=auth(conn,request)
            node=row(conn,nodes,nodes.c.id==nid)
            mapping=row(conn,mappings,(mappings.c.node_id==nid)&(mappings.c.central_user_id==user['id']))
            grant=row(conn,grants,(grants.c.node_id==nid)&(grants.c.user_id==user['id']))
            epochs=live(conn,user,session,node,mapping,grant)
            if expected!=epochs: raise ControlError(409,'conflict')
            token=secrets.token_urlsafe(32)
            federation_expiry=min(session['expires_at'],grant['valid_until'] if grant['valid_until'] is not None else session['expires_at'])
            expiry=min(now()+30,federation_expiry)
            ticket=dict(federation_expires_at=federation_expiry,id=uid(),token_digest=digest(b'node-exchange',token),central_session_id=session['id'],central_user_id=user['id'],node_id=nid,mapping_id=mapping['id'],grant_id=grant['id'],legacy_user_id=mapping['legacy_user_id'],expires_at=expiry,**epochs,**{k:node[k] for k in ('public_key','key_fingerprint','machine_token_digest','config_revision')})
            conn.execute(exchanges.insert().values(**ticket))
            return dict(schema=1,exchange_id=show(ticket['id']),exchange_token=token,node_id=show(nid),expires_at=expiry)

    @app.post('/control/v1/internal/node-exchanges/consume')
    async def consume(request: Request):
        data=await body(request,{'exchange_id','exchange_token','request_id'})
        eid,rid=identity(data['exchange_id']),identity(data['request_id'])
        decode(data['exchange_token'],32)
        header=request.headers.get('authorization','')
        if not header.startswith('Bearer '): raise ControlError(401,'unauthenticated')
        machine=header[7:];decode(machine,32)
        with engine.begin() as conn:
            authority_lock(conn)
            node=row(conn,nodes,nodes.c.machine_token_digest==digest(b'node-machine',machine))
            if not node or node['state']!='active' or node['public_key'] is None: raise ControlError(401,'unauthenticated')
            ticket=row(conn,exchanges,exchanges.c.id==eid)
            if not ticket or ticket['node_id']!=node['id'] or not secrets.compare_digest(ticket['token_digest'],digest(b'node-exchange',data['exchange_token'])):
                raise ControlError(401,'unauthenticated')
            user=row(conn,users,users.c.id==ticket['central_user_id'])
            session=row(conn,sessions,sessions.c.id==ticket['central_session_id'])
            mapping=row(conn,mappings,mappings.c.id==ticket['mapping_id'])
            grant=row(conn,grants,grants.c.id==ticket['grant_id'])
            epochs=live(conn,user,session,node,mapping,grant)
            if ticket['expires_at']<=now() or any(ticket[k]!=epochs[k] for k in EPOCHS) or any(ticket[k]!=node[k] for k in ('public_key','key_fingerprint','machine_token_digest','config_revision')) or ticket['legacy_user_id']!=mapping['legacy_user_id']:
                raise ControlError(410,'terminated')
            original=row(conn,exchanges,(exchanges.c.node_id==node['id'])&(exchanges.c.request_id==rid))
            if original is not None:
                if original['id']!=eid: raise ControlError(409,'conflict')
                return dict(schema=1,federation=original['result'])
            if ticket['request_id'] is not None:
                if ticket['request_id']!=rid: raise ControlError(409,'conflict')
                return dict(schema=1,federation=ticket['result'])
            fid=uid()
            # Identity deadline is frozen at issue, distinct from consumption window.
            result={k:show(ticket[k]) for k in ('central_session_id','central_user_id','node_id','legacy_user_id','mapping_id','grant_id')}
            result.update(federation_session_id=show(fid),epochs=epochs,expires_at=ticket['federation_expires_at'])
            conn.execute(federations.insert().values(id=fid,exchange_id=eid,result=result,expires_at=ticket['federation_expires_at']))
            conn.execute(exchanges.update().where(exchanges.c.id==eid,exchanges.c.request_id.is_(None)).values(request_id=rid,result=result))
            return dict(schema=1,federation=result)

    @app.post('/control/v1/internal/federation-sessions/validate')
    async def validate(request: Request):
        data=await body(request,{'federation_session_id','expected_epochs','required_scope'})
        fid=identity(data['federation_session_id']);expected=data['expected_epochs']
        if not isinstance(expected,dict) or set(expected)!=set(EPOCHS) or any(type(expected[k]) is not int or not 1<=expected[k]<=9007199254740991 for k in EPOCHS):
            raise ControlError(422,'invalid_input')
        scope=data['required_scope']
        if scope is not None and (not isinstance(scope,str) or scope not in ('files.read','files.write','tunnel')):
            raise ControlError(422,'invalid_input')
        header=request.headers.get('authorization','')
        if not header.startswith('Bearer '): raise ControlError(401,'unauthenticated')
        machine=header[7:];decode(machine,32)
        with engine.begin() as conn:
            authority_lock(conn)
            node=row(conn,nodes,nodes.c.machine_token_digest==digest(b'node-machine',machine))
            if not node or node['state']!='active' or node['public_key'] is None:
                raise ControlError(401,'unauthenticated')
            federation=row(conn,federations,federations.c.id==fid)
            if not federation: raise ControlError(410,'terminated')
            ticket=row(conn,exchanges,exchanges.c.id==federation['exchange_id'])
            if not ticket or ticket['node_id']!=node['id']:
                raise ControlError(401,'unauthenticated')
            user=row(conn,users,users.c.id==ticket['central_user_id'])
            session=row(conn,sessions,sessions.c.id==ticket['central_session_id'])
            mapping=row(conn,mappings,mappings.c.id==ticket['mapping_id'])
            grant=row(conn,grants,grants.c.id==ticket['grant_id'])
            epochs=live(conn,user,session,node,mapping,grant)
            if (federation['expires_at']<=now() or ticket['federation_expires_at']<=now()
                or federation['expires_at']!=ticket['federation_expires_at']
                or any(ticket[k]!=epochs[k] for k in EPOCHS)
                or any(ticket[k]!=node[k] for k in ('public_key','key_fingerprint','machine_token_digest','config_revision'))
                or ticket['legacy_user_id']!=mapping['legacy_user_id']):
                raise ControlError(410,'terminated')
            if expected!=epochs: raise ControlError(409,'conflict')
            if scope is not None and scope not in grant['scopes']: raise ControlError(403,'forbidden')
            return dict(schema=1,federation=federation['result'],scopes=grant['scopes'])

    from .permits import install_routes as install_permits
    install_permits(app,engine,body,identity,row,live)
