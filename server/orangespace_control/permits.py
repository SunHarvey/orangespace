"""Short forwarding permits, serialized with every authority mutation.

The centre also owns tunnel anti-replay: nodes keep leases only in memory, so a
restarted node cannot remember which tunnel IDs or generations it has seen.
"""
import time
from fastapi import Request
from sqlalchemy import select
from .schema_v1 import users, sessions, nodes, mappings, grants
from .exchange_schema import exchanges, federations
from .permit_schema import permits
from .binding_schema import bindings
from .security import ControlError, authority_lock, now, uid, show
from .enrollment import decode, digest

EPOCHS=('user_epoch','node_epoch','mapping_epoch','grant_epoch')

def install_routes(app,engine,body,identity,row,live):
    @app.post('/control/v1/internal/lease-permits')
    async def issue(request: Request):
        data=await body(request,{'request_id','federation_session_id','tunnel_id','sandbox_id','generation','operation','expected_epochs'})
        ids={k:identity(data[k]) for k in ('request_id','federation_session_id','tunnel_id','sandbox_id')}
        expected=data['expected_epochs']
        if (type(data['generation']) is not int or not 1<=data['generation']<=9007199254740991
            or type(data['operation']) is not str or data['operation'] not in ('create','renew')
            or type(expected) is not dict or set(expected)!=set(EPOCHS)
            or any(type(expected[k]) is not int or not 1<=expected[k]<=9007199254740991 for k in EPOCHS)):
            raise ControlError(422,'invalid_input')
        header=request.headers.get('authorization','')
        if not header.startswith('Bearer '): raise ControlError(401,'unauthenticated')
        machine=header[7:];decode(machine,32)
        with engine.begin() as conn:
            # Same global authority lock as revoke; no cache or network under lock.
            authority_lock(conn)
            node=row(conn,nodes,nodes.c.machine_token_digest==digest(b'node-machine',machine))
            if not node or node['state']!='active' or node['public_key'] is None: raise ControlError(401,'unauthenticated')
            federation=row(conn,federations,federations.c.id==ids['federation_session_id'])
            if not federation: raise ControlError(410,'terminated')
            ticket=row(conn,exchanges,exchanges.c.id==federation['exchange_id'])
            if not ticket or ticket['node_id']!=node['id']: raise ControlError(401,'unauthenticated')
            user=row(conn,users,users.c.id==ticket['central_user_id'])
            session=row(conn,sessions,sessions.c.id==ticket['central_session_id'])
            mapping=row(conn,mappings,mappings.c.id==ticket['mapping_id'])
            grant=row(conn,grants,grants.c.id==ticket['grant_id'])
            epochs=live(conn,user,session,node,mapping,grant)
            if (federation['expires_at']<=now() or federation['expires_at']!=ticket['federation_expires_at']
                or any(ticket[k]!=epochs[k] for k in EPOCHS)
                or any(ticket[k]!=node[k] for k in ('public_key','key_fingerprint','machine_token_digest','config_revision'))
                or ticket['legacy_user_id']!=mapping['legacy_user_id']):
                raise ControlError(410,'terminated')
            if expected!=epochs: raise ControlError(409,'conflict')
            if 'tunnel' not in grant['scopes']: raise ControlError(403,'forbidden')
            original=row(conn,permits,(permits.c.node_id==node['id'])&(permits.c.request_id==ids['request_id']))
            binding=dict(ids,generation=data['generation'],operation=data['operation'])
            if original:
                if any(original[k]!=v for k,v in binding.items()) or original['epochs']!=epochs:
                    raise ControlError(409,'conflict')
                if original['state']!='issued': raise ControlError(410,'terminated')
            key=((bindings.c.node_id==node['id'])&(bindings.c.central_user_id==ticket['central_user_id'])
                 &(bindings.c.sandbox_id==ids['sandbox_id']))
            if not original and data['operation']=='create':
                # A tunnel ID is single-use everywhere; a sandbox's generation only rises.
                if conn.execute(select(permits.c.id).where(permits.c.tunnel_id==ids['tunnel_id']).limit(1)).first():
                    raise ControlError(409,'conflict')
                latest=row(conn,bindings,key)
                if latest and data['generation']<=latest['generation']: raise ControlError(409,'conflict')
                values=dict(generation=data['generation'],tunnel_id=ids['tunnel_id'],
                            federation_session_id=ids['federation_session_id'],updated_at=now())
                if latest: conn.execute(bindings.update().where(key).values(**values))
                else: conn.execute(bindings.insert().values(node_id=node['id'],central_user_id=ticket['central_user_id'],sandbox_id=ids['sandbox_id'],**values))
            # Renewals (and retried creates) must still be the sandbox's current
            # tunnel, created on this node under this federation session.
            current=row(conn,bindings,key)
            if (not current or current['generation']!=data['generation'] or current['tunnel_id']!=ids['tunnel_id']
                or current['federation_session_id']!=ids['federation_session_id']):
                raise ControlError(410,'terminated')
            if original:
                pid,expiry,cap=original['id'],original['expires_at'],original['remaining_ttl_ms']
            else:
                pid=uid()
                expiry=min(now()+30,federation['expires_at'],session['expires_at'],grant['valid_until'] if grant['valid_until'] is not None else session['expires_at'])
                cap=30000
            # Integer floor, original expiry and persisted cap: retries never increase.
            current_deadline=min(expiry,federation['expires_at'],session['expires_at'],grant['valid_until'] if grant['valid_until'] is not None else session['expires_at'])
            remaining=min(cap,30000,(current_deadline*1_000_000_000-time.time_ns())//1_000_000)
            if remaining<=0: raise ControlError(410,'terminated')
            if original:
                conn.execute(permits.update().where(permits.c.id==pid).values(remaining_ttl_ms=remaining))
            else:
                conn.execute(permits.insert().values(id=pid,node_id=node['id'],**binding,epochs=epochs,expires_at=expiry,remaining_ttl_ms=remaining,state='issued'))
            return dict(schema=1,permit_id=show(pid),request_id=data['request_id'],epochs=epochs,expires_at=expiry,remaining_ttl_ms=remaining)
