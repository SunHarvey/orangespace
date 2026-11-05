"""Inventory evidence only; no provisioning, permits or revocation consumers."""
import hashlib
import json
import re
from fastapi import Request
from sqlalchemy import select
from .schema_v1 import nodes, mappings, users
from .identity_schema import evidence
from .security import ControlError, authority_lock, now, uid, show, record_audit
from .enrollment import decode, digest


def install_routes(app, engine, body, auth, page, identity):
    def hex_digest(value):
        if not isinstance(value,str) or not re.fullmatch('[0-9a-f]{64}',value):
            raise ControlError(422,'invalid_input')
        return bytes.fromhex(value)

    def reason(data):
        if not isinstance(data['reason'],str) or not 1 <= len(data['reason'].strip()) <= 512:
            raise ControlError(422,'invalid_input')

    def trusted(conn,nid,legacy,proof):
        node = conn.execute(select(nodes).where(nodes.c.id==nid).with_for_update()).mappings().first()
        row = conn.execute(select(evidence).where(evidence.c.digest==proof,evidence.c.node_id==nid,evidence.c.legacy_user_id==legacy).with_for_update()).mappings().first()
        if not node or not row or node['state']!='active' or row['expires_at']<=now() or any(row[k]!=node[k] for k in ('public_key','key_fingerprint','node_epoch','config_revision')):
            raise ControlError(409,'untrusted_evidence')
        return row

    def dto(row):
        return dict(schema=1,mapping_id=show(row['id']),node_id=show(row['node_id']),legacy_user_id=show(row['legacy_user_id']),central_user_id=show(row['central_user_id']),state=row['state'],mapping_epoch=row['mapping_epoch'],evidence_digest=row['evidence_digest'].hex())

    @app.post('/control/v1/internal/identity-evidence',status_code=201)
    async def submit(request: Request):
        data = await body(request,{'node_id','node_epoch','config_revision','legacy_user_id','request_id'})
        nid,legacy,rid = (identity(data[k]) for k in ('node_id','legacy_user_id','request_id'))
        for k in ('node_epoch','config_revision'):
            if type(data[k]) is not int or not 1<=data[k]<=9007199254740991:
                raise ControlError(422,'invalid_input')
        header = request.headers.get('authorization','')
        if not header.startswith('Bearer '):
            raise ControlError(401,'unauthenticated')
        token = header[7:]
        decode(token,32)
        with engine.begin() as conn:
            authority_lock(conn)
            node = conn.execute(select(nodes).where(nodes.c.machine_token_digest==digest(b'node-machine',token)).with_for_update()).mappings().first()
            if not node or node['id']!=nid or node['state']!='active' or node['public_key'] is None or any(node[k]!=data[k] for k in ('node_epoch','config_revision')):
                raise ControlError(401,'unauthenticated')
            row = conn.execute(select(evidence).where(evidence.c.node_id==nid,evidence.c.request_id==rid).with_for_update()).mappings().first()
            if row:
                if row['legacy_user_id']!=legacy or any(row[k]!=node[k] for k in ('public_key','key_fingerprint','node_epoch','config_revision')):
                    raise ControlError(409,'conflict')
            else:
                row = dict(id=uid(),node_id=nid,legacy_user_id=legacy,request_id=rid,created_at=now(),**{k:node[k] for k in ('public_key','key_fingerprint','node_epoch','config_revision')})
                row['expires_at']=row['created_at']+120
                canonical = {k:(v.hex() if isinstance(v,bytes) else v) for k,v in row.items()}
                row['digest']=hashlib.sha256(b'OrangeSpace-identity-evidence-v1\0'+json.dumps(canonical,sort_keys=True,separators=(',',':')).encode()).digest()
                conn.execute(evidence.insert().values(**row))
            return dict(schema=1,evidence_digest=row['digest'].hex(),expires_at=row['expires_at'])

    @app.get('/control/v1/admin/identity-mappings')
    async def listing(request: Request):
        limit,cursor,_ = page(request)
        with engine.begin() as conn:
            auth(conn,request,True)
            query=select(mappings)
            if cursor is not None: query=query.where(mappings.c.id>cursor)
            rows=conn.execute(query.order_by(mappings.c.id).limit(limit+1)).mappings().all()
            return dict(schema=1,items=[dto(r) for r in rows[:limit]],next_cursor=show(rows[limit-1]['id']) if len(rows)>limit else None)

    @app.post('/control/v1/admin/identity-mappings',status_code=201)
    async def propose(request: Request):
        data=await body(request,{'central_user_id','node_id','legacy_user_id','evidence_digest','reason'})
        nid,legacy,central=(identity(data[k]) for k in ('node_id','legacy_user_id','central_user_id'))
        proof=hex_digest(data['evidence_digest']);reason(data)
        with engine.begin() as conn:
            actor,_=auth(conn,request,True)
            trusted(conn,nid,legacy,proof)
            if not conn.execute(select(users.c.id).where(users.c.id==central,users.c.enabled.is_(True))).first():
                raise ControlError(404,'not_found')
            row=dict(id=uid(),node_id=nid,legacy_user_id=legacy,central_user_id=central,state='pending',mapping_epoch=1,evidence_digest=proof,reason=data['reason'])
            conn.execute(mappings.insert().values(**row))
            record_audit(conn,actor['id'],'mapping.propose',row['id'],None,1,data['reason'],request.state.request_id)
            return dto(row)

    @app.post('/control/v1/admin/identity-mappings/{mid}/approve')
    async def approve(mid: str,request: Request):
        data=await body(request,{'expected_mapping_epoch','evidence_digest','reason'})
        target=identity(mid);proof=hex_digest(data['evidence_digest']);reason(data)
        expected=data['expected_mapping_epoch']
        if type(expected) is not int or not 1<=expected<9007199254740991:
            raise ControlError(422,'invalid_input')
        with engine.begin() as conn:
            actor,_=auth(conn,request,True)
            row=conn.execute(select(mappings).where(mappings.c.id==target).with_for_update()).mappings().first()
            if not row: raise ControlError(404,'not_found')
            if row['state']!='pending' or row['mapping_epoch']!=expected or row['evidence_digest']!=proof:
                raise ControlError(409,'conflict')
            trusted(conn,row['node_id'],row['legacy_user_id'],proof)
            result=conn.execute(mappings.update().where(mappings.c.id==target,mappings.c.mapping_epoch==expected,mappings.c.state=='pending').values(state='approved',mapping_epoch=expected+1,approved_by=actor['id'],reason=data['reason']))
            if result.rowcount!=1: raise ControlError(409,'conflict')
            record_audit(conn,actor['id'],'mapping.approve',target,expected,expected+1,data['reason'],request.state.request_id)
            return dto(dict(row,state='approved',mapping_epoch=expected+1))
