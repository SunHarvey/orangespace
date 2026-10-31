"""Online node federation. No cached authority or forwarding permits."""
import hashlib
import json
import os
import re
import secrets
import stat
import time
from uuid import UUID, uuid5, NAMESPACE_URL
from urllib.parse import urlsplit
import httpx
from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, StrictInt, StrictStr, field_validator
from sqlalchemy import MetaData, Table, Column, String, JSON, ForeignKey, select
from sqlalchemy.exc import IntegrityError
from .auth import authenticate, digest_token
from .database import AccessSession, User
from .control_identity import validate as validate_machine

metadata = MetaData()
# References use actual v1 table objects; v1 metadata remains frozen.
bindings = Table('federation_bindings', metadata,
    Column('exchange_id', String(36), primary_key=True),
    Column('token_digest', String(64), ForeignKey(AccessSession.__table__.c.token_digest, ondelete='RESTRICT'), unique=True, nullable=False),
    Column('cleanup_digest', String(64), nullable=False),
    Column('federation', JSON, nullable=False),
    mysql_engine='InnoDB', mysql_charset='utf8mb4', mysql_collate='utf8mb4_0900_bin')


def unique(pairs):
    out = {}
    for k,v in pairs:
        if k in out: raise ValueError('duplicate JSON member')
        out[k]=v
    return out


def canonical(v):
    if type(v) is not str: raise ValueError('invalid UUID')
    parsed = UUID(v)
    if not parsed.int or str(parsed) != v: raise ValueError('invalid UUID')
    return v


class ExchangeBody(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    schema: StrictInt
    exchange_id: StrictStr
    exchange_token: StrictStr

    @field_validator('schema')
    @classmethod
    def schema_one(cls,v):
        if v != 1: raise ValueError('schema')
        return v

    @field_validator('exchange_id')
    @classmethod
    def identifier(cls,v): return canonical(v)

    @field_validator('exchange_token')
    @classmethod
    def credential(cls,v):
        if not re.fullmatch('[A-Za-z0-9_-]{43}',v): raise ValueError('token')
        return v


def load_config(path,node_id):
    fd=None
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        s=os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.geteuid() or s.st_mode&0o077 or s.st_nlink!=1 or s.st_size>16384: raise ValueError()
        with os.fdopen(fd) as f:
            fd=None
            data=json.load(f,object_pairs_hook=unique)
        if set(data)!={'origin','token','node_id','node_epoch','config_revision','node_api_origin'}: raise ValueError()
        validate_machine(data)
        if data['node_id']!=str(node_id): raise ValueError()
        origin=data['node_api_origin']; p=urlsplit(origin)
        if p.scheme!='https' or not p.hostname or p.username or p.password or p.query or p.fragment or p.path not in ('','/nodes/'+str(node_id)) or origin!='https://'+p.netloc+p.path or any(ord(c)<=32 for c in origin): raise ValueError()
        return data
    except Exception:
        raise ValueError('invalid protected federation configuration') from None
    finally:
        if fd is not None: os.close(fd)


def checked_federation(value, config):
    keys={'federation_session_id','central_session_id','central_user_id','node_id','legacy_user_id','mapping_id','grant_id','epochs','expires_at'}
    if type(value) is not dict or set(value)!=keys: raise ValueError()
    for k in keys-{'epochs','expires_at'}: canonical(value[k])
    epochs=value['epochs']
    if type(epochs) is not dict or set(epochs)!={'user_epoch','node_epoch','mapping_epoch','grant_epoch'} or any(type(v) is not int or not 1<=v<=9007199254740991 for v in epochs.values()): raise ValueError()
    # Centre owns the issuance bound; retain its authenticated absolute deadline.
    # The node only vetoes malformed, unsafe or already elapsed deadlines.
    if value['node_id']!=config['node_id'] or epochs['node_epoch']!=config['node_epoch'] or type(value['expires_at']) is not int or not 1<=value['expires_at']<=9007199254740991 or value['expires_at']<=time.time(): raise ValueError()
    return value


class Federation:
    def __init__(self,config,database):
        self.config=config
        self.db=database

    def _post(self,route,data):
        with httpx.Client(verify=True,follow_redirects=False,trust_env=False,timeout=10) as client:
            return client.post(self.config['origin']+route,json=data,headers={'Authorization':'Bearer '+self.config['token']})

    def remote(self,route,data,validate=False):
        try:
            r=self._post('/control/v1/internal/'+route,data)
            if r.status_code!=200:
                raise HTTPException(r.status_code if r.status_code in (401,403,409,410) else 503,'federation authorization denied')
            dto=json.loads(r.content,object_pairs_hook=unique)
            if type(dto) is not dict or set(dto)!=({'schema','federation','scopes'} if validate else {'schema','federation'}) or type(dto['schema']) is not int or dto['schema']!=1: raise ValueError()
            checked_federation(dto['federation'],self.config)
            if validate and (type(dto['scopes']) is not list or not dto['scopes'] or any(type(s) is not str or s not in ('files.read','files.write','tunnel') for s in dto['scopes']) or len(dto['scopes'])!=len(set(dto['scopes']))): raise ValueError()
            return dto
        except HTTPException: raise
        except Exception: raise HTTPException(503,'federation service unavailable') from None

    def permit(self, current, body, operation, budget):
        """Consume one online permit without holding a manager/database lock."""
        from uuid import uuid4
        with self.db.session() as s:
            row=s.execute(select(bindings).where(bindings.c.token_digest==current.token_digest)).mappings().first()
            if row is None: raise HTTPException(401,'federated credential required')
            f=checked_federation(row['federation'],self.config)
        rid=str(uuid4())
        data=dict(schema=1,request_id=rid,federation_session_id=f['federation_session_id'],
                  tunnel_id=body.tunnel_id,sandbox_id=body.sandbox_id,generation=body.generation,
                  operation=operation,expected_epochs=f['epochs'])
        anchor=time.monotonic()
        try:
            r=self._post('/control/v1/internal/lease-permits',data)
            if r.status_code!=200:
                raise HTTPException(r.status_code if r.status_code in (401,403,409,410) else 503,'lease permit denied')
            dto=json.loads(r.content,object_pairs_hook=unique)
            if type(dto) is not dict or set(dto)!={'schema','permit_id','request_id','epochs','expires_at','remaining_ttl_ms'}: raise ValueError()
            if type(dto['schema']) is not int or dto['schema']!=1: raise ValueError()
            canonical(dto['permit_id']); canonical(dto['request_id'])
            if dto['request_id']!=rid: raise ValueError()
            epochs=dto['epochs']
            if type(epochs) is not dict or set(epochs)!=set(f['epochs']) or any(type(v) is not int or not 1<=v<=9007199254740991 for v in epochs.values()) or epochs!=f['epochs']: raise ValueError()
            if type(dto['remaining_ttl_ms']) is not int or not 1<=dto['remaining_ttl_ms']<=30000: raise ValueError()
            if type(dto['expires_at']) is not int or not 1<=dto['expires_at']<=9007199254740991: raise ValueError()
            mono=time.monotonic(); wall=time.time()
            deadline=min(budget,anchor+dto['remaining_ttl_ms']/1000,anchor+30,
                         mono+min(dto['expires_at'],f['expires_at'],current.expires_at)-wall)
            if deadline-mono<0.001: raise ValueError()
            return deadline
        except HTTPException: raise
        except Exception: raise HTTPException(503,'lease permit unavailable') from None

    def cleanup_digest(self,b):
        return hashlib.sha256(('node-exchange-cleanup\0'+self.config['node_id']+'\0'+b.exchange_id+'\0'+b.exchange_token).encode()).hexdigest()

    def exchange(self,b):
        with self.db.session() as s:
            if s.execute(select(bindings).where(bindings.c.exchange_id==b.exchange_id)).first(): raise HTTPException(409,'exchange already delivered')
        # Stable request identity binds this node and exact exchange across crashes.
        rid=str(uuid5(NAMESPACE_URL,'orangespace-node-exchange:'+self.config['node_id']+':'+b.exchange_id))
        f=self.remote('node-exchanges/consume',dict(schema=1,exchange_id=b.exchange_id,exchange_token=b.exchange_token,request_id=rid))['federation']
        token=secrets.token_urlsafe(32)
        try:
            with self.db.session() as s:
                u=s.get(User,f['legacy_user_id'],with_for_update=True)
                if u is None or not u.enabled: raise HTTPException(401,'local identity unavailable')
                d=digest_token(token)
                s.add(AccessSession(token_digest=d,user_id=u.id,expires_at=f['expires_at']))
                s.flush()
                s.execute(bindings.insert().values(exchange_id=b.exchange_id,token_digest=d,cleanup_digest=self.cleanup_digest(b),federation=f))
        except IntegrityError: raise HTTPException(409,'exchange already delivered') from None
        return dict(schema=1,federation=f,node_credential=dict(schema=1,node_id=self.config['node_id'],api_origin=self.config['node_api_origin'],access_token=token,expires_at=f['expires_at']))

    def cleanup(self,b):
        with self.db.session() as s:
            row=s.execute(select(bindings).where(bindings.c.exchange_id==b.exchange_id).with_for_update()).mappings().first()
            if row is None or not secrets.compare_digest(row['cleanup_digest'],self.cleanup_digest(b)): raise HTTPException(401,'unknown exchange')
            a=s.get(AccessSession,row['token_digest'],with_for_update=True)
            if a is None: raise HTTPException(410,'local session absent')
            a.revoked_at=int(time.time())
        return dict(schema=1,local_session_state='revoked')

    def authenticate(self,token,scope):
        current=authenticate(self.db,token)
        if current is None: raise HTTPException(401,'authentication required')
        with self.db.session() as s:
            row=s.execute(select(bindings).where(bindings.c.token_digest==current.token_digest)).mappings().first()
            if row is None: raise HTTPException(401,'federated credential required')
            f=row['federation']
        dto=self.remote('federation-sessions/validate',dict(schema=1,federation_session_id=f['federation_session_id'],expected_epochs=f['epochs'],required_scope=scope),True)
        if dto['federation']!=f or (scope is not None and scope not in dto['scopes']): raise HTTPException(403,'federation authorization denied')
        # Local revocation/disable remains an extra veto after online IO.
        result=authenticate(self.db,token)
        if result is None: raise HTTPException(401,'authentication required')
        return result
