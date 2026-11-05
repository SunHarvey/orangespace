"""Real MySQL; approved mapping is an explicit seed, not remote node access."""
import secrets
from uuid import uuid4
from test_control_auth import control, login
from sqlalchemy import select, func
from orangespace_control.schema_v1 import nodes, mappings, grants, sessions
from orangespace_control.security import uid, canonical, now
from orangespace_control.enrollment import digest

ISSUE='/control/v1/node-exchanges'
CONSUME='/control/v1/internal/node-exchanges/consume'

def setup(control):
    client,engine,name,password,admin,_=control
    # Isolated schema fixture: reset login buckets between seeded cases only.
    from orangespace_control.schema_v1 import rates
    with engine.begin() as c:
        c.execute(rates.delete())
    logged,user=login(client,name,password)
    nid,mid,gid,legacy=uid(),uid(),uid(),uid()
    machine=secrets.token_urlsafe(32)
    with engine.begin() as c:
        c.execute(nodes.insert().values(id=nid,alias=uuid4().hex,display_name='fixture',api_origin='https://fixture.test',tls_server_name='fixture.test',public_key=b'p'*32,key_fingerprint=b'k'*32,machine_token_digest=digest(b'node-machine',machine),state='active',node_epoch=1,config_revision=1))
        c.execute(mappings.insert().values(id=mid,node_id=nid,legacy_user_id=legacy,central_user_id=canonical(admin['central_user_id']),state='approved',mapping_epoch=1,evidence_digest=b'e'*32,reason='explicit approved mapping fixture'))
        c.execute(grants.insert().values(id=gid,user_id=canonical(admin['central_user_id']),node_id=nid,enabled=True,grant_epoch=1,scopes=['files.read'],valid_until=now()+90))
    payload=dict(schema=1,node_id=str(__import__('uuid').UUID(bytes=nid)),expected_epochs=dict(user_epoch=1,node_epoch=1,mapping_epoch=1,grant_epoch=1))
    return client,engine,user,{'Authorization':'Bearer '+machine},payload,legacy,gid,logged

def test_exchange_roundtrip(control):
    client,engine,user,machine,payload,legacy,gid,logged=setup(control)
    assert client.post(ISSUE,json=payload).status_code==401
    r=client.post(ISSUE,headers=user,json=payload)
    assert r.status_code==201,r.text
    ticket=r.json()
    assert now()<ticket['expires_at']<=now()+30
    request=dict(schema=1,exchange_id=ticket['exchange_id'],exchange_token=ticket['exchange_token'],request_id=str(uuid4()))
    assert client.post(CONSUME,headers=user,json=request).status_code==401
    r=client.post(CONSUME,headers=machine,json=request)
    assert r.status_code==200,r.text
    dto=r.json()
    assert dto['federation']['legacy_user_id']==str(__import__('uuid').UUID(bytes=legacy))
    assert client.post(CONSUME,headers=machine,json=request).json()==dto
    assert client.post(CONSUME,headers=machine,json=dict(request,request_id=str(uuid4()))).status_code==409
    with engine.begin() as c:
        c.execute(grants.update().where(grants.c.id==gid).values(enabled=False,grant_epoch=2))
    assert client.post(CONSUME,headers=machine,json=request).status_code==410


def test_strict_domains_snapshot_expiry_and_concurrency(control):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from fastapi.testclient import TestClient
    from orangespace_control.exchange_schema import exchanges, federations
    client,engine,user,machine,payload,legacy,gid,logged=setup(control)
    for bad in (True,1.0,0):
        epochs=dict(payload['expected_epochs'],node_epoch=bad)
        assert client.post(ISSUE,headers=user,json=dict(payload,expected_epochs=epochs)).status_code==422
    assert client.post(ISSUE,headers=user,json=dict(payload,extra=1)).status_code==422
    raw=__import__('json').dumps(payload).replace('"schema": 1','"schema": 1,"schema": 1')
    assert client.post(ISSUE,headers=user,content=raw).status_code==422
    assert client.post(ISSUE,headers=user,json=dict(payload,expected_epochs=dict(payload['expected_epochs'],node_epoch=2))).status_code==409
    assert client.post(ISSUE,headers=machine,json=payload).status_code==401
    ticket=client.post(ISSUE,headers=user,json=payload).json()
    request=dict(schema=1,exchange_id=ticket['exchange_id'],exchange_token=ticket['exchange_token'],request_id=str(uuid4()))
    other=setup(control)[3]
    assert client.post(CONSUME,headers=other,json=request).status_code==401
    barrier=Barrier(2)
    def consume(rid):
        # Independent TestClient contexts each own a distinct ASGI event-loop portal.
        with TestClient(client.app,raise_server_exceptions=False) as portal:
            barrier.wait(timeout=10)
            return portal.post(CONSUME,headers=machine,json=dict(request,request_id=rid))
    ids=[str(uuid4()),str(uuid4())]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(consume,ids))
    assert sorted(r.status_code for r in results)==[200,409]
    winner=next(i for i,r in enumerate(results) if r.status_code==200)
    dto=results[winner].json()
    assert dto['federation']['expires_at']>ticket['expires_at']
    with engine.connect() as c:
        assert c.scalar(select(func.count()).select_from(federations).where(federations.c.exchange_id==canonical(ticket['exchange_id'])))==1
    retry=dict(request,request_id=ids[winner])
    assert client.post(CONSUME,headers=machine,json=retry).json()==dto
    with engine.begin() as c:
        c.execute(exchanges.update().where(exchanges.c.id==canonical(ticket['exchange_id'])).values(expires_at=now()-1))
    assert client.post(CONSUME,headers=machine,json=retry).status_code==410


def test_authority_changes_deny_cached_result(control):
    from orangespace_control.schema_v1 import users
    for target,change in [('session',{'revoked_at':now()}),('node',{'config_revision':2}),('node',{'public_key':b'x'*32}),('node',{'node_epoch':2}),('mapping',{'mapping_epoch':2}),('mapping',{'state':'revoked'}),('grant',{'valid_until':now()-1}),('user',{'enabled':False})]:
        client,engine,user,machine,payload,legacy,gid,logged=setup(control)
        ticket=client.post(ISSUE,headers=user,json=payload).json()
        req=dict(schema=1,exchange_id=ticket['exchange_id'],exchange_token=ticket['exchange_token'],request_id=str(uuid4()))
        assert client.post(CONSUME,headers=machine,json=req).status_code==200
        table,condition={
          'session':(sessions,sessions.c.id==canonical(logged['central_session_id'])),
          'node':(nodes,nodes.c.id==canonical(payload['node_id'])),
          'mapping':(mappings,mappings.c.node_id==canonical(payload['node_id'])),
          'grant':(grants,grants.c.id==gid),
          'user':(users,users.c.id==canonical(logged['user']['central_user_id']))}[target]
        with engine.begin() as c:
            old=c.execute(select(table).where(condition)).mappings().one()
            c.execute(table.update().where(condition).values(**change))
        assert client.post(CONSUME,headers=machine,json=req).status_code in (401,410)
        # Restore fixture admin only to enable next isolated case login.
        if target=='user':
            with engine.begin() as c:c.execute(users.update().where(condition).values(enabled=True))
