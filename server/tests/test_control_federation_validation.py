"""Real MySQL online identity checks; DB expiry controls are not natural waits."""
from uuid import uuid4
import pytest
from test_control_auth import control
from test_control_exchange import setup, ISSUE, CONSUME
from orangespace_control.schema_v1 import sessions, grants, nodes, mappings, users
from orangespace_control.exchange_schema import exchanges, federations
from orangespace_control.security import canonical, now

VALIDATE='/control/v1/internal/federation-sessions/validate'

def issued(control, cap='grant'):
    client,engine,user,machine,payload,legacy,gid,logged=setup(control)
    stamp=now()
    session_end=stamp+120 if cap=='session' else logged['expires_at']
    grant_end=stamp+180 if cap=='session' else (None if cap=='none' else stamp+90)
    with engine.begin() as c:
        c.execute(sessions.update().where(sessions.c.id==canonical(logged['central_session_id'])).values(expires_at=session_end))
        c.execute(grants.update().where(grants.c.id==gid).values(valid_until=grant_end))
    t=client.post(ISSUE,headers=user,json=payload)
    assert t.status_code==201,t.text
    t=t.json()
    # Deterministic authority extension after issue: cannot extend frozen identity.
    with engine.begin() as c:
        c.execute(grants.update().where(grants.c.id==gid).values(valid_until=stamp+7200))
        c.execute(sessions.update().where(sessions.c.id==canonical(logged['central_session_id'])).values(expires_at=session_end+600))
    req=dict(schema=1,exchange_id=t['exchange_id'],exchange_token=t['exchange_token'],request_id=str(uuid4()))
    r=client.post(CONSUME,headers=machine,json=req)
    assert r.status_code==200,r.text
    f=r.json()['federation']
    v=dict(schema=1,federation_session_id=f['federation_session_id'],expected_epochs=payload['expected_epochs'],required_scope='files.read')
    return client,engine,user,machine,payload,gid,logged,t,req,f,v,min(session_end,grant_end or session_end)

@pytest.mark.parametrize('cap',['session','grant','none'])
def test_identity_deadline_is_frozen_independently_of_ticket(control,cap):
    c,e,u,m,p,g,l,t,r,f,v,deadline=issued(control,cap)
    assert now()<t['expires_at']<=now()+30
    assert f['expires_at']==deadline
    assert f['expires_at']>t['expires_at']
    assert c.post(CONSUME,headers=m,json=r).json()['federation']==f
    # Deterministic DB time negative control, not a natural 30-second wait.
    with e.begin() as db:
        db.execute(exchanges.update().where(exchanges.c.id==canonical(t['exchange_id'])).values(expires_at=now()-1))
    assert c.post(CONSUME,headers=m,json=r).status_code==410
    response=c.post(VALIDATE,headers=m,json=v)
    assert response.status_code==200,response.text
    assert response.json()==dict(schema=1,federation=f,scopes=['files.read'])
    assert response.headers['cache-control']=='no-store'


def test_validation_route_strict_identity_and_scope(control):
    c,e,u,m,p,g,l,t,r,f,v,_=issued(control)
    response=c.post(VALIDATE,headers=m,json=v)
    assert response.status_code==200,response.text
    assert c.post(VALIDATE,headers=u,json=v).status_code==401
    other=setup(control)[3]
    assert c.post(VALIDATE,headers=other,json=v).status_code==401
    assert c.post(VALIDATE,headers=m,json=dict(v,required_scope='tunnel')).status_code==403
    for field in ('schema','expected_epochs'):
        for bad in (True,1.0):
            data=dict(v)
            data[field]=bad if field=='schema' else dict(v[field],user_epoch=bad)
            assert c.post(VALIDATE,headers=m,json=data).status_code==422
    assert c.post(VALIDATE,headers=m,json=dict(v,extra=1)).status_code==422
    assert c.post(VALIDATE,headers=m,json=dict(v,expected_epochs=dict(v['expected_epochs'],extra=1))).status_code==422
    raw=__import__('json').dumps(v).replace('"schema": 1','"schema": 1,"schema": 1')
    assert c.post(VALIDATE,headers=m,content=raw).status_code==422
    assert c.post(VALIDATE,headers=m,json=dict(v,required_scope='unknown')).status_code==422
    assert c.post(VALIDATE,headers=m,json=dict(v,expected_epochs=dict(v['expected_epochs'],node_epoch=2))).status_code==409

@pytest.mark.parametrize('target,change',[
 ('grant',{'grant_epoch':2,'scopes':['files.read','tunnel']}),
 ('grant',{'grant_epoch':2,'enabled':False}),
 ('grant',{'valid_until':0}),('session',{'revoked_at':1}),
 ('session',{'expires_at':1}),('user',{'user_epoch':2}),
 ('node',{'config_revision':2}),('node',{'public_key':b'x'*32}),
 ('node',{'key_fingerprint':b'x'*32}),('node',{'machine_token_digest':b'x'*32}),
 ('mapping',{'mapping_epoch':2}),('mapping',{'state':'revoked'}),
 ('federation',{'expires_at':1})])
def test_validation_rechecks_authority_each_call(control,target,change):
    c,e,u,m,p,g,l,t,r,f,v,_=issued(control)
    assert c.post(VALIDATE,headers=m,json=v).status_code==200
    table,condition={
      'grant':(grants,grants.c.id==g),
      'session':(sessions,sessions.c.id==canonical(l['central_session_id'])),
      'user':(users,users.c.id==canonical(l['user']['central_user_id'])),
      'node':(nodes,nodes.c.id==canonical(p['node_id'])),
      'mapping':(mappings,mappings.c.id==canonical(f['mapping_id'])),
      'federation':(federations,federations.c.id==canonical(f['federation_session_id']))}[target]
    with e.begin() as db: db.execute(table.update().where(condition).values(**change))
    try:
        assert c.post(VALIDATE,headers=m,json=v).status_code in (401,410)
    finally:
        if target=='user':
            with e.begin() as db: db.execute(users.update().where(condition).values(user_epoch=1))
