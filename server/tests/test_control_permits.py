"""Real MySQL authority; ASGI only, not forwarding evidence."""
from uuid import uuid4
from test_control_auth import control
from test_control_exchange import setup, ISSUE, CONSUME
from orangespace_control.schema_v1 import grants
from orangespace_control.security import now

PERMIT='/control/v1/internal/lease-permits'

def prepared(control):
    c,e,u,m,p,legacy,g,l=setup(control)
    with e.begin() as db:
        db.execute(grants.update().where(grants.c.id==g).values(scopes=['tunnel']))
    t=c.post(ISSUE,headers=u,json=p)
    assert t.status_code==201
    t=t.json()
    r=c.post(CONSUME,headers=m,json=dict(schema=1,exchange_id=t['exchange_id'],exchange_token=t['exchange_token'],request_id=str(uuid4())))
    assert r.status_code==200
    f=r.json()['federation']
    b=dict(schema=1,request_id=str(uuid4()),federation_session_id=f['federation_session_id'],tunnel_id=str(uuid4()),sandbox_id=str(uuid4()),generation=1,operation='create',expected_epochs=f['epochs'])
    return c,e,u,m,b,g,l

def test_permit_issue_original_deadline_idempotency_tuple_conflict(control):
    c,e,u,m,b,g,l=prepared(control)
    r=c.post(PERMIT,headers=m,json=b)
    assert r.status_code==200
    a=r.json()
    assert set(a)=={'schema','permit_id','request_id','epochs','expires_at','remaining_ttl_ms'}
    assert a['request_id']==b['request_id'] and a['epochs']==b['expected_epochs']
    assert now()<a['expires_at']<=now()+30
    assert 0<a['remaining_ttl_ms']<=30000
    retry=c.post(PERMIT,headers=m,json=b)
    assert retry.status_code==200
    z=retry.json()
    assert {k:v for k,v in z.items() if k!='remaining_ttl_ms'}=={k:v for k,v in a.items() if k!='remaining_ttl_ms'}
    assert 0<z['remaining_ttl_ms']<=a['remaining_ttl_ms']
    for change in ({'tunnel_id':str(uuid4())},{'sandbox_id':str(uuid4())},{'generation':2},{'operation':'renew'}):
        assert c.post(PERMIT,headers=m,json=dict(b,**change)).status_code==409
    renewed=c.post(PERMIT,headers=m,json=dict(b,request_id=str(uuid4()),operation='renew'))
    assert renewed.status_code==200
    assert renewed.json()['permit_id']!=a['permit_id']


def test_retry_current_authority_deadline_can_only_reduce_budget(control):
    c,e,u,m,b,g,l=prepared(control)
    first=c.post(PERMIT,headers=m,json=b)
    assert first.status_code==200
    original=first.json()
    with e.begin() as db:
        db.execute(grants.update().where(grants.c.id==g).values(valid_until=now()+2))
    r=c.post(PERMIT,headers=m,json=b)
    assert r.status_code==200
    assert r.json()['expires_at']==original['expires_at']
    assert 0<r.json()['remaining_ttl_ms']<=2000


def test_strict_domain_and_revoked_retry_no_new_rows(control):
    import json
    c,e,u,m,b,g,l=prepared(control)
    assert c.post(PERMIT,headers=u,json=b).status_code==401
    assert c.post(PERMIT,json=b).status_code==401
    for key,value in [('generation',True),('generation',1.0),('generation',0),('generation',9007199254740992),('tunnel_id',b['tunnel_id'].upper()),('sandbox_id','00000000-0000-0000-0000-000000000000'),('operation','unknown'),('extra',1)]:
        assert c.post(PERMIT,headers=m,json=dict(b,**{key:value})).status_code==422
    raw=json.dumps(b).replace('"schema": 1','"schema": 1,"schema": 1')
    assert c.post(PERMIT,headers=m,content=raw).status_code==422
    assert c.post(PERMIT,headers=m,json=dict(b,expected_epochs=dict(b['expected_epochs'],user_epoch=True))).status_code==422
    assert c.post(PERMIT,headers=m,json=dict(b,expected_epochs=dict(b['expected_epochs'],user_epoch=2))).status_code==409
    with e.begin() as db:
        db.execute(grants.update().where(grants.c.id==g).values(scopes=['files.read']))
    assert c.post(PERMIT,headers=m,json=b).status_code==403
    with e.begin() as db:
        db.execute(grants.update().where(grants.c.id==g).values(scopes=['tunnel']))
    assert c.post(PERMIT,headers=m,json=b).status_code==200
    with e.begin() as db:
        db.execute(grants.update().where(grants.c.id==g).values(enabled=False,grant_epoch=2))
    assert c.post(PERMIT,headers=m,json=b).status_code==410
    assert c.post(PERMIT,headers=m,json=dict(b,request_id=str(uuid4()))).status_code==410


def test_two_independent_portals_same_request_exactly_one_result(control):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from fastapi.testclient import TestClient
    from sqlalchemy import select, func
    from orangespace_control.permit_schema import permits
    from orangespace_control.security import canonical
    c,e,u,m,b,g,l=prepared(control)
    barrier=Barrier(2)
    def run(_):
        with TestClient(c.app,raise_server_exceptions=False) as portal:
            barrier.wait(timeout=10)
            return portal.post(PERMIT,headers=m,json=b)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(run,range(2)))
    assert [r.status_code for r in results]==[200,200]
    assert results[0].json()['permit_id']==results[1].json()['permit_id']
    with e.connect() as db:
        assert db.scalar(select(func.count()).select_from(permits).where(permits.c.request_id==canonical(b['request_id'])))==1


def test_revoke_authority_lock_precedes_queued_permit(control):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from fastapi.testclient import TestClient
    from sqlalchemy import event, select, func
    from orangespace_control.schema_v1 import sessions
    from orangespace_control.permit_schema import permits
    from orangespace_control.security import authority_lock, canonical
    c,e,u,m,b,g,l=prepared(control)
    waiting=Event()
    def observed(conn,cursor,statement,parameters,context,executemany):
        if 'control_locks' in statement and 'FOR UPDATE' in statement: waiting.set()
    def run():
        with TestClient(c.app,raise_server_exceptions=False) as portal:
            return portal.post(PERMIT,headers=m,json=b)
    with ThreadPoolExecutor(max_workers=1) as pool:
        with e.begin() as db:
            authority_lock(db)
            event.listen(e,'before_cursor_execute',observed)
            future=pool.submit(run)
            try:
                assert waiting.wait(timeout=10)
                assert not future.done()
                db.execute(sessions.update().where(sessions.c.id==canonical(l['central_session_id'])).values(revoked_at=now()))
            finally:
                event.remove(e,'before_cursor_execute',observed)
        assert future.result(timeout=15).status_code==410
    with e.connect() as db:
        assert db.scalar(select(func.count()).select_from(permits).where(permits.c.request_id==canonical(b['request_id'])))==0
