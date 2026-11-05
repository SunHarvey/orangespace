"""Real MySQL inventory-to-approval slice; ASGI is not remote deployment."""
from uuid import uuid4
from test_control_auth import control, login
from test_control_enrollment import registration_case, completion


def test_inventory_approval(control):
    client, engine, key, creation, enrollment, root, request = registration_case(control)
    challenge = client.post(root+'/challenge', json=request).json()
    machine = client.post(root+'/complete', json=completion(key, creation, enrollment, challenge)).json()
    _, admin = login(client, control[2], control[3])
    nid = creation['node_id']
    bearer = {'Authorization':'Bearer '+machine['node_access_token']}
    client.post('/control/v1/admin/nodes/'+nid+'/activate', headers=admin, json=dict(schema=1,expected_node_epoch=1,expected_config_revision=1,reason='verified'))
    legacy = str(uuid4())
    evidence = dict(schema=1,node_id=nid,node_epoch=1,config_revision=1,legacy_user_id=legacy,request_id=str(uuid4()))
    path = '/control/v1/internal/identity-evidence'
    assert client.post(path,headers=admin,json=evidence).status_code == 401
    assert client.post(path,headers=bearer,json=dict(evidence,node_id=str(uuid4()))).status_code == 401
    response = client.post(path,headers=bearer,json=evidence)
    assert response.status_code == 201
    proof = response.json()
    assert client.post(path,headers=bearer,json=evidence).json() == proof
    assert client.post(path,headers=bearer,json=dict(evidence,legacy_user_id=str(uuid4()))).status_code == 409
    user = client.post('/control/v1/admin/users',headers=admin,json=dict(schema=1,username='u_'+uuid4().hex[:12],password='test-password-long',role='user')).json()['user']
    proposal = dict(schema=1,node_id=nid,legacy_user_id=legacy,central_user_id=user['central_user_id'],evidence_digest='0'*64,reason='explicit selection')
    mappings = '/control/v1/admin/identity-mappings'
    assert client.post(mappings,headers=admin,json=proposal).status_code == 409
    proposal['evidence_digest'] = proof['evidence_digest']
    r = client.post(mappings,headers=admin,json=proposal)
    assert r.status_code == 201
    mapping = r.json()
    assert mapping['state'] == 'pending'
    _, user_auth = login(client,user['username'],'test-password-long')
    grant = '/control/v1/admin/users/'+user['central_user_id']+'/nodes/'+nid+'/grant'
    assert client.put(grant,headers=admin,json=dict(schema=1,expected_grant_epoch=0,enabled=True,scopes=['files.read'],valid_until=None,reason='test')).status_code == 200
    assert client.get('/control/v1/me/nodes',headers=user_auth).json()['items'] == []
    approve = dict(schema=1,expected_mapping_epoch=1,evidence_digest=proof['evidence_digest'],reason='reviewed inventory')
    assert client.post(mappings+'/'+mapping['mapping_id']+'/approve',headers=bearer,json=approve).status_code == 401
    assert client.post(mappings+'/'+mapping['mapping_id']+'/approve',headers=admin,json=approve).status_code == 200
    assert client.post(mappings+'/'+mapping['mapping_id']+'/approve',headers=admin,json=approve).status_code == 409
    rows = client.get('/control/v1/me/nodes',headers=user_auth).json()['items']
    assert len(rows) == 1 and rows[0]['legacy_user_id'] == legacy
    assert client.post(mappings,headers=admin,json=dict(proposal,central_user_id=control[4]['central_user_id'])).status_code == 409


def test_real_node_inventory_to_center_approved_catalogue(control, client, config):
    import asyncio
    import httpx
    from sqlalchemy import select
    from orangespace_node.control_identity import submit_inventory
    from orangespace_node.database import User
    center, _, key, creation, enrollment, root, request = registration_case(control, node_id=str(config.node_id))
    challenge=center.post(root+'/challenge',json=request)
    assert challenge.status_code == 200
    machine=center.post(root+'/complete',json=completion(key,creation,enrollment,challenge.json()))
    assert machine.status_code == 201
    _,admin=login(center,control[2],control[3])
    nid=creation['node_id']
    assert center.post('/control/v1/admin/nodes/'+nid+'/activate',headers=admin,json=dict(schema=1,expected_node_epoch=1,expected_config_revision=1,reason='local protocol fixture')).status_code == 200
    engine=client.app.state.database.engine
    with engine.connect() as conn:
        legacy=conn.scalar(select(User.id).where(User.username=='alice'))
    machine_config=dict(origin='https://control.example.test',token=machine.json()['node_access_token'],node_id=nid,node_epoch=1,config_revision=1)
    proof=asyncio.run(submit_inventory(engine,machine_config,legacy,str(uuid4()),transport=httpx.ASGITransport(app=center.app)))
    created=center.post('/control/v1/admin/users',headers=admin,json=dict(schema=1,username='bridge_'+uuid4().hex[:12],password='test-password-long',role='user'))
    assert created.status_code == 201
    user=created.json()['user']
    uid=user['central_user_id']
    assert center.put('/control/v1/admin/users/'+uid+'/nodes/'+nid+'/grant',headers=admin,json=dict(schema=1,expected_grant_epoch=0,enabled=True,scopes=['tunnel'],valid_until=None,reason='local bridge fixture')).status_code == 200
    pending=center.post('/control/v1/admin/identity-mappings',headers=admin,json=dict(schema=1,node_id=nid,legacy_user_id=legacy,central_user_id=uid,evidence_digest=proof['evidence_digest'],reason='explicit local inventory'))
    assert pending.status_code == 201
    _,user_auth=login(center,user['username'],'test-password-long')
    assert center.get('/control/v1/me/nodes',headers=user_auth).json()['items'] == []
    approved=center.post('/control/v1/admin/identity-mappings/'+pending.json()['mapping_id']+'/approve',headers=admin,json=dict(schema=1,expected_mapping_epoch=1,evidence_digest=proof['evidence_digest'],reason='approve actual local primary key'))
    assert approved.status_code == 200
    rows=center.get('/control/v1/me/nodes',headers=user_auth).json()['items']
    assert len(rows)==1 and rows[0]['legacy_user_id']==legacy and rows[0]['node_id']==nid
    with engine.connect() as conn:
        assert conn.scalar(select(User.id).where(User.username=='alice')) == legacy


def test_inventory_cli_queries_real_local_identity(client, config, tmp_path, monkeypatch, capsys):
    import json
    import time
    import httpx
    from sqlalchemy import select
    from orangespace_node import cli, control_identity
    from orangespace_node.database import User
    with client.app.state.database.engine.connect() as conn:
        legacy = conn.scalar(select(User.id).where(User.username == 'alice'))
    machine = dict(origin='https://control.example.test', token='A'*43,
                   node_id=str(config.node_id), node_epoch=1, config_revision=1)
    path = tmp_path/'machine.json'
    path.write_text(json.dumps(machine)); path.chmod(0o600)
    calls = []
    def handle(request):
        calls.append(json.loads(request.content))
        return httpx.Response(201, json=dict(schema=1,evidence_digest='d'*64,expires_at=int(time.time())+120))
    real_submit = control_identity.submit_inventory
    async def submit(*args, **kwargs):
        return await real_submit(*args, **kwargs, transport=httpx.MockTransport(handle))
    monkeypatch.setattr(control_identity, 'submit_inventory', submit)
    monkeypatch.setattr(cli.Settings, 'from_env', staticmethod(lambda: config))
    rid = str(uuid4())
    monkeypatch.setattr('sys.argv', ['orangespace-node','publish-identity-evidence','--machine-config',str(path),'--legacy-user-id',legacy,'--request-id',rid])
    cli.main()
    output = capsys.readouterr().out
    assert machine['token'] not in output
    assert json.loads(output)['evidence_digest'] == 'd'*64
    assert len(calls) == 1 and calls[0]['legacy_user_id'] == legacy and calls[0]['node_id'] == str(config.node_id)


def test_inventory_cli_refuses_other_node_configuration(client, config, tmp_path, monkeypatch, capsys):
    import json
    import pytest
    from orangespace_node import cli, control_identity
    path=tmp_path/'other-node.json'
    path.write_text(json.dumps(dict(origin='https://control.example.test',token='A'*43,node_id=str(uuid4()),node_epoch=1,config_revision=1)))
    path.chmod(0o600)
    calls=[]
    async def submit(*args, **kwargs):
        calls.append(True)
        return dict(schema=1,evidence_digest='d'*64,expires_at=1999999999)
    monkeypatch.setattr(control_identity,'submit_inventory',submit)
    monkeypatch.setattr(cli.Settings,'from_env',staticmethod(lambda:config))
    monkeypatch.setattr('sys.argv',['orangespace-node','publish-identity-evidence','--machine-config',str(path),'--legacy-user-id',str(uuid4()),'--request-id',str(uuid4())])
    with pytest.raises(SystemExit) as rejected:
        cli.main()
    assert rejected.value.code == 1 and calls == []
    output=capsys.readouterr()
    assert output.out == '' and output.err == 'Identity inventory submission failed.\n'


def test_local_missing_uuid_never_submits(client):
    import asyncio
    import httpx
    from orangespace_node.control_identity import submit_inventory
    calls = []
    transport = httpx.MockTransport(lambda request: calls.append(request))
    with __import__('pytest').raises(ValueError,match='local identity absent'):
        asyncio.run(submit_inventory(client.app.state.database.engine,dict(origin='https://control.example.test',token='A'*43,node_id=str(uuid4()),node_epoch=1,config_revision=1),str(uuid4()),str(uuid4()),transport=transport))
    assert calls == []
