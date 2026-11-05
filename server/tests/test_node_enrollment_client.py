"""Protocol models plus real isolated-MySQL ASGI; not deployed HTTPS or activation."""
import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_control_auth import control


def encode(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')


@pytest.fixture
def private_setup(tmp_path):
    key = Ed25519PrivateKey.generate()  # Test-owned key only; product must never generate.
    keyfile = tmp_path / 'key.pem'
    keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    keyfile.chmod(0o600)
    config = dict(origin='https://control.example.test', node_id=str(uuid4()),
                  node_api_origin='https://node.example.test', enrollment_id=str(uuid4()),
                  enrollment_token=encode(bytes(range(32))), private_key_file=str(keyfile),
                  output_dir=str(tmp_path / 'owned-scope'))
    path = tmp_path / 'private.json'
    path.write_text(json.dumps(config)); path.chmod(0o600)
    return path, config, key


@pytest.mark.parametrize('boundary', ['challenge', 'complete'])
def test_real_control_asgi_mysql_requires_client_schema(private_setup, control, boundary):
    """Real app/body and isolated MySQL, not deployed HTTPS or activation.

    Repair only the prerequisite challenge for the complete case so both
    missing-schema bugs independently fail against the actual server boundary.
    """
    from test_control_auth import login
    from orangespace_node.enrollment_client import EnrollmentError, enroll
    client, engine, name, password, _, _ = control
    path, config, key = private_setup
    _, admin = login(client, name, password)
    public = key.public_key().public_bytes_raw()
    response = client.post('/control/v1/admin/node-enrollments', headers=admin, json=dict(
        schema=1, node_id=config['node_id'], alias='schema_' + uuid4().hex[:16],
        display_name='schema regression', api_origin=config['node_api_origin'],
        tls_server_name='node.example.test', expected_key_fingerprint=hashlib.sha256(public).hexdigest(),
        reason='test-owned schema boundary'))
    assert response.status_code == 201
    enrollment = response.json()
    config.update(enrollment_id=enrollment['enrollment_id'], enrollment_token=enrollment['enrollment_token'])
    path.write_text(json.dumps(config))
    statuses = []

    class ObservedASGI(httpx.ASGITransport):
        async def handle_async_request(self, request):
            if boundary == 'complete' and request.url.path.endswith('/challenge'):
                data = json.loads(request.content)
                data['schema'] = 1
                request = httpx.Request(request.method, request.url, json=data)
            response = await super().handle_async_request(request)
            statuses.append((request.url.path.rsplit('/', 1)[-1], response.status_code))
            return response

    try:
        result = asyncio.run(enroll(path, transport=ObservedASGI(app=client.app)))
    except EnrollmentError:
        result = None
    assert statuses == [('challenge', 200), ('complete', 201)]
    assert result is not None
    assert result['state'] == 'pending'
    nodes = client.get('/control/v1/admin/nodes', headers=admin).json()['items']
    assert next(node for node in nodes if node['node_id'] == config['node_id'])['state'] == 'pending'


def test_protocol_model_real_ed25519_proof_and_loader_compatible_outputs(private_setup):
    from orangespace_node.enrollment_client import enroll
    from orangespace_node.control_identity import load_machine_config
    from orangespace_node.federation import load_config
    path, config, key = private_setup
    cid, nonce, expiry = str(uuid4()), encode(b'n' * 32), 1900000030
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    fingerprint = hashlib.sha256(public).hexdigest()
    calls = []

    def model(request):
        calls.append(request.url.path)
        data = json.loads(request.content)
        assert 'authorization' not in request.headers
        assert data['enrollment_token'] == config['enrollment_token']
        if request.url.path.endswith('/challenge'):
            assert set(data) == {'schema', 'enrollment_token', 'node_id', 'public_key'}
            assert type(data['schema']) is int and data['schema'] == 1
            assert data['node_id'] == config['node_id']
            assert data['public_key'] == encode(public)
            # Files must already be exclusively reserved before any credential reply.
            for name in ('machine.json', 'federation.json'):
                assert (Path(config['output_dir']) / name).stat().st_size == 0
            return httpx.Response(200, json=dict(schema=1, challenge_id=cid, nonce=nonce, expires_at=expiry))
        assert set(data) == {'schema', 'enrollment_token', 'challenge_id', 'signature'}
        assert type(data['schema']) is int and data['schema'] == 1
        values = [config['enrollment_id'], config['node_id'], fingerprint,
                  config['node_api_origin'], cid, nonce, str(expiry)]
        message = b'OrangeSpace-enroll-v1\n' + b''.join(str(len(v.encode())).encode() + b':' + v.encode() for v in values)
        key.public_key().verify(base64.urlsafe_b64decode(data['signature'] + '=='), message)
        return httpx.Response(201, json=dict(schema=1, node_id=config['node_id'], node_epoch=1,
                                           config_revision=1, node_access_token=encode(b't' * 32)))

    result = asyncio.run(enroll(path, transport=httpx.MockTransport(model), now=lambda: 1900000000))
    assert len(calls) == 2
    assert result['node_id'] == config['node_id'] and result['fingerprint'] == fingerprint
    assert result['state'] == 'pending'
    directory = Path(config['output_dir'])
    assert directory.stat().st_uid == os.geteuid()
    assert directory.stat().st_mode & 0o777 == 0o700
    machine = load_machine_config(directory / 'machine.json')
    federation = load_config(directory / 'federation.json', config['node_id'])
    assert machine == {k: v for k, v in federation.items() if k != 'node_api_origin'}
    assert federation['node_api_origin'] == config['node_api_origin']
    for name in ('machine.json', 'federation.json'):
        s = (directory / name).stat()
        assert s.st_mode & 0o777 == 0o600 and s.st_uid == os.geteuid() and s.st_nlink == 1
    assert 'token' not in json.dumps(result)

def run_model(path, config, *, challenge_change=None, complete_change=None, status=200):
    from orangespace_node.enrollment_client import enroll
    calls = []
    def model(request):
        calls.append(request.url.path)
        if request.url.path.endswith('/challenge'):
            value = dict(schema=1, challenge_id=str(uuid4()), nonce=encode(b'n' * 32), expires_at=1900000030)
            if challenge_change: value.update(challenge_change)
            return httpx.Response(status, json=value, headers={'location': 'https://other.example.test/steal'})
        value = dict(schema=1, node_id=config['node_id'], node_epoch=1,
                     config_revision=1, node_access_token=encode(b't' * 32))
        if complete_change: value.update(complete_change)
        return httpx.Response(201, json=value)
    return lambda: asyncio.run(enroll(path, transport=httpx.MockTransport(model), now=lambda: 1900000000)), calls


@pytest.mark.parametrize('field,value', [
    ('schema', True), ('schema', 1.0), ('schema', 2), ('extra', 1),
    ('expires_at', True), ('expires_at', 1900000030.0), ('expires_at', 1900000000),
    ('expires_at', 1900000061), ('nonce', 'a' * 43), ('challenge_id', str(UUID(int=0)))])
def test_protocol_model_rejects_bad_challenge(private_setup, field, value):
    from orangespace_node.enrollment_client import EnrollmentError
    path, config, _ = private_setup
    run, calls = run_model(path, config, challenge_change={field: value})
    with pytest.raises(EnrollmentError): run()
    assert len(calls) == 1
    assert Path(config['output_dir']).is_dir()


@pytest.mark.parametrize('change', [
    {'node_id': str(uuid4())}, {'node_epoch': True}, {'node_epoch': 0},
    {'config_revision': 9007199254740992}, {'schema': 1.0}, {'schema': True},
    {'extra': 'secret'}, {'node_access_token': 'a' * 43}, {'node_access_token': 'secret'},
])
def test_protocol_model_rejects_crossnode_or_bad_completion(private_setup, change):
    from orangespace_node.enrollment_client import EnrollmentError
    path, config, _ = private_setup
    run, calls = run_model(path, config, complete_change=change)
    with pytest.raises(EnrollmentError): run()
    assert len(calls) == 2
    assert all(p.stat().st_size == 0 for p in Path(config['output_dir']).iterdir())


@pytest.mark.parametrize('status', [301, 302, 303, 307, 308, 400, 500])
def test_protocol_model_no_redirect_or_retry(private_setup, status):
    from orangespace_node.enrollment_client import EnrollmentError
    path, config, _ = private_setup
    run, calls = run_model(path, config, status=status)
    with pytest.raises(EnrollmentError): run()
    assert len(calls) == 1


@pytest.mark.parametrize('change', [
    {'insecure': False}, {'verify': False}, {'origin': 'http://control.example.test'},
    {'origin': 'https://control.example.test/'}, {'origin': 'https://user:pw@example.test'},
    {'origin': 'https://control.example.test:0'}, {'enrollment_token': 'a' * 43},
    {'node_id': '00000000-0000-0000-0000-000000000000'}, {'private_key_file': 'relative'},
])
def test_invalid_config_never_contacts_server(private_setup, change):
    from orangespace_node.enrollment_client import EnrollmentError
    path, config, _ = private_setup
    config.update(change); path.write_text(json.dumps(config))
    run, calls = run_model(path, config)
    with pytest.raises(EnrollmentError): run()
    assert calls == [] and not Path(config['output_dir']).exists()


@pytest.mark.parametrize('target', ['config-mode', 'key-mode', 'config-link', 'key-link', 'hardlink', 'parent-mode'])
def test_protected_inputs_fail_before_http(private_setup, target):
    from orangespace_node.enrollment_client import EnrollmentError
    path, config, _ = private_setup
    key = Path(config['private_key_file'])
    if target == 'config-mode': path.chmod(0o644)
    elif target == 'key-mode': key.chmod(0o640)
    elif target == 'hardlink': os.link(key, key.with_name('second-link'))
    elif target == 'parent-mode': path.parent.chmod(0o777)
    else:
        source = path if target == 'config-link' else key
        saved = source.with_name(source.name + '.saved'); source.rename(saved); source.symlink_to(saved)
    run, calls = run_model(path, config)
    with pytest.raises(EnrollmentError): run()
    assert calls == []


def test_existing_scope_is_never_overwritten(private_setup):
    from orangespace_node.enrollment_client import EnrollmentError
    path, config, _ = private_setup
    directory = Path(config['output_dir']); directory.mkdir(mode=0o700)
    sentinel = directory / 'machine.json'; sentinel.write_text('keep')
    run, calls = run_model(path, config)
    with pytest.raises(EnrollmentError): run()
    assert calls == [] and sentinel.read_text() == 'keep'


def test_unknown_complete_retains_scope_and_sanitizes_cli(private_setup, monkeypatch, capsys):
    import orangespace_node.enrollment_client as module
    path, config, _ = private_setup
    calls = []
    def model(request):
        calls.append(request.url.path)
        if len(calls) == 1:
            return httpx.Response(200, json=dict(schema=1, challenge_id=str(uuid4()), nonce=encode(b'n'*32), expires_at=1900000030))
        raise httpx.ReadTimeout('SECRET response ' + config['enrollment_token'])
    original = module.enroll
    async def injected(path):
        return await original(path, transport=httpx.MockTransport(model), now=lambda:1900000000)
    monkeypatch.setattr(module, 'enroll', injected)
    assert module.main(['--config', str(path)]) == 1
    output = capsys.readouterr()
    assert output.out == module.FAILURE + '\n' and output.err == ''
    assert len(calls) == 2 and Path(config['output_dir']).is_dir()
    assert len(list(Path(config['output_dir']).iterdir())) == 2


def test_second_output_failure_retains_first_without_remote_delete(private_setup, monkeypatch):
    import orangespace_node.enrollment_client as module
    path, config, _ = private_setup
    original = module._write
    count = 0
    def fail_second(fd, value):
        nonlocal count
        count += 1
        if count == 2: raise OSError('SECRET')
        original(fd, value)
    monkeypatch.setattr(module, '_write', fail_second)
    run, calls = run_model(path, config)
    with pytest.raises(module.EnrollmentError): run()
    directory = Path(config['output_dir'])
    assert len(calls) == 2 and (directory / 'machine.json').stat().st_size > 0
    assert (directory / 'federation.json').stat().st_size == 0


def test_https_constructor_uses_normal_verification_no_env_no_redirect(private_setup, monkeypatch):
    import orangespace_node.enrollment_client as module
    path, config, _ = private_setup
    real = httpx.AsyncClient
    options = []
    def observed(**kwargs):
        options.append(kwargs)
        return real(**kwargs)
    monkeypatch.setattr(module.httpx, 'AsyncClient', observed)
    run, _ = run_model(path, config)
    run()
    assert options[0]['verify'] is True
    assert options[0]['trust_env'] is False and options[0]['follow_redirects'] is False


@pytest.mark.parametrize('raw', [b'{' + b' ' * 16384 + b'}', b'{"schema":1,"schema":1}', b'[]'])
def test_protocol_model_response_caps_and_duplicate_members(private_setup, raw):
    from orangespace_node.enrollment_client import EnrollmentError, enroll
    path, config, _ = private_setup
    def model(request): return httpx.Response(200, content=raw)
    with pytest.raises(EnrollmentError):
        asyncio.run(enroll(path, transport=httpx.MockTransport(model)))


def test_unprotected_input_parent_rejected_even_with_safe_output_parent(private_setup):
    from orangespace_node.enrollment_client import EnrollmentError
    path, config, _ = private_setup
    unsafe = path.parent / 'unsafe'; unsafe.mkdir(mode=0o777); unsafe.chmod(0o777)
    moved = unsafe / 'private.json'; path.rename(moved)
    run, calls = run_model(moved, config)
    with pytest.raises(EnrollmentError): run()
    assert calls == []


def test_cli_rejects_unknown_arguments_without_echoing_values(capsys):
    from orangespace_node.enrollment_client import main, FAILURE
    assert main(['--config', '/private.json', '--insecure', 'SECRET']) == 1
    captured = capsys.readouterr()
    assert captured.out == FAILURE + '\n' and captured.err == ''


def test_untrusted_writable_ancestor_rejected(private_setup):
    from orangespace_node.enrollment_client import EnrollmentError
    path, config, _ = private_setup
    unsafe = path.parent / 'unsafe'; unsafe.mkdir(mode=0o777); unsafe.chmod(0o777)
    nested = unsafe / 'protected'; nested.mkdir(mode=0o700)
    moved = nested / 'private.json'; path.rename(moved)
    run, calls = run_model(moved, config)
    with pytest.raises(EnrollmentError): run()
    assert calls == []
