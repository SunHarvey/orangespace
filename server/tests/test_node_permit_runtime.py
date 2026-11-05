"""Real MySQL/Centre+Node ASGI and real local TUIC, not Windows/WFP.

Centre/Node control requests use ASGI transport; no claim of public HTTPS.
An existing central session is revoked through its real API. Independent Node
expiry must stop A without a manual DELETE while B is renewed and still forwards.
Probe requests are new TCP streams; this does not prove existing TCP/UDP flows.
"""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import threading
import time
from uuid import UUID

import pytest
from sqlalchemy import update
import uvicorn

from test_control_auth import control, login
from test_control_exchange import setup, ISSUE
from test_tunnel_runtime import TestClient, tunneled_probe, redact_json
from test_tunnels import binding
from orangespace_control.schema_v1 import grants, mappings
from orangespace_node.app import create_app
from orangespace_node.auth import create_user, set_tunnel_grant
from orangespace_node import federation

APPROVED_RUNTIME_SHA256 = '1264361b5f8868c8768f7555d3e77e20118bf503c41ac08bb290a0d99056aa3a'


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def test_centre_session_revoke_stops_real_permit_child_preserves_b(control, config, tmp_path, monkeypatch):
    source = os.environ.get('ORANGESPACE_TEST_SING_BOX')
    if not source:
        pytest.skip('approved real sing-box runtime required')
    assert source is not None
    assert os.geteuid() == 0  # Own protected fixture only; not a production UID test.
    binary = Path(source)
    assert binary.is_absolute() and binary.is_file() and not binary.is_symlink()
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == APPROVED_RUNTIME_SHA256
    runtime = tmp_path / 'sing-box'
    shutil.copyfile(binary, runtime)
    runtime.chmod(0o755)
    cert, key = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-keyout', str(key), '-out', str(cert), '-days', '1',
                    '-subj', '/CN=orangespace.test', '-addext',
                    'subjectAltName=DNS:orangespace.test'], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    key.chmod(0o600)
    for _ in range(8):
        port = free_port(socket.SOCK_DGRAM)
        if port <= 65527:
            break
    assert port <= 65527
    probe_port = free_port()
    lock = tmp_path / 'runtime.lock'
    lock.touch(mode=0o600)
    runtime_path = tmp_path / 'runtime.json'
    runtime_path.write_text(json.dumps(dict(
        executable=str(runtime), executable_sha256=APPROVED_RUNTIME_SHA256,
        certificate=str(cert), private_key=str(key), endpoint_ip='127.0.0.1',
        listen_ip='127.0.0.1', tls_server_name='orangespace.test', port_start=port,
        port_end=port+8, max_leases=4, lease_seconds=30, startup_timeout=2,
        probe_port=probe_port, dns_port=5353, lock_file=str(lock))))
    runtime_path.chmod(0o600)

    centre, engine, user_a, machine, payload, _, grant_id, session_a = setup(control)
    _, _, name, password, _, _ = control
    _, user_b = login(centre, name, password)
    with engine.begin() as db:
        db.execute(update(grants).where(grants.c.id == grant_id).values(scopes=['tunnel']))
    fed_path = tmp_path / 'federation.json'
    fed_path.write_text(json.dumps(dict(
        origin='https://centre.test', token=machine['Authorization'][7:],
        node_id=payload['node_id'], node_epoch=1, config_revision=1,
        node_api_origin='https://node.test')))
    fed_path.chmod(0o600)
    operations = []
    def control_post(self, route, data):
        if route.endswith('/lease-permits'):
            operations.append((data['operation'], data['tunnel_id']))
        return centre.post(route, headers=machine, json=data)
    monkeypatch.setattr(federation.Federation, '_post', control_post)
    node_id = payload['node_id']
    assert isinstance(node_id, str)
    app = create_app(replace(config, node_id=UUID(node_id),
                             federation_config=fed_path, tunnel_config=runtime_path))
    helpers, server, worker = [], None, None
    with TestClient(app, base_url=f'http://127.0.0.1:{probe_port}',
                    client=('127.0.0.1', 50000)) as node:
        local = create_user(app.state.database, 'federated-runtime', 'fixture-only-local-password')
        set_tunnel_grant(app.state.database, 'federated-runtime', True)
        with engine.begin() as db:
            db.execute(update(mappings).where(mappings.c.node_id == UUID(node_id).bytes)
                       .values(legacy_user_id=UUID(local.id).bytes))
        auth = []
        for central_user in (user_a, user_b):
            ticket = centre.post(ISSUE, headers=central_user, json=payload)
            assert ticket.status_code == 201
            ticket = ticket.json()
            exchanged = node.post('/federation/v1/sessions/exchange', json=dict(
                schema=1, exchange_id=ticket['exchange_id'], exchange_token=ticket['exchange_token']))
            assert exchanged.status_code == 200
            auth.append({'Authorization': 'Bearer '+exchanged.json()['node_credential']['access_token'],
                         'X-OrangeSpace-Lease-Schema': '2'})
        leases = []
        for credential in auth:
            made = node.post('/v1/tunnels', headers=credential, json=binding())
            assert made.status_code == 200
            leases.append(made.json())
        manager = app.state.tunnels
        a, b = leases
        owner_a, owner_b = manager.leases[a['tunnel_id']], manager.leases[b['tunnel_id']]
        original_deadline = owner_a.deadline
        assert owner_a.process.poll() is None and owner_b.process.poll() is None
        assert owner_a.process.pidfd is not None and owner_b.process.pidfd is not None
        try:
            server = uvicorn.Server(uvicorn.Config(app, host='127.0.0.1', port=probe_port,
                lifespan='off', access_log=False, log_config=None, log_level='critical'))
            worker = threading.Thread(target=server.run, daemon=True)
            worker.start()
            ready = time.monotonic()+3
            while not server.started and time.monotonic() < ready:
                time.sleep(0.01)
            assert server.started
            for lease in leases:
                socks_port = free_port()
                username, secret = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
                document = dict(log={'disabled': True}, inbounds=[dict(type='socks', listen='127.0.0.1',
                    listen_port=socks_port, users=[dict(username=username, password=secret)])],
                    outbounds=[dict(type='tuic', tag='lease', server=lease['endpoint_ip'],
                    server_port=lease['endpoint_port'], uuid=lease['tuic_uuid'], password=lease['tuic_password'],
                    zero_rtt_handshake=False, tls=dict(enabled=True, server_name=lease['tls_server_name'],
                    certificate_path=str(cert)))], route={'final': 'lease'})
                process = subprocess.Popen([str(runtime), 'run', '-c', 'stdin'], stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={})
                helpers.append((process, socks_port, username, secret, lease))
                assert process.stdin is not None
                process.stdin.write(json.dumps(document).encode())
                process.stdin.close()
                ready = time.monotonic()+3
                while True:
                    try:
                        with socket.create_connection(('127.0.0.1', socks_port), timeout=0.1):
                            break
                    except OSError:
                        assert process.poll() is None and time.monotonic() < ready
                        time.sleep(0.01)
                assert redact_json(tunneled_probe(*helpers[-1][1:])) == {
                    'tunnel_id': lease['tunnel_id'], 'proof': lease['probe_response']}
            assert operations == [('create', a['tunnel_id']), ('create', b['tunnel_id'])]
            revoked = centre.delete('/control/v1/sessions/'+session_a['central_session_id'], headers=user_b)
            assert revoked.status_code == 202
            assert revoked.json()['cleanup_state'] == 'pending'  # A receipt is not process-stop proof.
            denied = node.post('/v1/tunnels/'+a['tunnel_id']+'/renew', headers=auth[0], json={})
            assert denied.status_code in (401, 403, 410)
            assert owner_a.deadline == original_deadline
            # Do not DELETE A or call _reap: independent expiry must stop its real child.
            renewed_at = time.monotonic()
            while owner_a.process.poll() is None and time.monotonic() < original_deadline+3:
                now = time.monotonic()
                if now-renewed_at >= 5:
                    renewed = node.post('/v1/tunnels/'+b['tunnel_id']+'/renew', headers=auth[1], json={})
                    assert renewed.status_code == 200
                    assert 0 < renewed.json()['remaining_ttl_ms'] <= 30000
                    renewed_at = now
                time.sleep(0.02)
            assert owner_a.process.poll() is not None
            released = time.monotonic()+3
            clean = False
            while time.monotonic() < released:
                with manager.lock:
                    clean = (a['tunnel_id'] not in manager.leases and
                             owner_a.process.pid not in manager.children and owner_a.process.pidfd is None)
                if clean:
                    break
                time.sleep(0.01)
            assert clean and manager.thread.is_alive()
            assert owner_b.process.poll() is None
            with pytest.raises((OSError, ValueError, AssertionError)):
                tunneled_probe(*helpers[0][1:])
            assert redact_json(tunneled_probe(*helpers[1][1:])) == {
                'tunnel_id': b['tunnel_id'], 'proof': b['probe_response']}
            assert any(op == 'renew' and tid == b['tunnel_id'] for op, tid in operations)
            assert node.delete('/v1/tunnels/'+b['tunnel_id'], headers=auth[1]).status_code == 204
            assert owner_b.process.poll() is not None and owner_b.process.pidfd is None
        finally:
            for process, *_ in helpers:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=3)
            if server is not None:
                server.should_exit = True
            if worker is not None:
                worker.join(timeout=5)
                assert not worker.is_alive()
