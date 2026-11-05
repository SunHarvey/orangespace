"""Bounded console runtime tests; database fixture owns a unique schema."""
from pathlib import Path
import sys


def test_cli_serve_options(monkeypatch):
    from orangespace_control import cli
    assert hasattr(cli, 'parse_args'), 'serve runtime options missing'
    args = cli.parse_args(['--config', '/private/config', 'serve'])
    assert (args.host, args.port, args.dist, args.ssl_certfile, args.ssl_keyfile) == ('127.0.0.1', 8090, None, None, None)
    args = cli.parse_args(['--config', '/private/config', 'serve', '--host', '127.0.0.2', '--port', '19092', '--dist', '/public/dist', '--ssl-certfile', '/cert', '--ssl-keyfile', '/key'])
    assert (args.host, args.port, args.dist) == ('127.0.0.2', 19092, '/public/dist')
    for extra in [['--port', '0'], ['--port', '65536'], ['--ssl-certfile', '/cert'], ['--ssl-keyfile', '/key']]:
        with pytest.raises(SystemExit):
            cli.parse_args(['--config', '/private/config', 'serve', *extra])

import importlib.util
import json
import os
import socket
import subprocess
import time
import httpx
from test_control_auth import control


def test_linux_scope_real_http_and_exact_stop(control, tmp_path):
    _, engine, _, _, _, _ = control
    runner = Path(__file__).parents[2] / 'deploy/dev/console.py'
    assert runner.is_file(), 'Linux console scope runner missing'
    config = tmp_path / 'control.json'
    from orangespace_control.config import load_config
    from sqlalchemy.engine import make_url
    source = load_config(os.environ['ORANGESPACE_CONTROL_TEST_CONFIG'])
    scoped_url = make_url(source.database_url).set(database=engine.url.database)
    config.write_text(json.dumps({'database_url': scoped_url.render_as_string(hide_password=False)}))
    config.chmod(0o600)
    # Test-owned static fixture: HTTP/runtime coverage, not Vue UI acceptance.
    dist = tmp_path / 'runtime-static-fixture'
    assets = dist / 'assets'
    assets.mkdir(parents=True)
    fixture_html = b'<html><body>runtime static fixture, not Vue UI</body></html>'
    fixture_js = b'console.log("runtime static fixture, not Vue UI");'
    (dist / 'index.html').write_bytes(fixture_html)
    (assets / 'index-Abc12345.js').write_bytes(fixture_js)
    scope = tmp_path / 'scope'
    base = [sys.executable, str(runner), '--scope', str(scope)]
    # Independent process is never in this runner's ownership.
    unrelated = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
    try:
        result = subprocess.run(['sh', str(runner.parent / 'start.sh'), '--python', sys.executable, '--config', str(config), '--dist', str(dist), '--port', '19097'], env={**os.environ, 'ORANGESPACE_CONSOLE_SCOPE': str(scope)}, capture_output=True, text=True, timeout=20)
        assert result.returncode == 0, result.stdout + result.stderr
        with httpx.Client(base_url='http://127.0.0.1:19097', trust_env=False) as client:
            response = None
            for _ in range(100):
                try:
                    response = client.get('/healthz')
                    break
                except httpx.ConnectError:
                    time.sleep(.05)
            assert response is not None, 'console health endpoint remained unreachable'
            assert response.json() == {'status': 'ok'}
            assert client.get('/control/v1/session').status_code == 401
            assert client.post('/control/v1/auth/login', json={'schema': 1, 'username': 'missing', 'password': 'wrong-password-test'}).status_code == 401
            index_response = client.get('/')
            assert index_response.status_code == 200
            assert index_response.content == fixture_html
            users_response = client.get('/users')
            assert users_response.status_code == 200
            assert users_response.content == fixture_html
            for asset in (dist / 'assets').iterdir():
                asset_response = client.get('/assets/' + asset.name)
                assert asset_response.status_code == 200
                assert asset_response.content == fixture_js
            assert client.get('/control.json').status_code == 404
        assert subprocess.run(['sh', str(runner.parent / 'status.sh')], env={**os.environ, 'ORANGESPACE_CONSOLE_SCOPE': str(scope)}, capture_output=True).returncode == 0
        # Duplicate scope refuses a second launch; no PID guessing.
        assert subprocess.run([*base, 'start', '--python', sys.executable, '--config', str(config), '--dist', str(dist)], capture_output=True, timeout=10).returncode != 0
        assert subprocess.run(['sh', str(runner.parent / 'stop.sh')], env={**os.environ, 'ORANGESPACE_CONSOLE_SCOPE': str(scope)}, capture_output=True, timeout=15).returncode == 0
        assert subprocess.run([*base, 'status'], capture_output=True).returncode != 0
        assert unrelated.poll() is None
        with socket.socket() as probe:
            assert probe.connect_ex(('127.0.0.1', 19097)) != 0
    finally:
        subprocess.run([*base, 'stop'], capture_output=True, timeout=15)
        unrelated.terminate()
        unrelated.wait(timeout=5)
        config.unlink(missing_ok=True)

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


def test_console_public_routes_do_not_publish_private_files(tmp_path):
    assert importlib.util.find_spec('orangespace_control.runtime') is not None, 'console runtime missing'
    from orangespace_control.runtime import install_console
    dist = tmp_path / 'dist'
    assets = dist / 'assets'
    assets.mkdir(parents=True)
    (dist / 'index.html').write_text('<html>console</html>')
    (assets / 'index-Abc12345.js').write_text('console.log(1)')
    (dist / 'private.json').write_text('SECRET')
    (assets / 'config.json').write_text('SECRET')
    (assets / 'escape-Abc12345.js').symlink_to(dist / 'private.json')
    app = FastAPI()
    install_console(app, dist)
    with TestClient(app) as client:
        assert client.get('/healthz').json() == {'status': 'ok'}
        for path in ['/', '/login', '/users', '/leases']:
            assert client.get(path).text == '<html>console</html>'
        assert client.get('/assets/index-Abc12345.js').text == 'console.log(1)'
        for path in ['/private.json', '/assets/config.json', '/assets/escape-Abc12345.js', '/unknown', '/control/v1/unknown', '/assets/../private.json']:
            assert client.get(path).status_code == 404, path
        assert client.post('/users').status_code == 405
