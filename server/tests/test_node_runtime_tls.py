"""Real two-listener Node runtime: one application lifetime, no TLS bypass."""
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import pytest
from test_node_runtime_entry import write_profile


@pytest.mark.parametrize('first', [0, 1])
@pytest.mark.parametrize('original_failure', [False, True])
def test_late_listener_shutdown_failure_is_not_lost(tmp_path, monkeypatch, first, original_failure):
    import asyncio
    from contextlib import asynccontextmanager
    from types import SimpleNamespace
    import uvicorn
    from orangespace_node import runtime

    profile = runtime.load_profile(write_profile(
        tmp_path, tlsListenPort=19094, tlsCertificate='/synthetic-cert',
        tlsPrivateKey='/synthetic-key'))
    original = ValueError('synthetic-original-failure')
    secret = 'synthetic-shutdown-secret'
    finished = []
    lifetimes = []

    @asynccontextmanager
    async def lifespan(app):
        lifetimes.append('start')
        try:
            yield
        finally:
            lifetimes.append('stop')

    monkeypatch.setattr(runtime, 'build_app', lambda _: SimpleNamespace(
        router=SimpleNamespace(lifespan_context=lifespan)))

    async def exercise():
        loop = asyncio.get_running_loop()
        handlers = {}
        monkeypatch.setattr(loop, 'add_signal_handler', lambda sig, callback: handlers.setdefault(sig, callback))
        monkeypatch.setattr(loop, 'remove_signal_handler', lambda sig: handlers.pop(sig))
        entered = []
        both_entered = asyncio.Event()

        async def serve(server):
            index = len(entered)
            entered.append(server)
            if len(entered) == 2:
                both_entered.set()
            await both_entered.wait()
            if index == first:
                handlers[signal.SIGTERM]()
                finished.append(index)
                if original_failure:
                    raise original
                return
            while not server.should_exit:
                await asyncio.sleep(0)
            # Complete only after FIRST_COMPLETED has returned to the owner.
            await asyncio.sleep(.01)
            finished.append(index)
            raise ValueError(secret)

        monkeypatch.setattr(uvicorn.Server, 'serve', serve)
        with pytest.raises(ValueError if original_failure else RuntimeError) as caught:
            await runtime.serve_dual(profile)
        if original_failure:
            assert caught.value is original
        else:
            assert str(caught.value) == 'node listener shutdown failed'
            assert caught.value.__suppress_context__
            assert secret not in str(caught.value)
        assert not handlers

    asyncio.run(exercise())
    assert finished == [first, 1 - first]
    assert lifetimes == ['start', 'stop']


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def test_tls_profile_is_explicit_and_plain_http_stays_loopback(tmp_path):
    from orangespace_node.runtime import load_profile
    profile = write_profile(tmp_path, tlsListenPort=19094,
                            tlsCertificate=str(tmp_path/'cert.pem'),
                            tlsPrivateKey=str(tmp_path/'key.pem'))
    selected = load_profile(profile)
    assert selected.host == '127.0.0.1'
    assert selected.tls_host == '127.0.0.1' and selected.tls_port == 19094
    assert selected.tls_certificate == tmp_path/'cert.pem'
    for changes in ({'tlsListenPort': 19094},
                    {'tlsListenPort': True, 'tlsCertificate': '/a', 'tlsPrivateKey': '/b'},
                    {'tlsListenHost': '0.0.0.0', 'tlsListenPort': 19094,
                     'tlsCertificate': '/a', 'tlsPrivateKey': '/b'}):
        with pytest.raises(ValueError):
            load_profile(write_profile(tmp_path, **changes))


def test_real_http_probe_and_https_use_same_node_and_close_together(tmp_path, mysql_config_path):
    cert, key = tmp_path/'cert.pem', tmp_path/'key.pem'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes',
                    '-days','1','-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1',
                    '-addext','basicConstraints=critical,CA:TRUE',
                    '-out',str(cert),'-keyout',str(key)],check=True,
                   stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
    cert.chmod(0o600);key.chmod(0o600)
    http_port, tls_port = free_port(), free_port()
    assert http_port != tls_port
    profile = write_profile(tmp_path, dbConfig=str(mysql_config_path),
                            listenPort=http_port, tlsListenPort=tls_port,
                            tlsCertificate=str(cert), tlsPrivateKey=str(key))
    log = tmp_path/'dual-runtime.log'
    env = {k:v for k,v in os.environ.items() if not k.startswith('ORANGESPACE_')}
    context = ssl.create_default_context(cafile=str(cert))
    with log.open('w+') as stream:
        child = subprocess.Popen([sys.executable,'-m','orangespace_node.runtime',
                                  '--profile',str(profile),'serve'],env=env,
                                 stdout=stream,stderr=stream)
        try:
            expected = '4eef0765-2443-4879-badb-02967baac185'
            for base, ctx in [(f'http://127.0.0.1:{http_port}',None),
                              (f'https://127.0.0.1:{tls_port}',context)]:
                deadline=time.monotonic()+20
                while True:
                    assert child.poll() is None, 'runtime must retain both listeners'
                    try:
                        with urllib.request.urlopen(base+'/healthz',context=ctx,timeout=1) as response:
                            assert response.headers['X-OrangeSpace-Node']==expected
                            assert json.load(response)['status']=='ok'
                        break
                    except OSError:
                        if time.monotonic()>=deadline:raise AssertionError('listener readiness failed')
                        time.sleep(.1)
                with pytest.raises(urllib.error.HTTPError) as denied:
                    urllib.request.urlopen(base+'/v1/files',context=ctx,timeout=3)
                assert denied.value.code==401
                denied.value.close()  # Release the owned TLS response before SIGTERM.
            with pytest.raises(urllib.error.URLError) as untrusted:
                urllib.request.urlopen(f'https://127.0.0.1:{tls_port}/healthz',timeout=3)
            assert isinstance(untrusted.value.reason,ssl.SSLCertVerificationError)
            child.send_signal(signal.SIGTERM)
            assert child.wait(timeout=20)==0
            for port in (http_port,tls_port):
                with socket.socket() as check:assert check.connect_ex(('127.0.0.1',port))!=0
        finally:
            if child.poll() is None:
                child.terminate()
                try:child.wait(timeout=20)
                except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)
