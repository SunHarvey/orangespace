#!/usr/bin/env python3
"""Exercise the actually linked C executable against independent Python/OpenSSL TLS."""
import os, pathlib, subprocess, sys
here=pathlib.Path(__file__).resolve().parent
fixture=subprocess.Popen([sys.executable,str(here/'tls_fixture.py')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
try:
    assert fixture.stdout is not None
    port, directory=fixture.stdout.readline().strip().split(' ',1)
    env=dict(os.environ, HTTPS_PROXY='http://127.0.0.1:1',HTTP_PROXY='http://127.0.0.1:1',ALL_PROXY='http://127.0.0.1:1',NO_PROXY='')
    result=subprocess.run([str(here.parent/'target/ffi-smoke'),f'https://localhost:{port}',str(pathlib.Path(directory)/'ca.pem')],env=env,capture_output=True,text=True,timeout=20)
    assert result.returncode==0, (result.returncode,result.stdout,result.stderr)
    assert result.stderr=='', 'FFI error path must not print diagnostics'
    assert 'secret-body-never-print' not in result.stdout and 'secret-token-never-print' not in result.stdout
    print(result.stdout,end='')
    print('C ABI real TLS: 401 exact JSON/status; optional centre header; proxy env ignored; stderr empty')
finally:
    if fixture.stdin is not None: fixture.stdin.close()
    fixture.wait(timeout=10)
