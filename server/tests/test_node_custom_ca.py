"""App-local development CA trust: real TLS, never system-store mutation."""
import os
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest
from orangespace_node import control_identity


def test_custom_ca_keeps_hostname_and_chain_validation(tmp_path):
    factory = getattr(control_identity, 'tls_verify', None)
    assert callable(factory), 'node machine transport needs app-local CA support'
    cert, key = tmp_path / 'ca.pem', tmp_path / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-days', '1', '-subj', '/CN=OrangeSpace isolated TLS fixture',
                    '-addext', 'subjectAltName=IP:127.0.0.1',
                    '-addext', 'basicConstraints=critical,CA:TRUE',
                    '-keyout', str(key), '-out', str(cert)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    key.chmod(0o600)
    cert.chmod(0o600)
    context = factory({'ca_file': str(cert)})
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'isolated TLS transport fixture')
        def do_POST(self):
            # Consume the fixture request before closing its TLS connection.
            self.rfile.read(int(self.headers.get('Content-Length', '0')))
            self.do_GET()

        def log_message(self, format, *args):
            pass

    server = HTTPServer(('127.0.0.1', 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    port = server.server_port
    try:
        with httpx.Client(verify=context, trust_env=False, timeout=3) as client:
            assert client.get(f'https://127.0.0.1:{port}').status_code == 200
            with pytest.raises(httpx.ConnectError) as mismatch:
                client.get(f'https://localhost:{port}')
            assert 'CERTIFICATE_VERIFY_FAILED' in str(mismatch.value)
            assert 'mismatch' in str(mismatch.value).lower()
        from orangespace_node.federation import Federation
        remote = Federation({'origin': f'https://127.0.0.1:{port}',
                             'token': 'a' * 43, 'ca_file': str(cert)}, None)
        assert remote._post('/transport-fixture', {}).status_code == 200
        with httpx.Client(verify=True, trust_env=False, timeout=3) as client:
            with pytest.raises(httpx.ConnectError) as untrusted:
                client.get(f'https://127.0.0.1:{port}')
            assert 'CERTIFICATE_VERIFY_FAILED' in str(untrusted.value)
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)


def test_ca_reference_is_not_an_insecure_switch(tmp_path):
    factory = getattr(control_identity, 'tls_verify', None)
    assert callable(factory), 'app-local trust must not be a verification bypass'
    assert factory({}) is True
    for value in (False, True, '', 'relative.pem', str(tmp_path / 'absent')):
        with pytest.raises(ValueError):
            factory({'ca_file': value})
    source = tmp_path / 'public.pem'
    source.write_text('not a certificate')
    source.chmod(0o644)
    with pytest.raises(ValueError):
        factory({'ca_file': str(source)})
    source.chmod(0o600)
    link = tmp_path / 'link.pem'
    link.symlink_to(source)
    with pytest.raises(ValueError):
        factory({'ca_file': str(link)})
