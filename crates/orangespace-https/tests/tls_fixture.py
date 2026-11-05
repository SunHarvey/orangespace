#!/usr/bin/env python3
"""Independent real TLS server, ephemeral OpenSSL CA, never a TLS mock."""
import http.server, ssl, subprocess, tempfile, pathlib, threading, sys, time
root = tempfile.TemporaryDirectory(prefix='os-https-fixture-')
p = pathlib.Path(root.name)
def cmd(*args):
    subprocess.run(['openssl', *args], cwd=p, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
cmd('req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.pem','-days','2','-subj','/CN=OS Test CA','-addext','basicConstraints=critical,CA:TRUE')
cmd('req','-newkey','rsa:2048','-nodes','-keyout','server.key','-out','server.csr','-subj','/CN=localhost')
(p/'ext').write_text('subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
if len(sys.argv)>1 and sys.argv[1]=='expired':
    (p/'index').write_text('')
    (p/'serial').write_text('1000\n')
    (p/'ca.conf').write_text('[ca]\ndefault_ca=local\n[local]\ndatabase=index\nserial=serial\nnew_certs_dir=.\ncertificate=ca.pem\nprivate_key=ca.key\ndefault_md=sha256\npolicy=policy\n[policy]\ncommonName=supplied\n')
    cmd('ca','-batch','-config','ca.conf','-in','server.csr','-out','server.pem','-startdate','20200101000000Z','-enddate','20200102000000Z','-extfile','ext')
else:
    cmd('x509','-req','-in','server.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-out','server.pem','-days','1','-extfile','ext')
cmd('req','-x509','-newkey','rsa:2048','-nodes','-keyout','wrong.key','-out','wrong.pem','-days','2','-subj','/CN=Wrong CA','-addext','basicConstraints=critical,CA:TRUE')
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args): pass
    def do_GET(self): self.handle_request()
    def do_POST(self): self.handle_request()
    def do_DELETE(self): self.handle_request()
    def handle_request(self):
        body = self.rfile.read(int(self.headers.get('Content-Length',0)))
        if self.path == '/slow': time.sleep(6)
        status = 204 if self.path == '/empty' else 401 if self.path == '/status' else 302 if self.path == '/redirect' else 200
        if self.path == '/lease-header' and self.headers.get('X-OrangeSpace-Lease-Schema') != '2': status = 400
        data = b'' if status == 204 else b'x' * (1048577 if self.path == '/large' else 1048576) if self.path in ('/large','/limit') else body or b'{"ok":true}'
        self.send_response(status)
        self.send_header('Content-Type', 'text/html' if self.path == '/not-json' else 'application/json')
        if self.path == '/duplicate-content-type': self.send_header('Content-Type', 'application/json')
        if self.path != '/centre': self.send_header('X-OrangeSpace-Node', 'N' * 43)
        if self.path == '/duplicate': self.send_header('X-OrangeSpace-Node','N'*43)
        if self.path == '/comma': self.send_header('X-OrangeSpace-Node','N'*43 + ',' + 'N'*43)
        if self.path == '/redirect': self.send_header('Location','https://127.0.0.1:1/must-not-follow')
        self.send_header('Content-Length',str(len(data)))
        self.end_headers()
        if self.path == '/slowbody': time.sleep(6)
        try: self.wfile.write(data)
        except (BrokenPipeError, ssl.SSLError): pass
server = http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(p/'server.pem',p/'server.key')
server.socket = ctx.wrap_socket(server.socket,server_side=True)
print(server.server_port, str(p), flush=True)
threading.Thread(target=server.serve_forever,daemon=True).start()
sys.stdin.read()
server.shutdown()
