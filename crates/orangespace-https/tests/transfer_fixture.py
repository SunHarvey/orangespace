#!/usr/bin/env python3
# Reuse the existing ephemeral certificate fixture, change only its HTTP handler.
import pathlib, sys
source=(pathlib.Path(__file__).with_name('tls_fixture.py')).read_text()
start=source.index('class Handler(')
end=source.index('server = ',start)
handler='''class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_PUT(self): self.reply()
    def do_POST(self): self.reply()
    def do_GET(self): self.reply()
    def reply(self):
        n=int(self.headers.get('Content-Length',0))
        while n:
            data=self.rfile.read(min(n,65536))
            if not data: return
            n-=len(data)
        status=302 if self.path.endswith('/redirect') else 401 if self.path.endswith('/error') else 201 if self.command!='GET' else 200
        self.send_response(status)
        if not self.path.endswith('/missing'): self.send_header('X-OrangeSpace-Node','W'*43 if self.path.endswith('/wrong') else '22222222-2222-4222-8222-222222222222')
        if self.path.endswith('/duplicate'): self.send_header('X-OrangeSpace-Node','22222222-2222-4222-8222-222222222222')
        kind = 'application/octet-stream' if self.command == 'GET' and '/v1/files/' in self.path else 'application/json'
        if not self.path.endswith('missingtype'): self.send_header('Content-Type', 'text/html' if self.path.endswith('badtype') else kind)
        if self.path.endswith('duplicatetype'): self.send_header('Content-Type', kind)
        if status==302: self.send_header('Location','https://127.0.0.1:1/never')
        size=2*1024*1024+17 if self.command=='GET' else 1
        self.send_header('Content-Length',str(size))
        self.end_headers()
        if self.path.endswith('/partial'): size=1
        try:
            while size:
                n=min(size,65536);self.wfile.write(b'x'*n);size-=n
        except (BrokenPipeError,ConnectionResetError,ssl.SSLError): pass
'''
exec(compile(source[:start]+handler+source[end:],__file__,'exec'))
