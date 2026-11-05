#!/usr/bin/env python3
"""Opt-in real Windows WinHTTP negative TLS test; never changes certificate stores.

Requires an explicitly authorized Windows SSH test account with an elevated token,
OpenSSL, and the built orangespace-node-tls-rejection-tests.exe. All credentials in
this fixture are synthetic constants; never supply a real account/password/token.
The Windows host must reach --bind-ip on an ephemeral TCP port. No browser runs.
"""
import argparse
import ipaddress
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ssh-target', required=True, help='authorized user@Windows-host')
    parser.add_argument('--identity', type=Path, required=True, help='existing SSH key, never copied')
    parser.add_argument('--known-hosts', type=Path, required=True)
    parser.add_argument('--bind-ip', required=True, help='local address reachable from test host')
    parser.add_argument('--test-executable', type=Path, required=True)
    args = parser.parse_args()
    address = str(ipaddress.ip_address(args.bind_ip))
    if ':' in address:
        parser.error('fixture currently supports IPv4 only')
    if args.ssh_target.startswith('-') or any(c.isspace() for c in args.ssh_target):
        parser.error('invalid explicit SSH target')
    for path in (args.identity, args.known_hosts, args.test_executable):
        if not path.is_file():
            parser.error('a required local input file is missing')
    options = ['-i', str(args.identity.resolve()), '-o', 'IdentitiesOnly=yes',
               '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
               '-o', 'UserKnownHostsFile=' + str(args.known_hosts.resolve())]
    tag = 'OrangeSpace-TlsFixture-' + uuid.uuid4().hex
    executable_name, script_name = tag + '.exe', tag + '.ps1'
    observed = dict(tcp_connections=0, tls_completed_on_server=0, http_application_bytes=0)
    errors = []
    with tempfile.TemporaryDirectory(prefix='orangespace-tls-negative-') as temporary:
        root = Path(temporary)
        cert, key = root / 'cert.pem', root / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-days', '1', '-subj', '/CN=orangespace-fixture.invalid',
                        '-addext', 'subjectAltName=IP:' + address,
                        '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        listener = socket.socket()
        listener.bind((address, 0))
        listener.listen(1)
        listener.settimeout(30)
        port = listener.getsockname()[1]

        def serve():
            try:
                raw, _ = listener.accept()
                observed['tcp_connections'] += 1
                raw.settimeout(10)
                try:
                    with context.wrap_socket(raw, server_side=True) as connection:
                        observed['tls_completed_on_server'] += 1
                        try:
                            observed['http_application_bytes'] += len(connection.recv(16384))
                        except (ConnectionResetError, ssl.SSLError):
                            pass
                except ssl.SSLError:
                    raw.close()
            except Exception as error:
                errors.append(type(error).__name__)
            finally:
                listener.close()

        configuration = json.dumps({'schema': 1, 'nodes': [{
            'name': 'fixture', 'node_id': str(uuid.uuid4()),
            'api_origin': f'https://{address}:{port}',
        }]}, separators=(',', ':'))
        script = r'''$ErrorActionPreference = 'Stop'
$root = 'C:\TAG'
$binary = Join-Path $env:USERPROFILE 'EXECUTABLE'
if (Test-Path -LiteralPath $root) { throw 'Fixture collision' }
try {
 New-Item -ItemType Directory -Path $root | Out-Null
 $acl = New-Object Security.AccessControl.DirectorySecurity
 $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
 Set-Acl -LiteralPath $root -AclObject $acl
 $path = Join-Path $root 'nodes.json'
 [IO.File]::WriteAllText($path, 'CONFIGURATION', (New-Object System.Text.UTF8Encoding($false)))
 $acl = New-Object Security.AccessControl.FileSecurity
 $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)')
 Set-Acl -LiteralPath $path -AclObject $acl
 & $binary $path fixture
 if ($LASTEXITCODE -ne 0) { throw 'Native TLS rejection test failed' }
} finally {
 if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
 Remove-Item -LiteralPath $binary -Force -ErrorAction SilentlyContinue
 $self = $PSCommandPath
 Remove-Item -LiteralPath $self -Force
 if ((Test-Path -LiteralPath $root) -or (Test-Path -LiteralPath $binary) -or (Test-Path -LiteralPath $self)) { throw 'Fixture cleanup incomplete' }
 Write-Output 'Windows fixture cleanup verified; certificate stores unchanged'
}
'''.replace('TAG', tag).replace('EXECUTABLE', executable_name).replace('CONFIGURATION', configuration)
        script_path = root / script_name
        script_path.write_text(script, encoding='utf-8')
        thread = threading.Thread(target=serve, daemon=True)
        try:
            # Generated leaf names only; SCP uses the account's home directory.
            subprocess.run(['scp', *options, str(args.test_executable.resolve()),
                            args.ssh_target + ':' + executable_name], check=True, timeout=30)
            subprocess.run(['scp', *options, str(script_path),
                            args.ssh_target + ':' + script_name], check=True, timeout=30)
            thread.start()
            subprocess.run(['ssh', *options, args.ssh_target,
                            'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\\' + script_name],
                           check=True, timeout=40)
            thread.join(timeout=15)
            if thread.is_alive() or errors:
                raise RuntimeError('TLS fixture did not finish cleanly: ' + ','.join(errors))
            if observed['tcp_connections'] != 1 or observed['http_application_bytes'] != 0:
                raise AssertionError('Unexpected credential-boundary evidence: ' + json.dumps(observed))
            # Server-side TLS completion is not acceptance of its certificate by
            # WinHTTP. Windows can abort after TLS before writing HTTP bytes.
        finally:
            listener.close()
            # Independent SSH also covers upload interruption and a timed-out
            # primary SSH whose PowerShell finally block never ran. Only this
            # invocation's UUID-generated literal paths may be deleted.
            # All interpolated names are generated ASCII UUID leaves, never
            # user input. Keep complex PowerShell in the uploaded reviewed .ps1;
            # fallback uses only literal cmd deletion/existence checks.
            protected_root = 'C:\\' + tag
            command = (
                'cmd /d /c "(if exist ' + protected_root + ' rmdir /s /q ' + protected_root + ')' +
                ' & del /f /q ' + executable_name + ' ' + script_name + ' 2>nul' +
                ' & (if exist ' + protected_root + ' exit /b 1)' +
                ' & (if exist ' + executable_name + ' exit /b 1)' +
                ' & (if exist ' + script_name + ' exit /b 1)' +
                ' & echo Windows fallback cleanup verified & exit /b 0"'
            )
            result = subprocess.run(['ssh', *options, args.ssh_target, command],
                                    check=True, timeout=20, capture_output=True, text=True)
            if 'Windows fallback cleanup verified' not in {line.strip() for line in result.stdout.splitlines()}:
                raise RuntimeError('Windows fallback cleanup verification missing')
        # Never report success until the independent cleanup/readback succeeded.
        print(json.dumps({'ok': True, 'winhttp_secure_failure': 12175,
                          'certificate_store_modified': False, **observed}, indent=2))


if __name__ == '__main__':
    main()
