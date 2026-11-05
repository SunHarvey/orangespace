#!/usr/bin/env python3
"""Linux-only project console scope. No PID files and no arbitrary commands.

The daemon retains Popen + pidfd for its sole child. Lost control socket means
unknown ownership: refuse cleanup, never search/kill a process by name or PID.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import time


def request(scope, operation):
    # fd-relative address also avoids AF_UNIX's short pathname limit.
    fd = os.open(scope, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(12)
            client.connect(f'/proc/self/fd/{fd}/s')
            client.sendall(operation.encode())
            return json.loads(client.recv(1024))
    finally:
        os.close(fd)


def run(args, scope):
    lock = os.open(scope / 'lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    if (scope / 's').exists():
        raise RuntimeError('stale scope; ownership unknown')
    root = Path(__file__).resolve().parents[2]
    command = [str(Path(args.python).absolute()), '-m', 'orangespace_control.cli', '--config', str(Path(args.config).absolute()),
               'serve', '--host', args.host, '--port', str(args.port), '--dist', str(Path(args.dist).absolute())]
    if args.ssl_certfile or args.ssl_keyfile:
        if not (args.ssl_certfile and args.ssl_keyfile):
            raise ValueError('TLS pair required')
        command += ['--ssl-certfile', str(Path(args.ssl_certfile).absolute()), '--ssl-keyfile', str(Path(args.ssl_keyfile).absolute())]
    child = None
    pidfd = None
    server = socket.socket(socket.AF_UNIX)
    directory = os.open(scope, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        server.bind(f'/proc/self/fd/{directory}/s')
        server.listen(4)
        server.settimeout(.2)
        child = subprocess.Popen(command, cwd=root / 'server', stdin=subprocess.DEVNULL)
        pidfd = os.pidfd_open(child.pid)
        while child.poll() is None:
            try:
                connection, _ = server.accept()
            except socket.timeout:
                continue
            with connection:
                connection.settimeout(2)
                operation = connection.recv(32)
                if operation == b'stop':
                    signal.pidfd_send_signal(pidfd, signal.SIGTERM)
                    try:
                        child.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                        child.wait(timeout=2)
                    (scope / 's').unlink()
                    connection.sendall(b'{"state":"stopped"}')
                    return
                connection.sendall(json.dumps({'state': 'running', 'pid': child.pid}).encode())
    finally:
        if child is not None and child.poll() is None:
            # Only this directly owned child, with a retained stable identity.
            if pidfd is not None:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            else:
                child.kill()  # unreaped direct child cannot have a recycled PID
            child.wait(timeout=3)
        if pidfd is not None:
            os.close(pidfd)
        server.close()
        (scope / 's').unlink(missing_ok=True)
        os.close(directory)
        os.close(lock)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope', required=True, help='private, dedicated scope directory')
    parser.add_argument('action', choices=['start', 'stop', 'status', '_run'])
    parser.add_argument('--python', default=sys.executable)
    parser.add_argument('--config')
    parser.add_argument('--dist')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8090)
    parser.add_argument('--ssl-certfile')
    parser.add_argument('--ssl-keyfile')
    args = parser.parse_args()
    os.umask(0o077)
    scope = Path(args.scope).absolute()
    try:
        scope.mkdir(mode=0o700, parents=False, exist_ok=True)
        info = scope.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('scope must be owner-only directory')
        if args.action == '_run':
            run(args, scope)
            return 0
        if args.action in ('status', 'stop'):
            print(json.dumps(request(scope, args.action)))
            return 0
        if not args.config or not args.dist or not 1 <= args.port <= 65535:
            parser.error('start requires config, dist and valid port')
        if (scope / 's').exists():
            raise RuntimeError('scope occupied; inspect status, never guess cleanup')
        logfd = os.open(scope / 'console.log', os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        with os.fdopen(logfd, 'ab') as log:
            daemon = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--scope', str(scope), '_run',
                '--python', args.python, '--config', str(Path(args.config).absolute()), '--dist', str(Path(args.dist).absolute()),
                '--host', args.host, '--port', str(args.port),
                *(['--ssl-certfile', args.ssl_certfile] if args.ssl_certfile else []),
                *(['--ssl-keyfile', args.ssl_keyfile] if args.ssl_keyfile else [])],
                stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
        for _ in range(100):
            if daemon.poll() is not None:
                raise RuntimeError('scope startup failed; inspect private log')
            try:
                result = request(scope, 'status')
                print(json.dumps(result))
                return 0
            except (OSError, ValueError):
                time.sleep(.05)
        raise RuntimeError('scope startup unknown; inspect private log, do not guess kill')
    except Exception:
        print('console scope unavailable; inspect private scope/log; no guessed cleanup performed', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
