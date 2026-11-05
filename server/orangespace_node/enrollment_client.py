"""Source-only Ed25519 possession enrollment; administrator activation is separate.

Run from the installed package: python -m orangespace_node.enrollment_client
--config /absolute/private.json. The owner-only JSON has exactly origin,
node_id, node_api_origin, enrollment_id, enrollment_token, private_key_file,
output_dir, and optional ca_file. All file paths must be absolute. output_dir
must not exist; its parent must already exist and be owner-protected.

No retries or remote deletion. A retained scope (including empty/partial files)
is NOT a completed enrollment. After any failure check central pending status
before using a new scope/token. Two file writes are not an atomic transaction.
Injected transports are protocol-model testing seams, not HTTPS evidence.
"""
import argparse
import asyncio
import base64
import hashlib
import json
import os
import re
import stat
import time
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .control_identity import tls_verify

CAP = 16384
MAX_INT = 9007199254740991
FAILURE = 'enrollment failed; retain scope and verify central pending status before retry'


class EnrollmentError(ValueError):
    """Fixed, secret-free failure; never include server or OS exception text."""

    def __init__(self):
        super().__init__(FAILURE)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def _json(raw):
    if len(raw) > CAP:
        raise ValueError()
    data = json.loads(raw, object_pairs_hook=_unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    if type(data) is not dict:
        raise ValueError()
    return data


def _uuid(value):
    if type(value) is not str or str(UUID(value)) != value or not UUID(value).int:
        raise ValueError()
    return value


def _integer(value, minimum=1):
    if type(value) is not int or not minimum <= value <= MAX_INT:
        raise ValueError()
    return value


def _token(value, size=32):
    if type(value) is not str or not re.fullmatch(r'[A-Za-z0-9_-]+', value):
        raise ValueError()
    raw = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    if len(raw) != size or _encode(raw) != value:
        raise ValueError()
    return value


def _encode(value):
    return base64.urlsafe_b64encode(value).decode('ascii').rstrip('=')


def _origin(value):
    if type(value) is not str or len(value) > 512 or any(ord(c) <= 32 or ord(c) >= 127 for c in value):
        raise ValueError()
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.path or parsed.query or parsed.fragment
            or parsed.port == 0 or value != 'https://' + parsed.netloc or '\\' in value):
        raise ValueError()


def _parent(path):
    """Walk without following symlinks; hold the final parent descriptor."""
    path = os.fspath(path)
    if not os.path.isabs(path) or '\0' in path or any(p in ('.', '..', '') for p in path.split('/')[1:]):
        raise ValueError()
    parts = path.split('/')[1:]
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = next_fd
            info = os.fstat(fd)
            # Root-owned sticky temporary roots are safe traversal points;
            # writable non-sticky ancestors can replace protected descendants.
            sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if info.st_uid not in (0, os.geteuid()) or (info.st_mode & 0o022 and not sticky_root):
                raise ValueError()
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise


def _protected(path):
    parent, leaf = _parent(path)
    try:
        parent_info = os.fstat(parent)
        if parent_info.st_uid not in (0, os.geteuid()) or parent_info.st_mode & 0o022:
            raise ValueError()
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink != 1 or not 0 < info.st_size <= CAP):
            raise ValueError()
        raw = os.read(fd, CAP + 1)
        if len(raw) != info.st_size:
            raise ValueError()
        return raw
    finally:
        os.close(fd)


def load_config(path):
    data = _json(_protected(path))
    required = {'origin', 'node_id', 'node_api_origin', 'enrollment_id',
                'enrollment_token', 'private_key_file', 'output_dir'}
    if not required <= set(data) or set(data) - required - {'ca_file'}:
        raise ValueError()
    _origin(data['origin']); _origin(data['node_api_origin'])
    _uuid(data['node_id']); _uuid(data['enrollment_id']); _token(data['enrollment_token'])
    for field in ('private_key_file', 'output_dir', 'ca_file'):
        if field in data and (type(data[field]) is not str or not os.path.isabs(data[field])):
            raise ValueError()
    return data


def _scope(path):
    parent, leaf = _parent(path)
    directory = None
    files = []
    try:
        info = os.fstat(parent)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError()
        os.mkdir(leaf, 0o700, dir_fd=parent)  # Exclusive scope, never reused/deleted.
        directory = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        os.fchmod(directory, 0o700)
        info = os.fstat(directory)
        if info.st_uid != os.geteuid() or info.st_mode & 0o777 != 0o700:
            raise ValueError()
        for name in ('machine.json', 'federation.json'):
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=directory)
            files.append(fd)
            os.fchmod(fd, 0o600)
        os.fsync(directory); os.fsync(parent)
        return directory, files
    except BaseException:
        for fd in files:
            os.close(fd)
        if directory is not None:
            os.close(directory)
        raise
    finally:
        os.close(parent)


async def _post(client, url, payload, status):
    async with client.stream('POST', url, json=payload, headers={'Accept': 'application/json'}) as response:
        if response.status_code != status:
            raise ValueError()
        raw = bytearray()
        async for chunk in response.aiter_bytes():
            if len(raw) + len(chunk) > CAP:
                raise ValueError()
            raw.extend(chunk)
        return _json(raw)


def _write(fd, value):
    raw = json.dumps(value, separators=(',', ':'), ensure_ascii=True).encode('ascii') + b'\n'
    view = memoryview(raw)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            raise OSError()
        view = view[count:]
    os.fsync(fd)


async def enroll(config_path, *, transport=None, now=time.time):
    """Return public receipt only. Never retry an unknown completion outcome."""
    directory = None
    files = []
    try:
        config = load_config(config_path)
        key = serialization.load_pem_private_key(_protected(config['private_key_file']), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError()
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        fingerprint = hashlib.sha256(public).hexdigest()
        verify = tls_verify({'ca_file': config['ca_file']} if 'ca_file' in config else {})
        directory, files = _scope(config['output_dir'])
        async with httpx.AsyncClient(verify=verify, trust_env=False, follow_redirects=False,
                                     timeout=10, transport=transport) as client:
            base = config['origin'] + '/control/v1/node-enrollments/' + config['enrollment_id']
            challenge = await _post(client, base + '/challenge', dict(
                schema=1, enrollment_token=config['enrollment_token'], node_id=config['node_id'],
                public_key=_encode(public)), 200)
            if (set(challenge) != {'schema', 'challenge_id', 'nonce', 'expires_at'}
                    or type(challenge['schema']) is not int or challenge['schema'] != 1):
                raise ValueError()
            _uuid(challenge['challenge_id']); _token(challenge['nonce'])
            expiry = _integer(challenge['expires_at'])
            if not now() < expiry <= now() + 60:
                raise ValueError()
            values = [config['enrollment_id'], config['node_id'], fingerprint, config['node_api_origin'],
                      challenge['challenge_id'], challenge['nonce'], str(expiry)]
            message = b'OrangeSpace-enroll-v1\n' + b''.join(
                str(len(v.encode('utf8'))).encode('ascii') + b':' + v.encode('utf8') for v in values)
            signature = _encode(key.sign(message))
            if now() >= expiry:
                raise ValueError()
            complete = await _post(client, base + '/complete', dict(
                schema=1, enrollment_token=config['enrollment_token'], challenge_id=challenge['challenge_id'],
                signature=signature), 201)
            if (set(complete) != {'schema', 'node_id', 'node_epoch', 'node_access_token', 'config_revision'}
                    or type(complete['schema']) is not int or complete['schema'] != 1
                    or _uuid(complete['node_id']) != config['node_id']):
                raise ValueError()
            _integer(complete['node_epoch']); _integer(complete['config_revision'])
            _token(complete['node_access_token'])
            machine = dict(origin=config['origin'], token=complete['node_access_token'],
                           node_id=config['node_id'], node_epoch=complete['node_epoch'],
                           config_revision=complete['config_revision'])
            if 'ca_file' in config:
                machine['ca_file'] = config['ca_file']
            _write(files[0], machine)
            _write(files[1], dict(machine, node_api_origin=config['node_api_origin']))
            os.fsync(directory)
        return dict(node_id=config['node_id'], fingerprint=fingerprint, state='pending',
                    machine_config=config['output_dir'] + '/machine.json',
                    federation_config=config['output_dir'] + '/federation.json')
    except Exception:
        raise EnrollmentError() from None
    finally:
        for fd in files:
            os.close(fd)
        if directory is not None:
            os.close(directory)


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise EnrollmentError()


def main(argv=None):
    parser = _Parser(description='Node possession enrollment; activation requires administrator approval', allow_abbrev=False)
    parser.add_argument('--config', required=True, help='absolute owner-only JSON configuration path')
    try:
        args = parser.parse_args(argv)
        receipt = asyncio.run(enroll(args.config))
    except (EnrollmentError, KeyboardInterrupt):
        print(FAILURE)
        return 1
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
