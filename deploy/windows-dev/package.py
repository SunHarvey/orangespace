"""Exact-file Windows development package policy; no config or user data."""
NAMES = ('OrangeSpace.exe', 'OrangeSpaceLogin.exe', 'OrangeSpaceService.exe',
         'orangespace-broker.exe', 'sing-box.exe')
HELPER_SHA256 = '8f30682ee198855440d2a7fe070d5d3653793b2d01bb8c85eea88f93bbe7c8b9'

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat


def regular(path):
    s = path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or getattr(s, 'st_file_attributes', 0) & 0x400:
        raise ValueError('not a unique ordinary file')
    return s


def validate_rows(rows):
    if not isinstance(rows, list) or len(rows) != len(NAMES):
        raise ValueError('manifest cardinality')
    if {r.get('name') for r in rows} != set(NAMES):
        raise ValueError('manifest exact allowlist')
    for r in rows:
        if set(r) != {'name', 'size', 'sha256'} or type(r['size']) is not int or r['size'] <= 0:
            raise ValueError('manifest size/schema')
        if not isinstance(r['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', r['sha256']):
            raise ValueError('manifest digest')
        if r['name'] == 'sing-box.exe' and r['sha256'] != HELPER_SHA256:
            raise ValueError('helper hash')


def inventory(root, packaged=False):
    # abspath preserves links for lstat: resolve() would hide a junction/symlink.
    root = Path(__import__('os').path.abspath(root))
    for directory in (root, *root.parents):
        s = directory.lstat()
        if not stat.S_ISDIR(s.st_mode) or getattr(s, 'st_file_attributes', 0) & 0x400:
            raise ValueError('source directory or ancestor is not ordinary')
    expected = set(NAMES) | ({'manifest.json'} if packaged else set())
    if {p.name for p in root.iterdir()} != expected:
        raise ValueError('unexpected or missing package entry; config/data are forbidden')
    rows = []
    for name in NAMES:
        path = root / name
        s = regular(path)
        data = path.read_bytes()
        if not data.startswith(b'MZ'):
            raise ValueError('not a PE candidate')
        rows.append(dict(name=name, size=s.st_size, sha256=hashlib.sha256(data).hexdigest()))
    validate_rows(rows)
    return rows


def install_identity(suffix):
    if not isinstance(suffix, str) or (suffix and not re.fullmatch(r'[a-z0-9-]{1,24}', suffix)):
        raise ValueError('invalid development install identity')
    return dict(development_install_id=suffix,
                service_name='OrangeSpaceFoundation' + ('.Dev.' + suffix if suffix else ''),
                pipe_prefix=r'\\.\pipe\OrangeSpace.Foundation' + ('.Dev.' + suffix if suffix else '') + '.v1.session.')


def validate_identity_manifest(manifest):
    base = {'schema', 'kind', 'files'}
    keys = {'development_install_id', 'service_name', 'pipe_prefix'}
    if set(manifest) == base:
        return install_identity('')
    if set(manifest) != base | keys:
        raise ValueError('manifest schema')
    identity = install_identity(manifest['development_install_id'])
    if not identity['development_install_id'] or any(manifest[k] != v for k, v in identity.items()):
        raise ValueError('manifest namespace mismatch')
    return identity


def validate_binary_identity(root, identity):
    marker = 'OrangeSpace.InstallIdentity.v1|'.encode('utf-16le')
    expected = ('OrangeSpace.InstallIdentity.v1|' + identity['development_install_id'] + '|' +
                identity['service_name'] + '\0' + identity['pipe_prefix'] + '\0').encode('utf-16le')
    for name in NAMES[:3]:
        data = (Path(root) / name).read_bytes()
        records = list(re.finditer(re.escape(marker), data))
        if identity['development_install_id'] and not records:
            raise ValueError('binary namespace provenance missing')
        for record in records:
            if record.start() % 2 or not data.startswith(expected, record.start()):
                raise ValueError('binary namespace provenance mismatch')


def verify(root):
    root = Path(root)
    regular(root / 'manifest.json')
    m = json.loads((root / 'manifest.json').read_text(encoding='utf-8'))
    identity = validate_identity_manifest(m)
    if m['schema'] != 1 or m['kind'] != 'orangespace-windows-dev':
        raise ValueError('manifest schema')
    validate_rows(m['files'])
    rows = inventory(root, packaged=True)
    if rows != m['files']:
        raise ValueError('size/hash/order mismatch')
    validate_binary_identity(root, identity)
    return m


def create(source, target, development_install_id=''):
    identity = install_identity(development_install_id)
    source, target = Path(source), Path(target)
    if target.exists() or target.is_symlink():
        raise FileExistsError('existing target refused')
    rows = inventory(source)
    validate_binary_identity(source, identity)
    target.mkdir(parents=False)
    # No general rollback: partial owned target remains for explicit inspection.
    for name in NAMES:
        shutil.copyfile(source / name, target / name)
    manifest = dict(schema=1, kind='orangespace-windows-dev', files=rows)
    if development_install_id:
        manifest.update(identity)
    (target / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    return verify(target)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    c = sub.add_parser('create')
    c.add_argument('source', type=Path)
    c.add_argument('target', type=Path)
    c.add_argument('--development-install-id', default='')
    v = sub.add_parser('verify')
    v.add_argument('target', type=Path)
    args = parser.parse_args()
    try:
        result = create(args.source, args.target, args.development_install_id) if args.action == 'create' else verify(args.target)
    except (OSError, ValueError, TypeError, KeyError):
        parser.exit(1, 'Package rejected (scope, manifest, file or pinned helper policy).\n')
    print(json.dumps(result, indent=2))
