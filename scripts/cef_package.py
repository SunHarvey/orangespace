"""Pinned CEF package preflight. Does not download or run CEF."""
import argparse
import hashlib
import json
import re
import tarfile
import tempfile
import urllib.request
from pathlib import Path, PurePosixPath

LOCK_PATH = Path(__file__).resolve().parents[1] / 'apps/windows-client/cef/cef.lock.json'
REQUIRED_FILES = (
    'include/cef_version.h', 'include/cef_api_versions.h',
    'include/cef_sandbox_win.h', 'include/cef_version_info.h',
    'cmake/FindCEF.cmake', 'libcef_dll/CMakeLists.txt',
    'Release/bootstrap.exe', 'Release/chrome_elf.dll',
    'Release/libcef.lib', 'Release/libcef.dll',
)


def load_lock() -> dict:
    return json.loads(LOCK_PATH.read_text(encoding='utf-8'))


def verify_root(root: Path, lock: dict) -> None:
    for name in REQUIRED_FILES:
        path = root / name
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f'CEF required file missing or empty: {name}')
    version = (root / 'include/cef_version.h').read_text(encoding='utf-8')
    for macro, value in [('CEF_VERSION', lock['cef_version']),
                         ('CEF_COMMIT_HASH', lock['cef_commit']),
                         ('CEF_SANDBOX_COMPAT_HASH', lock['sandbox_compat'])]:
        if not re.search(r'^#define\s+' + macro + r'\s+"' + re.escape(value) + r'"\s*$', version, re.M):
            raise ValueError(f'CEF exact pin mismatch: {macro}')
    api = (root / 'include/cef_api_versions.h').read_text(encoding='utf-8')
    pattern = (r'#if defined\(OS_WIN\)\s*#define CEF_API_HASH_' +
               str(lock['api_version']) + r'\s+"' + lock['api_hash_windows'] + r'"')
    if not re.search(pattern, api):
        raise ValueError('CEF Windows API hash mismatch')


def verify_archive(path: Path, expected_sha1: str, expected_size: int, expected_sha256: str) -> None:
    if not re.fullmatch(r'[0-9a-f]{64}', expected_sha256):
        raise ValueError('CEF archive SHA-256 pin missing or invalid')
    if path.stat().st_size != expected_size:
        raise ValueError('CEF archive size mismatch')
    digest = hashlib.sha1()
    sha256 = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
            sha256.update(block)
    if digest.hexdigest() != expected_sha1:
        raise ValueError('CEF archive SHA-1 mismatch')
    if sha256.hexdigest() != expected_sha256:
        raise ValueError('CEF archive SHA-256 mismatch')


def extract_verified(archive: Path, destination: Path, lock: dict) -> None:
    """Extract once, without merging old content or trusting archive paths."""
    verify_archive(archive, lock['archive_sha1'], lock['archive_size'], lock.get('archive_sha256', ''))
    if destination.exists():
        raise ValueError('CEF extraction destination must not exist (no stale package merge)')
    destination.parent.mkdir(parents=True, exist_ok=True)
    top = lock['archive'].removesuffix('.tar.bz2')
    with tempfile.TemporaryDirectory(prefix='cef-extract-', dir=destination.parent) as temporary:
        staging = Path(temporary)
        with tarfile.open(archive, 'r:bz2') as tar:
            members = tar.getmembers()
            for member in members:
                parts = PurePosixPath(member.name).parts
                if (not parts or parts[0] != top or '..' in parts or
                        '\\' in member.name or ':' in member.name or
                        not (member.isfile() or member.isdir())):
                    raise ValueError(f'Unsafe CEF archive member: {member.name}')
            tar.extractall(staging, members=members, filter='data')
        extracted = staging / top
        verify_root(extracted, lock)
        extracted.rename(destination)


def check_index(lock: dict) -> None:
    """Small metadata-only lookup. Never follows a latest-version alias."""
    with urllib.request.urlopen(lock['index_url'], timeout=60) as response:
        index = json.load(response)
    for version in index[lock['platform']]['versions']:
        if version['cef_version'] != lock['cef_version']:
            continue
        for archive in version['files']:
            if archive['name'] == lock['archive']:
                if (archive['sha1'] != lock['archive_sha1'] or
                        archive['size'] != lock['archive_size'] or
                        version.get('sandbox_compat') != lock['sandbox_compat']):
                    raise ValueError('Official index no longer matches committed CEF pin')
                print('Official index matches exact version, archive size, SHA-1 and sandbox hash')
                return
    raise ValueError('Exact pinned CEF archive absent from official index')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-index', action='store_true', help='explicit small network lookup')
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--extract-to', type=Path)
    parser.add_argument('--root', type=Path, help='header/layout preflight only, not archive provenance')
    args = parser.parse_args()
    lock = load_lock()
    if not (args.archive or args.root or args.check_index):
        parser.error('specify --archive, --root or --check-index')
    if args.extract_to and not args.archive:
        parser.error('--extract-to requires --archive')
    if args.check_index:
        check_index(lock)
    if args.archive:
        if args.extract_to:
            extract_verified(args.archive, args.extract_to, lock)
        else:
            verify_archive(args.archive, lock['archive_sha1'], lock['archive_size'], lock.get('archive_sha256', ''))
        print('CEF archive integrity verified against committed pin')
    if args.root:
        verify_root(args.root, lock)
        print('CEF exact-version headers, Windows API hash and nonempty bootstrap layout verified')


if __name__ == '__main__':
    main()
