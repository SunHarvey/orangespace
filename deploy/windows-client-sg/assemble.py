"""Assemble an extracted Windows installer and ZIP; no credentials or native runs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import zipfile

INVENTORY = 'runtime.inventory.tsv'
MAX_FILES = 4096
MAX_ENTRIES = 8192
MAX_DEPTH = 16
MAX_TOTAL = 4 * 1024 * 1024 * 1024
MAX_METADATA = 1048576


def stream_hash(stream):
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1048576), b''):
        digest.update(chunk)
    return digest.hexdigest()


def file_hash(path):
    with Path(path).open('rb') as stream:
        return stream_hash(stream)


def bounded_bytes(path):
    if not 0 < Path(path).stat().st_size <= MAX_METADATA:
        raise ValueError('metadata resource limit')
    with Path(path).open('rb') as stream:
        raw = stream.read(MAX_METADATA + 1)
    if not 0 < len(raw) <= MAX_METADATA:
        raise ValueError('metadata resource limit')
    return raw
IDENTITY = {
    'schema': 1,
    'kind': 'orangespace-single-sg-install',
    'root_leaf': 'OrangeSpace-SinglePrototype-SG-v25-20261104',
    'state_leaf': 'OrangeSpace-SinglePrototype-SG-v25-State',
    'service_name': 'OrangeSpaceSinglePrototype.SG.v25',
    'service_exe': 'OrangeSpaceSinglePrototype.exe',
    'gui_exe': 'OrangeSpace.exe',
}


def valid_relative(value):
    if not value or len(value) > 220 or '\\' in value:
        return False
    parts = value.split('/')
    return all(re.fullmatch(r'[A-Za-z0-9_.-]+', p) and p not in ('.', '..')
               and not p.endswith('.') and not re.match(r'(?i)^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\.|$)', p)
               for p in parts)


def scan(root):
    root = Path(root)
    for parent in [root, *root.parents]:
        if parent.is_symlink():
            raise ValueError('symlink ancestor')
    files = {}
    names = set()
    total = 0
    pending = [(root, 0)]
    while pending:
        base, depth = pending.pop()
        with os.scandir(base) as entries:
          for entry in entries:
            path = Path(entry.path)
            rel = path.relative_to(root).as_posix()
            if len(names) >= MAX_ENTRIES or len(rel.split('/')) > MAX_DEPTH:
                raise ValueError('tree resource limit')
            meta = path.lstat()
            if re.search(r'(?i)(?:^|/)(?:profiles?|.*cache.*|cookies(?:\..*)?|credentials?.*|private[_-]?key.*|logs?|dumps?)(?:/|$)|\.(?:sqlite(?:3)?|db|log|dmp|dump|key|pem|pfx|p12|crt|cer)(?:$|[.-])', rel):
                raise ValueError('sensitive runtime path refused')
            if not valid_relative(rel) or rel.lower() in names or stat.S_ISLNK(meta.st_mode):
                raise ValueError('unsafe or colliding path')
            names.add(rel.lower())
            if stat.S_ISREG(meta.st_mode):
                if meta.st_nlink != 1:
                    raise ValueError('hardlink refused')
                if path.name in (INVENTORY, 'install-manifest.json', 'platform.json', 'nodes.json') and not 0 < meta.st_size <= MAX_METADATA:
                    raise ValueError('metadata resource limit')
                if rel != INVENTORY:
                    total += meta.st_size
                    if len(files) >= MAX_FILES or total > MAX_TOTAL:
                        raise ValueError('payload resource limit')
                    files[rel] = (None, meta.st_size)
            elif not stat.S_ISDIR(meta.st_mode):
                raise ValueError('special file refused')
            else:
                pending.append((path, depth + 1))
    return {name: (file_hash(root / name), size) for name, (_, size) in files.items()}


def write_inventory(root):
    files = scan(root)
    data = ''.join(f'{digest}\t{size}\t{name}\n' for name, (digest, size) in sorted(files.items()))
    if not data or len(data) > MAX_METADATA:
        raise ValueError('empty runtime')
    (Path(root) / INVENTORY).write_text(data, encoding='ascii', newline='\n')


def verify_inventory(root):
    raw = bounded_bytes(Path(root) / INVENTORY)
    if not raw.endswith(b'\n') or b'\r' in raw or len(raw) > 1048576:
        raise ValueError('inventory framing')
    expected = {}
    seen = set()
    for row in raw.decode('ascii').splitlines():
        if len(expected) >= MAX_FILES:
            raise ValueError('inventory resource limit')
        fields = row.split('\t')
        if len(fields) != 3:
            raise ValueError('inventory row')
        digest, size, name = fields
        if not re.fullmatch('[0-9a-f]{64}', digest) or not re.fullmatch('0|[1-9][0-9]{0,14}', size):
            raise ValueError('inventory value')
        if not valid_relative(name) or name.lower() in seen or name.lower() == INVENTORY:
            raise ValueError('inventory path')
        expected[name] = (digest, int(size))
        seen.add(name.lower())
    if not expected or len(expected) > 4096 or scan(root) != expected:
        raise ValueError('closed inventory mismatch')
    return expected


def assemble(runtime, output, *, service=None, gui=None, broker=None, config_dir=None, state_dir=None, state_pins=None, fresh_state=False):
    runtime, output = Path(runtime).absolute(), Path(output).absolute()
    for parent in output.parents:
        if parent.is_symlink():
            raise ValueError('output symlink ancestor')
    if output.exists() or output.with_suffix('.zip').exists() or output.is_relative_to(runtime):
        raise ValueError('fresh output outside runtime required')
    source = scan(runtime)
    overlays = {}
    for value, name in [(service, 'OrangeSpaceSinglePrototype.exe'), (gui, 'OrangeSpace.exe'), (broker, 'orangespace-broker.exe')]:
        if value is not None:
            path = Path(value)
            meta = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1:
                raise ValueError('overlay must be a single-link regular file')
            overlays[name] = path
    if config_dir:
        config_dir = Path(config_dir)
        for parent in [config_dir, *config_dir.parents]:
            if parent.is_symlink():
                raise ValueError('config symlink ancestor')
        for name in ('platform.json', 'nodes.json'):
            path = config_dir / name
            meta = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 or meta.st_uid != os.geteuid() or meta.st_mode & 0o077:
                raise ValueError('config requires owned mode-600 regular input')
            overlays[name] = path
    required = {'OrangeSpace.exe', 'OrangeSpaceSinglePrototype.exe', 'orangespace-broker.exe', 'client.exe', 'client.dll',
                'libcef.dll', 'sing-box.exe', 'platform.json', 'nodes.json'}
    if not required.issubset(source.keys() | overlays.keys()):
        raise ValueError('required payload missing')
    # Public configs only: the trusted builder supplies deployment values.
    # Freeze overlays once: validation and copying consume identical bytes.
    overlay_bytes = {}
    for name, path in overlays.items():
        for parent in path.parents:
            if parent.is_symlink():
                raise ValueError('overlay symlink ancestor')
        if path.stat().st_size > MAX_TOTAL:
            raise ValueError('overlay resource limit')
        overlay_bytes[name] = (file_hash(path), path.stat().st_size)
    configs = {name: bounded_bytes(overlays.get(name, runtime / name)).decode('utf-8-sig') for name in ('platform.json', 'nodes.json')}
    platform = json.loads(configs['platform.json'])
    if set(platform) != {'schema', 'api_origin'} or platform['schema'] != 1 or not platform['api_origin'].startswith('https://'):
        raise ValueError('public platform config rejected')
    json.loads(configs['nodes.json'])
    forbidden = re.compile(r'(?i)(password|access_token|refresh_token|private_key|client_secret|BEGIN [A-Z ]*PRIVATE KEY)')
    if any(forbidden.search(value) for value in configs.values()):
        raise ValueError('secret-bearing config rejected')
    identity = dict(IDENTITY)
    state_files = {}
    if not state_dir and not fresh_state:
        raise ValueError('explicit fresh-state required without retained state')
    if fresh_state and (state_dir or state_pins):
        raise ValueError('fresh-state conflicts with retained state')
    if fresh_state:
        identity['fresh_state'] = True
    if state_dir:
        if not state_pins:
            raise ValueError('external state pins required')
        if {path.name for path in Path(state_dir).iterdir()} != {'namespace.anchor', 'service-state.json'}:
            raise ValueError('exact preserved state directory required')
        for name in ('namespace.anchor', 'service-state.json'):
            bounded_bytes(Path(state_dir) / name)
        state_files = scan(state_dir)
        if set(state_files) != {'namespace.anchor', 'service-state.json'}:
            raise ValueError('exact preserved state pair required')
        state = json.loads((Path(state_dir) / 'service-state.json').read_text())
        if state.get('schema') not in (1, 2) or not isinstance(state.get('sandboxes'), list):
            raise ValueError('preserved ledger schema rejected')
        identity['initial_state'] = {name: {'sha256': digest, 'size': size} for name, (digest, size) in state_files.items()}
        if json.loads(bounded_bytes(state_pins)) != identity['initial_state']:
            raise ValueError('external state pin mismatch')
    expected_payload = dict(source)
    expected_payload.update(overlay_bytes)
    if len(expected_payload) + 1 > MAX_FILES or sum(size for _, size in expected_payload.values()) + MAX_METADATA > MAX_TOTAL:
        raise ValueError('combined payload resource limit')
    shutil.copytree(runtime, output / 'Runtime')
    for name, path in overlays.items():
        # Detach known build outputs rather than propagating their file identity.
        destination = output / 'Runtime' / name
        if destination.exists(): destination.unlink()
        with destination.open('xb') as stream:
            with path.open('rb') as source_stream:
                shutil.copyfileobj(source_stream, stream, 1048576)
    if scan(output / 'Runtime') != expected_payload:
        raise ValueError('runtime changed during copy')
    if state_dir:
        shutil.copytree(state_dir, output / 'State')
        if scan(output / 'State') != state_files:
            raise ValueError('preserved state copy mismatch')
    (output / 'Runtime' / 'install-manifest.json').write_text(json.dumps(identity, indent=2) + '\n', encoding='ascii')
    write_inventory(output / 'Runtime')
    verify_inventory(output / 'Runtime')
    for name in ('Install.cmd', 'Install.ps1', 'Start.cmd', 'Start.ps1', 'Uninstall.cmd', 'Uninstall.ps1', 'Common.ps1', 'README.txt'):
        shutil.copyfile(Path(__file__).parent / name, output / name)
    scan(output)  # Cap the complete uncompressed archive, including scripts and State.
    archive = output.with_suffix('.zip')
    with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for path in sorted(output.rglob('*')):
            if path.is_file():
                info = zipfile.ZipInfo(path.relative_to(output).as_posix(), date_time=(2026, 11, 4, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                with z.open(info, 'w', force_zip64=True) as dest, path.open('rb') as src:
                    shutil.copyfileobj(src, dest, 1048576)
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        for path in output.rglob('*'):
            if path.is_file():
                with z.open(path.relative_to(output).as_posix()) as stream:
                    if stream_hash(stream) != file_hash(path):
                        raise ValueError('archive readback mismatch')
    return archive


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', '--cef-runtime', dest='runtime', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--service', help='fresh built Service executable')
    parser.add_argument('--gui', help='fresh built ordinary-user GUI executable')
    parser.add_argument('--broker', help='fresh built broker executable, detached single link')
    parser.add_argument('--config-dir', help='owned mode-600 platform.json/nodes.json inputs')
    parser.add_argument('--state-dir', help='preserved exact same-namespace anchor/ledger pair')
    parser.add_argument('--state-pins', help='externally retained JSON name -> {sha256,size}; not generated from candidate State')
    parser.add_argument('--fresh-state', action='store_true', help='explicit genuinely new namespace only; forbidden for retained SG recovery')
    args = parser.parse_args()
    print(assemble(args.runtime, args.output, service=args.service, gui=args.gui, broker=args.broker, config_dir=args.config_dir, state_dir=args.state_dir, state_pins=args.state_pins, fresh_state=args.fresh_state))
