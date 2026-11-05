#!/usr/bin/env python3
"""Offline, clean-checkout development packaging. No installation or services."""
import argparse
from email.parser import BytesParser
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE_REPO = ROOT
TEMP = Path('/var/tmp/hermes-runtime/tmp')
PIN = json.loads((Path(__file__).parent / 'dependencies.json').read_text())


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(args, cwd=None):
    # Do not relay potentially credential-bearing package-manager diagnostics.
    result = subprocess.run(list(map(str, args)), cwd=cwd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=ENV)
    if result.returncode:
        raise ValueError('build subprocess failed: ' + Path(str(args[0])).name)
    return result.stdout.decode('utf-8', errors='strict').strip()


def ordinary(path):
    path = Path(path)
    for parent in path.parents:
        if parent.is_symlink():
            raise ValueError('symlink ancestor refused')
    s = path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1:
        raise ValueError('non-unique ordinary file refused')
    return path.read_bytes()


def safe_name(name):
    p = PurePosixPath(name)
    if not name or p.is_absolute() or '..' in p.parts or '\\' in name or ':' in name:
        raise ValueError('unsafe archive member')
    return p


def scan(name, data):
    safe_name(name)
    parts = PurePosixPath(name).parts
    if any(p.lower() in {'profile', 'profiles', '.git', '__pycache__', '.venv', 'node_modules'} for p in parts):
        raise ValueError('runtime directory refused')
    if name.lower().endswith(('.pem', '.key', '.p12', '.db', '.sqlite', '.sqlite3', '.log', '.pyc')):
        raise ValueError('runtime/secret file refused')
    if re.search(rb'-----BEGIN (?:[A-Z ]*PRIVATE KEY)-----', data):
        raise ValueError('private key material refused')
    if re.search(rb'(?:mysql(?:\+pymysql)?|postgres(?:ql)?)://[^\s/]+:[^\s/@]+@(?!mysql\.example\.invalid)', data):
        raise ValueError('credential-bearing connection string refused')


def checked_archive(data, kind):
    rows = []
    if kind == 'zip':
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for m in z.infolist():
                safe_name(m.filename)
                if m.is_dir():
                    continue
                if stat.S_ISLNK(m.external_attr >> 16):
                    raise ValueError('archive link refused')
                rows.append((m.filename, z.read(m)))
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as t:
            for m in t:
                safe_name(m.name)
                if m.isdir():
                    continue
                if not m.isfile():
                    raise ValueError('archive link/special file refused')
                stream = t.extractfile(m)
                if stream is None:
                    raise ValueError('missing archive file stream')
                rows.append((m.name, stream.read()))
    if len({n for n, _ in rows}) != len(rows):
        raise ValueError('duplicate member refused')
    return rows


def copy(src, dst):
    data = ordinary(src)
    scan(dst.name, data)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(data)
    dst.chmod(0o755 if src.suffix == '.sh' or src.name == 'sing-box' else 0o644)


def requirements(path):
    result = {}
    for line in path.read_text().splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        m = re.fullmatch(r'([A-Za-z0-9_.-]+)==([^;\s]+)(?:;.*)?', line)
        if not m:
            raise ValueError('requirements must be exactly pinned')
        result[re.sub('[-_.]+', '-', m[1]).lower()] = m[2]
    return result


def wheelhouse(directory, manifest, wanted, output):
    """External hash inventory is an explicitly reviewed trust input, not TOFU."""
    hashes = json.loads(ordinary(manifest))
    if not isinstance(hashes, dict) or not hashes:
        raise ValueError('wheelhouse hash inventory required')
    found, lines = {}, []
    output.mkdir()
    for name, expected in sorted(hashes.items()):
        if Path(name).name != name or not name.endswith('.whl') or not re.fullmatch('[0-9a-f]{64}', expected):
            raise ValueError('invalid wheelhouse inventory')
        data = ordinary(directory / name)
        if digest(data) != expected:
            raise ValueError('wheelhouse digest mismatch')
        rows = checked_archive(data, 'zip')
        metas = [b for n, b in rows if n.endswith('.dist-info/METADATA')]
        if len(metas) != 1:
            raise ValueError('wheel metadata cardinality')
        m = BytesParser().parsebytes(metas[0])
        package = re.sub('[-_.]+', '-', m['Name']).lower()
        if package not in wanted or wanted[package] != m['Version']:
            continue
        found[package] = m['Version']
        lines.append(f'{package}=={m["Version"]} --hash=sha256:{expected}')
        (output / name).write_bytes(data)
    if found != wanted:
        raise ValueError('missing pinned build/runtime wheel dependency')
    lock = output.parent / 'requirements-hashed.lock'
    lock.write_text('\n'.join(lines) + '\n')
    return lock


def windows_helper(deps):
    """Return only the uniquely named, pinned executable from the official ZIP."""
    pin = PIN['helper']
    data = ordinary(deps / pin['windows_archive'])
    if digest(data) != pin['windows_archive_sha256']:
        raise ValueError('official Windows helper archive digest mismatch')
    rows = checked_archive(data, 'zip')
    candidates = [b for n, b in rows if PurePosixPath(n).name.lower() == 'sing-box.exe']
    if len(candidates) != 1 or digest(candidates[0]) != pin['windows_binary_sha256']:
        raise ValueError('Windows helper binary mismatch')
    return candidates[0]


def helper(deps, stage, role):
    pin = PIN['helper']
    for name in ['sing-box-v1.14.4-source.tar.gz', 'LICENSE.sing-box', 'COPYING.GPL-3.0']:
        data = ordinary(deps / name)
        if digest(data) != pin['files'][name]:
            raise ValueError('helper source/license digest mismatch')
        copy(deps / name, stage / 'third-party' / name)
    # Verify source archive structure without extracting anything.
    checked_archive(ordinary(deps / 'sing-box-v1.14.4-source.tar.gz'), 'tar')
    if role == 'node':
        data = ordinary(deps / pin['linux_archive'])
        if digest(data) != pin['linux_archive_sha256']:
            raise ValueError('official helper archive digest mismatch')
        rows = checked_archive(data, 'tar')
        candidates = [b for n, b in rows if PurePosixPath(n).name == 'sing-box']
        if len(candidates) != 1 or digest(candidates[0]) != pin['linux_binary_sha256']:
            raise ValueError('helper binary mismatch')
        target = stage / 'runtime/sing-box'
        target.parent.mkdir()
        target.write_bytes(candidates[0])
        target.chmod(0o755)
    else:
        windows_helper(deps)
    (stage / 'third-party/UPSTREAM.json').write_text(json.dumps(pin, indent=2) + '\n')


def node_tools_compatible(node, npm):
    return (re.fullmatch(r'v26\.\d+\.\d+', node) is not None
            and re.fullmatch(r'(?:11|12)\.\d+\.\d+', npm) is not None)


def package_examples(role, stage):
    if role == 'node':
        copy(ROOT / 'deploy/packages/node/database.example.json', stage / 'examples/database.example.json')
        copy(ROOT / 'server/alembic-node.ini', stage / 'server/alembic-node.ini')
        for name in ['node-a.runtime.example.json', 'node-b.runtime.example.json']:
            copy(ROOT / 'deploy/linux-node' / name, stage / 'deploy/linux-node' / name)
    elif role == 'windows':
        for name in ['platform.example.json', 'nodes.example.json', 'service-state.fresh-only.example.json']:
            copy(ROOT / 'deploy/packages/windows/examples' / name, stage / 'examples' / name)


def install_identity(suffix):
    if not isinstance(suffix, str) or (suffix and not re.fullmatch(r'[a-z0-9-]{1,24}', suffix)):
        raise ValueError('invalid development install identity')
    return {'development_install_id': suffix,
            'service_name': 'OrangeSpaceFoundation' + ('.Dev.' + suffix if suffix else ''),
            'pipe_prefix': r'\\.\pipe\OrangeSpace.Foundation' + ('.Dev.' + suffix if suffix else '') + '.v1.session.'}


def gnu_commands(work, rust, development_install_id=''):
    install_identity(development_install_id)
    native = work / 'native'
    runtime = rust / 'x86_64-pc-windows-gnu/release/liborangespace_runtime.a'
    return [
        ['cargo', 'build', '--locked', '--offline', '--release', '--jobs', '1',
         '--target', 'x86_64-pc-windows-gnu', '--target-dir', str(rust),
         '-p', 'orangespace-runtime', '-p', 'orangespace-broker'],
        ['cmake', '-S', str(ROOT), '-B', str(native), '-G', 'Unix Makefiles',
         '-DCMAKE_SYSTEM_NAME=Windows', '-DCMAKE_BUILD_TYPE=Release', '-DBUILD_TESTING=OFF',
         '-DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++-posix',
         '-DCMAKE_RC_COMPILER=x86_64-w64-mingw32-windres',
         '-DCMAKE_EXE_LINKER_FLAGS=-static -static-libgcc -static-libstdc++',
         '-DORANGESPACE_WITH_CEF=OFF', f'-DORANGESPACE_DEVELOPMENT_INSTALL_ID={development_install_id}', f'-DORANGESPACE_RUNTIME_LIBRARY={runtime}'],
        ['cmake', '--build', str(native), '--parallel', '1', '--target',
         'OrangeSpace', 'OrangeSpaceLogin', 'OrangeSpaceService'],
    ]


def materialize_rust_broker(work):
    """Detach only Cargo's broker output in our fresh private build directory."""
    source = work / 'rust/x86_64-pc-windows-gnu/release/orangespace-broker.exe'
    for parent in source.parents:
        if parent.is_symlink():
            raise ValueError('symlink ancestor refused')
    before = source.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError('non-ordinary Rust broker refused')
    # Cargo hardlinks release/deps outputs. Never apply this exception to inputs.
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError('Rust broker changed during materialization')
        data = stream.read()
    staging = work / 'materialized-rust-broker'
    staging.mkdir(mode=0o700)
    target = staging / 'orangespace-broker.exe'
    with target.open('xb') as stream:
        stream.write(data)
    if ordinary(target) != data:
        raise ValueError('Rust broker materialization readback mismatch')
    return target


def windows_gnu(deps, stage, work, versions, development_install_id=''):
    versions['windows_builder'] = 'linux-windows-gnu; build-only, not native acceptance'
    for key, command in [('rust', ['rustc', '--version']), ('cargo', ['cargo', '--version']),
                         ('cmake', ['cmake', '--version']),
                         ('mingw_cxx', ['x86_64-w64-mingw32-g++-posix', '--version']),
                         ('mingw_rc', ['x86_64-w64-mingw32-windres', '--version']),
                         ('make', ['make', '--version'])]:
        versions[key] = run(command).splitlines()[0]
    targets = run(['rustup', 'target', 'list', '--installed']).splitlines()
    if 'x86_64-pc-windows-gnu' not in targets:
        raise ValueError('installed Windows GNU Rust target required')
    rust = work / 'rust'
    rust.mkdir(mode=0o700)  # Cargo output must belong to this fresh build, never a cache/input.
    for command in gnu_commands(work, rust, development_install_id):
        run(command, ROOT)
    exact = work / 'exact-programs'
    exact.mkdir()
    for name in ['OrangeSpace.exe', 'OrangeSpaceLogin.exe']:
        copy(work / 'native/apps/windows-client' / name, exact / name)
    copy(work / 'native/apps/windows-service/OrangeSpaceService.exe', exact / 'OrangeSpaceService.exe')
    copy(materialize_rust_broker(work), exact / 'orangespace-broker.exe')
    (exact / 'sing-box.exe').write_bytes(windows_helper(deps))
    # Reject external compiler runtime DLLs; Windows system CRT remains permitted.
    versions['pe_imports'] = {}
    for exe in sorted(exact.glob('*.exe')):
        imports = re.findall(r'DLL Name:\s*(\S+)', run(['x86_64-w64-mingw32-objdump', '-p', exe]))
        if not imports or any(re.match(r'(libgcc|libstdc\+\+|libwinpthread|vcruntime|msvcp)', n, re.I) for n in imports):
            raise ValueError('external compiler runtime dependency refused')
        versions['pe_imports'][exe.name] = imports
    run([sys.executable, ROOT / 'deploy/windows-dev/package.py', 'create', exact, stage / 'payload',
         '--development-install-id', development_install_id])
    run([sys.executable, ROOT / 'deploy/windows-dev/package.py', 'verify', stage / 'payload'])


def build(args, work, commit):
    stage = work / ('orangespace-' + args.role + '-dev')
    stage.mkdir()
    copy(ROOT / f'deploy/packages/{args.role}/README-DEV.md', stage / 'README-DEV.md')
    versions = {'python': sys.version.split()[0]}
    inputs = {'dependencies.json': digest(ordinary(Path(__file__).parent / 'dependencies.json'))}
    if args.role in {'control', 'node'}:
        wanted = requirements(ROOT / 'server/requirements.lock')
        if any(k in wanted and wanted[k] != v for k, v in PIN['python_build'].items()):
            raise ValueError('runtime/build dependency pins disagree')
        wanted.update(PIN['python_build'])
        lock = wheelhouse(args.deps / 'wheels', args.deps / 'wheels.sha256.json', wanted, work / 'wheels')
        inputs['wheelhouse_inventory_sha256'] = digest(ordinary(args.deps / 'wheels.sha256.json'))
        venv = work / 'venv'
        run([sys.executable, '-I', '-m', 'venv', venv])
        py = venv / 'bin/python'
        run([py, '-I', '-m', 'pip', '--isolated', 'install', '--no-index', '--only-binary=:all:',
             '--find-links', work / 'wheels', '--require-hashes', '-r', lock])
        versions['python_packages'] = json.loads(run([py, '-I', '-m', 'pip', '--isolated', 'list', '--format=json']))
        run([py, '-I', '-m', 'pip', '--isolated', 'wheel', '--no-deps', '--no-build-isolation',
             '--no-index', '--wheel-dir', work / 'wheel', ROOT / 'server'])
        wheels = list((work / 'wheel').glob('*.whl'))
        if len(wheels) != 1:
            raise ValueError('one unified server wheel required')
        wheelrows = checked_archive(ordinary(wheels[0]), 'zip')
        for name, data in wheelrows:
            scan(name, data)
        required = {'orangespace_node', 'orangespace_control', 'orangespace_common', 'node_migrations', 'control_migrations'}
        if not required <= {n.split('/')[0] for n, _ in wheelrows}:
            raise ValueError('unified server wheel incomplete')
        copy(wheels[0], stage / 'server' / wheels[0].name)
        copy(ROOT / 'server/requirements.lock', stage / 'server/requirements.lock')
        if args.role == 'control':
            versions['node'] = run(['node', '--version'])
            versions['npm'] = run(['npm', '--version'])
            if not node_tools_compatible(versions['node'], versions['npm']):
                raise ValueError('Node/npm compatibility constraint mismatch')
            frontend = work / 'console'
            shutil.copytree(ROOT / 'apps/control-console', frontend)
            run(['npm', 'ci', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--cache', args.deps / 'npm-cache'], frontend)
            run(['npm', 'run', 'typecheck'], frontend)
            run(['npm', 'run', 'build'], frontend)
            for f in sorted((frontend / 'dist').rglob('*')):
                if f.is_file():
                    copy(f, stage / 'apps/control-console/dist' / f.relative_to(frontend / 'dist'))
            if not (stage / 'apps/control-console/dist/index.html').is_file():
                raise ValueError('Vue dist missing')
            for name in ['README.md', 'console.py', 'start.sh', 'stop.sh', 'status.sh', 'orangespace-control.service.in']:
                copy(ROOT / 'deploy/dev' / name, stage / 'deploy/dev' / name)
            copy(ROOT / 'deploy/packages/control/control.example.json', stage / 'examples/control.example.json')
            copy(ROOT / 'deploy/packages/control/alembic-control.ini', stage / 'server/alembic-control.ini')
        else:
            helper(args.deps, stage, args.role)
            for name in ['README.md', 'VERIFICATION.md', 'node-a.runtime.example.json', 'node-b.runtime.example.json', 'orangespace-linux-node@.service']:
                copy(ROOT / 'deploy/linux-node' / name, stage / 'deploy/linux-node' / name)
            copy(ROOT / 'server/TUNNELS.md', stage / 'server/TUNNELS.md')
    else:
        helper(args.deps, stage, args.role)
        if args.windows_builder == 'gnu':
            windows_gnu(args.deps, stage, work, versions, args.development_install_id)
        else:
            # Optional existing WSL/native coordinator; never required for GNU.
            def win(path):
                return run(['wslpath', '-w', path])
            versions['windows_builder'] = 'wsl-native'
            versions['cargo'] = run(['cargo.exe', '--version'])
            versions['cmake'] = run(['cmake.exe', '--version']).splitlines()[0]
            helper_path = work / 'sing-box.exe'
            helper_path.write_bytes(windows_helper(args.deps))
            run([args.powershell, '-NoProfile', '-File', win(ROOT / 'deploy/windows-dev/Build.ps1'),
                 '-BuildRoot', win(work / 'native-build'), '-Helper', win(helper_path),
                 '-Output', win(stage / 'payload'), '-Offline'])
        for name in ['Common.ps1', 'Service.ps1', 'Start.ps1', 'Build.ps1', 'package.py']:
            copy(ROOT / 'deploy/windows-dev' / name, stage / 'tools' / name)
    package_examples(args.role, stage)
    # Check source again before attesting it. Output/temp never live in checkout.
    if run(['git', 'status', '--porcelain', '--untracked-files=all'], SOURCE_REPO) or run(['git', 'rev-parse', 'HEAD'], SOURCE_REPO) != commit:
        raise ValueError('source changed during build')
    for name in ['server/requirements.lock', 'server/pyproject.toml', 'apps/control-console/package-lock.json', 'Cargo.lock']:
        inputs[name] = digest(ordinary(ROOT / name))
    files = []
    for path in sorted(stage.rglob('*')):
        if path.is_file():
            data = ordinary(path)
            name = path.relative_to(stage).as_posix()
            scan(name, data)
            files.append({'name': name, 'size': len(data), 'sha256': digest(data)})
    manifest = {'schema': 2, 'role': args.role, 'source_commit': commit, 'source_clean': True,
                'dependencies': PIN, 'dependency_inputs': inputs, 'tool_versions': versions,
                'security_scan': {'policy': 'allowlisted-inputs+ordinary-files+archive-paths+private-key+DSN-v1',
                                  'passed': True, 'not_a_complete_secret_detector': True},
                'files': files, 'browser_allowed': False, 'acceptance': 'build-only; no runtime acceptance inherited'}
    if args.role == 'windows' and args.development_install_id:
        manifest.update(install_identity(args.development_install_id))
    (stage / 'BUILD-MANIFEST.json').write_text(json.dumps(manifest, indent=2) + '\n')
    paths = sorted(p for p in stage.rglob('*') if p.is_file())
    sums = ''.join(f'{digest(ordinary(p))}  {p.relative_to(stage).as_posix()}\n' for p in paths)
    (stage / 'SHA256SUMS').write_text(sums)
    output = args.output
    if args.role == 'windows':
        with zipfile.ZipFile(output, 'x', zipfile.ZIP_DEFLATED) as z:
            for path in sorted(stage.rglob('*')):
                if path.is_file():
                    z.write(path, stage.name + '/' + path.relative_to(stage).as_posix())
        kind = 'zip'
    else:
        with tarfile.open(output, 'x:gz') as t:
            t.add(stage, arcname=stage.name)
        kind = 'tar'
    expected = {stage.name + '/' + p.relative_to(stage).as_posix(): digest(ordinary(p))
                for p in stage.rglob('*') if p.is_file()}
    actual = {n: digest(b) for n, b in checked_archive(ordinary(output), kind)}
    if actual != expected:
        raise ValueError('archive readback mismatch')
    receipt = {'archive': output.name, 'sha256': digest(ordinary(output)), 'members': len(actual),
               'source_commit': commit, 'archive_member_readback_verified': True}
    output.with_name(output.name + '.receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt))


ENV = {k: v for k, v in os.environ.items() if k in {'PATH', 'HOME', 'SystemRoot', 'WINDIR', 'WSLENV'}}
ENV.update(TMPDIR=str(TEMP), CARGO_BUILD_JOBS='1', CMAKE_BUILD_PARALLEL_LEVEL='1',
           CARGO_NET_OFFLINE='true', PYTHONDONTWRITEBYTECODE='1', npm_config_jobs='1',
           CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER='x86_64-w64-mingw32-gcc-posix',
           CC_x86_64_pc_windows_gnu='x86_64-w64-mingw32-gcc-posix',
           CXX_x86_64_pc_windows_gnu='x86_64-w64-mingw32-g++-posix',
           CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUSTFLAGS='-C target-feature=+crt-static')


def main():
    global ROOT
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('role', choices=['control', 'node', 'windows'])
    p.add_argument('--deps', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--powershell', default='powershell.exe')
    p.add_argument('--windows-builder', choices=['gnu', 'wsl-native'], default='gnu')
    p.add_argument('--development-install-id', default='', type=lambda value: install_identity(value)['development_install_id'])
    args = p.parse_args()
    if args.development_install_id and (args.role != 'windows' or args.windows_builder != 'gnu'):
        p.error('development install identity currently requires windows GNU builder')
    args.deps = args.deps.absolute()
    args.output = args.output.absolute()
    TEMP.mkdir(parents=True, exist_ok=True)
    os.environ['TMPDIR'] = str(TEMP)
    tempfile.tempdir = str(TEMP)
    # flock(2), same lock as the documented shell flock command; held to readback.
    fd = os.open(TEMP / 'orangespace-build.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.output.exists() or args.output.is_symlink() or args.output.with_name(args.output.name + '.receipt.json').exists():
            raise ValueError('fresh archive and receipt target required')
        if ROOT == args.output or ROOT in args.output.parents:
            raise ValueError('output must be outside checkout')
        if run(['git', 'status', '--porcelain', '--untracked-files=all'], ROOT):
            raise ValueError('clean committed checkout required; WIP refused')
        commit = run(['git', 'rev-parse', 'HEAD'], ROOT)
        with tempfile.TemporaryDirectory(prefix='orangespace-source-build-', dir=TEMP) as d:
            work = Path(d)
            archive = subprocess.run(['git', 'archive', '--format=tar', commit], cwd=SOURCE_REPO,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout
            ROOT = work / 'source'
            ROOT.mkdir()
            for name, data in checked_archive(archive, 'tar'):
                target = ROOT / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                if name.endswith('.sh'):
                    target.chmod(0o755)
            build(args, work, commit)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError, zipfile.BadZipFile, tarfile.TarError):
        sys.exit('Build rejected: prerequisites, clean source, pinned dependencies or package policy; no runtime acceptance claimed.')
