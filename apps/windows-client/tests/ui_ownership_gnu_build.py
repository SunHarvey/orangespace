"""Fresh GNU Windows compile/link, NOT native execution or archive provenance.

Read existing production archives only; never run CMake or rebuild backend.
Record transitive compiler headers, traced linker inputs, source snapshots and
artifacts. Archive hashes identify inputs, not proof they match current source.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[3]

def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--archive-root', required=True, type=Path)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    cc = shutil.which('x86_64-w64-mingw32-g++')
    rc = shutil.which('x86_64-w64-mingw32-windres')
    if not cc or not rc:
        raise SystemExit('GNU Windows toolchain missing; no fallback')
    archives = [args.archive_root.resolve() / 'apps/windows-service/liborangespace_node_session.a',
                args.archive_root.resolve() / 'apps/windows-client/liborangespace_service_client.a']
    before = {str(p): digest(p) for p in archives}
    files = {Path(__file__).resolve(), Path(cc).resolve(), Path(rc).resolve(), *archives}
    commands = []
    logs = []

    def run(cmd):
        commands.append(cmd)
        result = subprocess.run(cmd, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        logs.append('$ ' + shlex.join(map(str, cmd)) + '\n' + result.stdout)
        (out / 'build.log').write_text('\n'.join(logs))
        if result.returncode:
            print(result.stdout)
            raise SystemExit(result.returncode)
        return result.stdout

    defines = ['-DNOMINMAX', '-DUNICODE', '-D_UNICODE', '-DWIN32_LEAN_AND_MEAN', '-D_WIN32_WINNT=0x0A00']
    includes = ['-I' + str(ROOT / p) for p in ['apps/windows-client/src', 'apps/windows-client/include', 'apps/windows-service/include']]
    objects = []
    for name in ['main_win.cpp', 'broker_win.cpp']:
        src = ROOT / 'apps/windows-client/src' / name
        obj = out / (name + '.o')
        dep = out / (name + '.d')
        run([cc, '-std=c++20', '-O2', '-fno-elide-constructors', *defines, *includes,
             '-MD', '-MF', str(dep), '-c', str(src), '-o', str(obj)])
        objects.append(obj)
        files.update([src, obj, dep])
        files.update(Path(p) for p in shlex.split(dep.read_text().replace('\\\n', ' ').split(':', 1)[1]))
    resource = out / 'app.rc.res'
    run([rc, '-O', 'coff', *defines, *includes, str(ROOT / 'apps/windows-client/src/app.rc'), str(resource)])
    files.add(resource)
    exe = out / 'OrangeSpace.exe'
    libs = ['comctl32', 'shell32', 'user32', 'gdi32', 'winhttp', 'crypt32', 'ole32', 'bcrypt', 'advapi32', 'uuid']
    trace = run([cc, '-static', '-static-libgcc', '-static-libstdc++', '-mwindows', '-municode',
                 '-Wl,--subsystem,windows', '-Wl,-t', *map(str, objects), str(resource),
                 str(archives[0]), str(archives[1]), str(archives[0]),
                 *['-l' + lib for lib in libs], '-o', str(exe)])
    for line in trace.splitlines():
        p = Path(line.strip())
        if p.is_file():
            files.add(p.resolve())
    files.add(exe)
    # Include all local source dependencies even for pre-existing archives.
    # Their present hashes are snapshots, not asserted build provenance.
    for folder in ['apps/windows-client/include', 'apps/windows-service/include']:
        files.update(p for p in (ROOT / folder).rglob('*') if p.is_file())
    for name in ['service_client_win.cpp', 'node_session_win.cpp', 'credential_store_win.cpp', 'app.rc', 'app.manifest']:
        files.add(ROOT / 'apps/windows-client/src' / name)
    assert before == {str(p): digest(p) for p in archives}, 'archive changed during build'
    manifest = {str(p): digest(p) for p in sorted(files)}
    (out / 'sha256.json').write_text(json.dumps(manifest, indent=2) + '\n')
    (out / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
    print(run(['file', str(exe)]), end='')
    print('GNU Windows compile/link PASS; NOT native; existing archive provenance NOT re-attested')
    print('EXE SHA256', digest(exe))
    for path, sha in before.items():
        print('READONLY ARCHIVE SHA256', sha, path)
    print('FULL DEPENDENCY MANIFEST', out / 'sha256.json', digest(out / 'sha256.json'))

if __name__ == '__main__':
    main()
