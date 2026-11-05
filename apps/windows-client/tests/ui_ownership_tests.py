"""Compile exact UI caller slices with injected return seams; policy, NOT native.

All generated files/artifacts are kept under --output for independent review.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]

def between(text, start, end):
    return text.split(start, 1)[1].split(end, 1)[0]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--sanitize', action='store_true')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    main_path = ROOT / 'apps/windows-client/src/main_win.cpp'
    client_path = ROOT / 'apps/windows-client/include/orangespace/service_client.hpp'
    template_path = Path(__file__).with_suffix('.cpp')
    source = main_path.read_text()
    grant = 'class Grant {' + between(client_path.read_text(), 'class Grant {', '\nGrant authorize(')
    auth = '          if(!box.cancelled)' + between(source, '          if(!box.cancelled)', '          if(box.cancelled)')
    chain_path = ROOT / 'apps/windows-service/include/orangespace/service_chain.hpp'
    chain = chain_path.read_text()
    binding = 'struct Binding {' + between(chain, 'struct Binding {', '\ninline std::string binding_json')
    cursor = 'struct Cursor {' + between(chain, 'struct Cursor {', '\nstruct Persisted')
    tunnel = between(source, 'start([grant,local,op,cursor,old=std::move(old)](Completion& out,Mailbox& box) mutable {', '      });')
    lease = 'struct TunnelLease {' + between(source, 'struct TunnelLease {', '\nstruct Completion')
    generated = (template_path.read_text().replace('/*GRANT_DECLARATION*/', grant)
                 .replace('/*AUTHORIZE_CALLER*/', auth).replace('/*BINDING_DECLARATION*/', binding)
                 .replace('/*CURSOR_DECLARATION*/', cursor).replace('/*TUNNEL_CALLER*/', tunnel)
                 .replace('/*LEASE_DECLARATION*/', lease))
    cpp = args.output / 'ui_ownership_extracted.cpp'
    exe = args.output / 'ui_ownership_tests'
    cpp.write_text(generated)
    depfile = args.output / 'ui_ownership_extracted.d'
    cmd = ['g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-g', '-fno-elide-constructors',
           '-MD', '-MF', str(depfile), '-Wl,-t', '-I' + str(ROOT / 'apps/windows-client/include'), str(cpp), '-o', str(exe)]
    if args.sanitize:
        cmd += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie']
    print('COMPILE', ' '.join(cmd), flush=True)
    build = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (args.output / 'build.log').write_text(' '.join(cmd) + '\n' + build.stdout)
    if build.returncode:
        print(build.stdout)
        raise SystemExit(build.returncode)
    import shlex
    import shutil
    compiler = shutil.which('g++')
    if compiler is None:
        raise SystemExit('g++ missing; no fallback')
    files = [main_path, client_path, chain_path, template_path, Path(__file__).resolve(), cpp, exe, depfile,
             Path(compiler).resolve(), ROOT / 'apps/windows-client/include/orangespace/ui_lifecycle.hpp']
    files += [Path(p) for p in shlex.split(depfile.read_text().replace('\\\n', ' ').split(':', 1)[1])]
    files += [Path(p.strip()).resolve() for p in build.stdout.splitlines() if Path(p.strip()).is_file()]
    manifest = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(set(files))}
    (args.output / 'sha256.json').write_text(json.dumps(manifest, indent=2) + '\n')
    result = subprocess.run([str(exe)], env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=1:halt_on_error=1'}, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(result.stdout, end='', flush=True)
    (args.output / 'result.log').write_text(result.stdout)
    raise SystemExit(result.returncode)

if __name__ == '__main__':
    main()
