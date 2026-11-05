#!/usr/bin/env python3
"""Offline build/portable tests ONLY; never executes PE or touches Windows SCM."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess

HERE = Path(__file__).resolve().parent
SCRATCH = Path('/root/.hermes/cache/scratch').resolve()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', default=str(SCRATCH / 'phase1_guardian_artifacts'))
    args = parser.parse_args()
    out = Path(args.out).resolve()
    if not out.is_relative_to(SCRATCH):
        parser.error('output must stay below the authorized scratch directory')
    out.mkdir(parents=True, exist_ok=True)
    evidence = {'commands': [], 'sources': {}, 'artifacts': {}, 'native_executed': False,
                'scm_executed': False, 'full_acceptance': False}

    def run(command):
        result = subprocess.run(command, cwd=HERE, text=True, capture_output=True, check=False)
        evidence['commands'].append({'argv': command, 'cwd': str(HERE), 'exit_code': result.returncode,
                                     'stdout': result.stdout, 'stderr': result.stderr})
        (out / 'build.json').write_text(json.dumps(evidence, indent=2))
        if result.returncode:
            raise RuntimeError(f'build/test command failed: {command[0]}: {result.stderr}')
        return result.stdout

    run(['g++', '--version'])
    run(['x86_64-w64-mingw32-g++', '--version'])
    for name in ['policy_tests', 'intent_tests']:
        dest = out / ('phase1_guardian_' + name)
        run(['g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-fno-elide-constructors',
             str(HERE / ('phase1_guardian_' + name + '.cpp')), '-o', str(dest)])
        print(run([str(dest)]).strip())
    for name in ['driver', 'fixture_service', 'native_tests']:
        dest = out / ('phase1_guardian_' + name + '.exe')
        run(['x86_64-w64-mingw32-g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
             '-fno-elide-constructors', '-D_WIN32_WINNT=0x0A00', '-static', '-municode',
             str(HERE / ('phase1_guardian_' + name + '.cpp')), '-o', str(dest),
             '-ladvapi32', '-lbcrypt', '-lshell32', '-lole32', '-luuid'])
        imports = run(['x86_64-w64-mingw32-objdump', '-p', str(dest)])
        dlls = [line.split('DLL Name:', 1)[1].strip() for line in imports.splitlines() if 'DLL Name:' in line]
        if any(any(part in dll.lower() for part in ['libstdc++', 'libgcc', 'libwinpthread', 'vcruntime', 'msvcp']) for dll in dlls):
            raise RuntimeError('unexpected dynamic compiler runtime import')
        evidence['artifacts'][dest.name] = {'sha256': hashlib.sha256(dest.read_bytes()).hexdigest(),
                                            'bytes': dest.stat().st_size, 'imports': dlls}
    evidence['sources'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in sorted(HERE.glob('phase1_guardian_*')) if p.is_file()}
    (out / 'build.json').write_text(json.dumps(evidence, indent=2))
    print(json.dumps({'build_manifest': str(out / 'build.json'), 'portable_suites_passed': 2,
                      'pe_artifacts_built': len(evidence['artifacts']), 'native_executed': False,
                      'full_acceptance': False}))

if __name__ == '__main__':
    main()
