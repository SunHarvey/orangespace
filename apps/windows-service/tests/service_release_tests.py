"""Portable test of the EXACT production release body and Realm/map declarations.
Not a Windows backend/ACL test. Uses a real host Rust runtime, no child launch.
Pass repo root, output directory and Linux liborangespace_runtime.a explicitly.
"""
from pathlib import Path
import subprocess
import sys
import os
import shlex
repo, output, library = map(Path, sys.argv[1:])
output.mkdir(parents=True, exist_ok=True)
source = (repo / 'apps/windows-service/src/chain_windows.cpp').read_text()
def block(start):
    begin = source.index(start)
    left = source.index('{', begin)
    depth = 1
    end = left + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[begin:end]
realm = block('struct Realm {') + ';'
map_line = next(line.strip() for line in source.splitlines() if ' realms_;' in line)
release = block('void release(std::string_view realm) noexcept override').replace(' override', '')
(output / 'release_under_test.hpp').write_text('struct ReleaseUnderTest {\nstd::mutex mutex_;\n' + realm + '\n' + map_line + '\n' + release + '\n};\n')
cmd = ['g++', '-std=c++20', '-O0', '-g', '-fno-elide-constructors', '-pthread',
       '-I' + str(repo / 'apps/windows-service/include'), '-I' + str(repo / 'apps/windows-client/include'),
       '-I' + str(repo / 'crates/orangespace-runtime/include'), '-I' + str(output),
       str(repo / 'apps/windows-service/tests/service_release_tests.cpp'), str(library), '-ldl', '-lm', '-o', str(output / 'release-test')]
cmd[1:1] = shlex.split(os.environ.get("SERVICE_TEST_CXXFLAGS", ""))
subprocess.run(cmd, check=True)
subprocess.run([str(output / 'release-test')], check=True)
