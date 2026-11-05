"""Extract exact production Realm/reserve/fail_closed; real host Rust link.
Injected liveness has no native process. Not Windows/helper/WFP acceptance.
"""
from pathlib import Path
import os
import shlex
import subprocess
import sys
repo, output, library = map(Path, sys.argv[1:])
output.mkdir(parents=True, exist_ok=True)
source = (repo / 'apps/windows-service/src/chain_windows.cpp').read_text()
def block(start):
    begin = source.index(start)
    left = source.index('{', begin)
    depth, end = 1, left + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[begin:end]
parts = [block('struct Realm {') + ';',
         next(line.strip() for line in source.splitlines() if ' realms_;' in line),
         block('void fail_closed() noexcept override').replace(' override', ''),
         block('void reserve(std::string_view realm,const Binding& b) override').replace(' override', '')]
(output / 'stop_poison_under_test.hpp').write_text(
    'struct ExtractedPoison {\nstd::mutex mutex_;\nbool poisoned_{};\n' + '\n'.join(parts) + '\n};\n')
cmd = ['g++', '-std=c++20', '-O0', '-g', '-Wall', '-Wextra', '-Werror',
       '-fno-elide-constructors', '-pthread',
       '-I' + str(repo / 'apps/windows-service/include'),
       '-I' + str(repo / 'apps/windows-client/include'),
       '-I' + str(repo / 'crates/orangespace-runtime/include'), '-I' + str(output),
       '-MD', '-MF', str(output / 'stop-poison.d'),
       str(repo / 'apps/windows-service/tests/service_stop_poison_tests.cpp'), str(library),
       '-ldl', '-lm', '-Wl,-t', '-o', str(output / 'stop-poison')]
cmd[1:1] = shlex.split(os.environ.get('SERVICE_TEST_CXXFLAGS', ''))
subprocess.run(cmd, check=True)
subprocess.run([str(output / 'stop-poison')], check=True)
