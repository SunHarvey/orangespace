"""Exercise exact client wrappers + exchange ACK tail with injected transport.
No SCM/pipe/HTTPS claims. The fake ACK completes the actual Engine Response,
then enables persistent allocation failure before returning to client code.
"""
from pathlib import Path
import subprocess
import sys
import os
import shlex
repo, output = map(Path, sys.argv[1:])
output.mkdir(parents=True, exist_ok=True)
source = (repo / 'apps/windows-client/src/service_client_win.cpp').read_text()
start = source.find('template<class Prepare>')
if start < 0:
    start = source.index('json::Value exchange(')
signature = source[start:source.index('    struct WipedFrame', start)]
tail_start = source.index('        // Strict schema, identity')
tail_end = source.index('\nstd::string auth_payload', tail_start)
tail = source[tail_start:tail_end]
wrappers = source[source.index('std::string auth_payload'):source.index('\nStatusResult query_foundation_status')]
# wrappers close the anonymous namespace opened around the exchange function.
(output / 'postack_under_test.hpp').write_text('namespace {\n' + signature + '\n(void)payload;\nconst auto& response=transport_bytes;\nconst unsigned response_size=static_cast<unsigned>(response.size());\nunsigned count{};\nMockHandle pipe,process;\n' + tail + '\n' + wrappers)
cmd = ['g++', '-std=c++20', '-O0', '-g', '-fno-elide-constructors', '-pthread',
       '-I' + str(repo / 'apps/windows-service/include'), '-I' + str(repo / 'apps/windows-client/include'), '-I' + str(output),
       str(repo / 'apps/windows-service/tests/service_postack_tests.cpp'), '-o', str(output / 'postack-test')]
cmd[1:1] = shlex.split(os.environ.get("SERVICE_TEST_CXXFLAGS", ""))
subprocess.run(cmd, check=True)
results = [subprocess.run([str(output / 'postack-test'), mode]).returncode for mode in ['authorize', 'start', 'stop']]
if any(results):
    raise SystemExit(1)
