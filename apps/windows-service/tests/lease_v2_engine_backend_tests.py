"""Exact Engine + backend close/reserve with real Rust no-helper handles.
Injected start proof/OS seams: NOT helper, Windows, HTTPS or forwarding evidence.
"""
from pathlib import Path
import importlib.util
import subprocess
import sys
import os
import shlex
repo, out, library = map(Path, sys.argv[1:])
out.mkdir(parents=True, exist_ok=True)
spec = importlib.util.spec_from_file_location('extract', repo/'apps/windows-service/tests/extract_lease_v2_backend.py')
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
source = (repo/'apps/windows-service/src/chain_windows.cpp').read_text()
parts = [module.block(source, 'struct Realm {')+';', next(x.strip() for x in source.splitlines() if ' realms_;' in x), module.block(source, 'struct OrdinaryInvalid {')+';']
for signature in ['void fail_closed() noexcept override', 'void release(std::string_view realm) noexcept override', 'void reserve(std::string_view realm,', 'bool confirm_absent(void* runtime,', 'void close(std::string_view realm,', 'std::string call(void* runtime_,']:
    method = module.block(source, signature)
    left = method.index('{')
    parts.append(method[:left].replace(' override', '')+method[left:])
(out/'engine_backend_under_test.hpp').write_text('struct ExactBackend { std::mutex mutex_; bool poisoned_{};\n'+'\n'.join(parts)+'\n};\n')
command = shlex.split(os.environ.get('CXX', 'g++')) + shlex.split(os.environ.get('CXXFLAGS', '')) + ['-std=c++20','-Wall','-Wextra','-Werror','-fno-elide-constructors','-pthread','-I'+str(repo/'apps/windows-service/include'),'-I'+str(repo/'apps/windows-client/include'),'-I'+str(repo/'crates/orangespace-runtime/include'),'-I'+str(out),str(repo/'apps/windows-service/tests/lease_v2_engine_backend_tests.cpp'),str(library),'-ldl','-lm','-o',str(out/'engine-backend')]
subprocess.run(command, check=True)
subprocess.run([str(out/'engine-backend')], check=True)
