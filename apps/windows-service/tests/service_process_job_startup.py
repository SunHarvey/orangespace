"""Startup wiring contract; kernel behavior lives in service_process_job_native.cpp.
Run directly with python3; no CMake modification or external dependency.
"""
from pathlib import Path

root = Path(__file__).resolve().parents[1]
source = (root / "src/service_main.cpp").read_text()
assert '#include "orangespace/service_process_job.hpp"' in source, "SelfJob header absent from service startup"
start = source.index("void run_service()")
identity = source.index('current_peer().sid != "S-1-5-18"', start)
install = source.index("install_service_process_job()", start)
backend = source.index("make_chain_backend()", start)
assert identity < install < backend, "SelfJob must follow SYSTEM check and precede backend"
assert "throw" in source[install:backend], "installation failure must abort before helper/backend"
assert "ERROR_SUCCESS" in source[install:backend], "explicit failure status must gate startup"
assert source.count("install_service_process_job()") == 1
print("PASS service SYSTEM -> fail-closed SelfJob -> backend startup ordering (source contract, not SCM acceptance)")
