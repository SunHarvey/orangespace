"""Configure-only regression: preserve raw runtime-library path validation.

The placeholder is deliberately NOT a Rust archive: no build, link, helper or
ABI execution occurs. Empty configuration must expose an honest CTest skip.
"""
from pathlib import Path
import subprocess
import sys

repo, output = (Path(arg).resolve() for arg in sys.argv[1:])
output.mkdir(parents=True, exist_ok=True)
placeholder = output / "configure-only-placeholder.a"
placeholder.write_bytes(b"configure-only; never linked or executed\n")


def configure(name, value, accepted, typed=False):
    key = "ORANGESPACE_RUNTIME_TEST_LIBRARY" + (":FILEPATH" if typed else "")
    result = subprocess.run(
        ["cmake", "-S", str(repo), "-B", str(output / name),
         "-DBUILD_TESTING=ON", "-D" + key + "=" + value],
        cwd=output, capture_output=True, text=True, timeout=45,
    )
    if (result.returncode == 0) != accepted:
        raise AssertionError("runtime library configuration policy: " + name)


configure("relative-fresh", placeholder.name, False)
configure("legacy-cache", str(placeholder), True, typed=True)
configure("legacy-cache", placeholder.name, False)
configure("typed-relative", placeholder.name, False, typed=True)
configure("absolute-valid", str(placeholder), True)
configure("absolute-missing", str(output / "missing.a"), False)
configure("empty", "", True)
result = subprocess.run(
    ["ctest", "--test-dir", str(output / "empty"), "-R",
     "^service-lease-v2-engine-real-abi-policy$", "--output-on-failure"],
    capture_output=True, text=True, timeout=20,
)
if result.returncode != 0 or "Skipped" not in result.stdout:
    raise AssertionError("missing runtime library must skip, not pass ABI execution")
print("PASS configure-only raw paths, reused cache, valid/missing absolute paths and honest ABI skip")
