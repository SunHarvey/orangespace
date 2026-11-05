#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export TMPDIR=/var/tmp/hermes-runtime/tmp
export CARGO_TARGET_DIR="$PWD/target"
mkdir -p "$TMPDIR"
lock="$TMPDIR/orangespace-build.lock"
export HTTPS_PROXY=http://127.0.0.1:1 HTTP_PROXY=http://127.0.0.1:1 ALL_PROXY=http://127.0.0.1:1 NO_PROXY=''
flock "$lock" cargo +1.85.0 test --locked -p orangespace-https -j1 -- --test-threads=1 2>&1 | tee msrv-1.85.log
unset HTTPS_PROXY HTTP_PROXY ALL_PROXY NO_PROXY
flock "$lock" cargo build --release --locked -p orangespace-https -j1 2>&1 | tee build-linux.log
flock "$lock" cargo build --release --locked -p orangespace-https --target x86_64-pc-windows-gnu -j1 2>&1 | tee build-windows-gnu.log
flock "$lock" gcc -std=c11 -Wall -Wextra -Werror -Iinclude tests/ffi_smoke.c target/release/liborangespace_https.a -ldl -lpthread -lm -o target/ffi-smoke
python3 tests/run_c_ffi.py 2>&1 | tee ffi-linux.log
flock "$lock" x86_64-w64-mingw32-gcc -std=c11 -Wall -Wextra -Werror -static -Iinclude tests/ffi_smoke.c target/x86_64-pc-windows-gnu/release/liborangespace_https.a -lbcrypt -ladvapi32 -lkernel32 -lntdll -luserenv -lws2_32 -ldbghelp -o target/ffi-smoke.exe 2>&1 | tee ffi-windows-link.log
sha256sum target/release/liborangespace_https.{a,rlib} target/x86_64-pc-windows-gnu/release/liborangespace_https.{a,rlib} target/ffi-smoke target/ffi-smoke.exe > SHA256SUMS
sha256sum -c SHA256SUMS
