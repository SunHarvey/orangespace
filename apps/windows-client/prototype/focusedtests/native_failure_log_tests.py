"""Execute the registered production exception logger with portable Win32 seams.
Not native exception-handler acceptance.
"""
import argparse
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[4]


def run(source, output):
    text = source.read_text()
    begin = text.index('LONG CALLBACK OfflineNativeFailure(')
    helper = text[begin:text.index('\nBootstrapVersion Snapshot(', begin)]
    assert 'AddVectoredExceptionHandler(1,OfflineNativeFailure)' in text
    assert '~FailureLog(){if(handle)RemoveVectoredExceptionHandler(handle);}' in text
    cpp = r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <string>
using DWORD=std::uint32_t;
using LONG=long;
#define CALLBACK
constexpr DWORD EXCEPTION_BREAKPOINT=0x80000003;
constexpr LONG EXCEPTION_CONTINUE_SEARCH=0;
struct Record {DWORD ExceptionCode;};
struct Context {std::uint64_t Rip=0x123456789abcdef0ULL,Rax=0xfedcba9876543210ULL;};
struct EXCEPTION_POINTERS {Record* ExceptionRecord;Context* ContextRecord;};
static std::string logged;
static DWORD error;
DWORD GetLastError(){return error;}
void OfflineEarlyLog(const char* text){logged+=text;}
/*HELPER*/
int main(){
 Record record{EXCEPTION_BREAKPOINT};Context context;
 EXCEPTION_POINTERS exception{&record,&context};
 for(DWORD code:{DWORD(0),DWORD(5),DWORD(0xffffffff)}){
  error=code;logged.clear();assert(OfflineNativeFailure(&exception)==EXCEPTION_CONTINUE_SEARCH);
  const auto expected=std::string("native-breakpoint win32=")+std::to_string(code)+"\n";
  if(logged!=expected){std::fputs("FAIL: exception log exceeds fixed-label DWORD contract\n",stderr);return 1;}
 }
 for(EXCEPTION_POINTERS* event:{static_cast<EXCEPTION_POINTERS*>(nullptr),&exception}){
  logged.clear();record.ExceptionCode=1;
  assert(OfflineNativeFailure(event)==EXCEPTION_CONTINUE_SEARCH);assert(logged.empty());
 }
 record.ExceptionCode=EXCEPTION_BREAKPOINT;
 exception.ContextRecord=nullptr;logged.clear();
 assert(OfflineNativeFailure(&exception)==EXCEPTION_CONTINUE_SEARCH);assert(logged.empty());
 exception.ContextRecord=&context;exception.ExceptionRecord=nullptr;
 assert(OfflineNativeFailure(&exception)==EXCEPTION_CONTINUE_SEARCH);assert(logged.empty());
 std::puts("PASS actual registered logger: fixed label + DWORD only; predicate/search preserved");
}
'''.replace('/*HELPER*/', helper)
    output.mkdir(parents=True, exist_ok=True)
    src = output / 'native_failure_log.cpp'
    src.write_text(cpp)
    exe = output / 'native_failure_log'
    cmd = ['g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', str(src), '-o', str(exe)]
    build = subprocess.run(cmd, text=True, capture_output=True)
    (output / 'build.log').write_text(repr(cmd) + '\n' + build.stdout + build.stderr)
    if build.returncode:
        print(build.stdout + build.stderr, end='')
        return build.returncode
    result = subprocess.run([str(exe)], text=True, capture_output=True)
    (output / 'run.log').write_text(result.stdout + result.stderr)
    print(result.stdout + result.stderr, end='')
    return result.returncode


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / 'apps/windows-client/prototype/bootstrap_prototype_win.cc')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(run(args.source, args.output))
