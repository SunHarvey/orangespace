"""Extract actual io into the existing injected OS seam; not native evidence."""
from pathlib import Path
import ast
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
source = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE.parent / 'service_win.cpp'
baseline = Path(sys.argv[2]) if len(sys.argv) > 2 else None
BASELINE_IO = '''bool io(HANDLE pipe,void* data,DWORD size,bool write){Handle event(CreateEventW(nullptr,TRUE,FALSE,nullptr));if(!event)return false;OVERLAPPED ov{};ov.hEvent=event.get();DWORD n=0;BOOL ok=write?WriteFile(pipe,data,size,&n,&ov):ReadFile(pipe,data,size,&n,&ov);if(!ok&&GetLastError()==ERROR_IO_PENDING){HANDLE waits[]{stop_event,event.get()};if(WaitForMultipleObjects(2,waits,FALSE,1500)!=WAIT_OBJECT_0+1){CancelIoEx(pipe,&ov);GetOverlappedResult(pipe,&ov,&n,TRUE);return false;}ok=GetOverlappedResult(pipe,&ov,&n,FALSE);}return ok&&n==size;}'''
def extract(path):
    text = path.read_text()
    return text[text.index('bool io('):text.index('\nHandle pipe_for(', text.index('bool io('))]
# Each adjacent fallible private-offer boundary gets attribution, not a repair.
text = source.read_text()
private = text[text.index('stage="committed-write"'):text.index('stage="private-offer-write"')]
for stage, boundary in [
    ('private-live-verify', 'control.verify_live(*channel)'),
    ('private-offer-build', 'p::PrivateOwner private_owner'),
    ('private-offer-validate', 'need(p::ValidPrivateOffer('),
    ('private-offer-hash', 'BCRYPT_ALG_HANDLE alg{}'),
]:
    assert 'stage="' + stage + '";' in private, 'missing bounded stage: ' + stage
    assert private.index('stage="' + stage + '";') < private.index(boundary)
# Reuse the Handle/DWORD/BOOL definitions from the existing portable seam.
tree = ast.parse((HERE / 'v24_online_service_tests.py').read_text())
harness = next(ast.literal_eval(n.value) for n in ast.walk(tree) if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'harness' for t in n.targets))
shim = harness[:harness.index('struct Peer')]
shim += r'''
#include <string>
#include <vector>
#include <utility>
#include <cstdio>
#include <algorithm>
using ULONGLONG=unsigned long long;
constexpr BOOL FALSE=0,TRUE=1;
constexpr DWORD ERROR_IO_PENDING=997,WAIT_FAILED=0xffffffffu,MAXDWORD=0xffffffffu;
struct OVERLAPPED{HANDLE hEvent{};};
HANDLE stop_event=11;
int scenario; DWORD last_error; std::vector<int> calls;
std::vector<std::pair<std::string,DWORD>> logs;
DWORD GetLastError(){return last_error;}
void SetLastError(DWORD e){last_error=e;}
ULONGLONG GetTickCount64(){last_error=9999;return logs.empty()?10:10;}
// Separate tick counter tests both normal elapsed and DWORD saturation.
ULONGLONG ticks=0,elapsed=37;
ULONGLONG tick(){last_error=9999;return ticks++?10+elapsed:10;}
void report_fixed(const char*l,DWORD v){logs.emplace_back(l,v);last_error=8888;}
HANDLE CreateEventW(void*,BOOL a,BOOL b,void*){assert(a==TRUE&&b==FALSE);calls.push_back(1);if(scenario==0){last_error=8;return 0;}last_error=77;return 22;}
BOOL transfer(bool write,HANDLE p,void*,DWORD size,DWORD*n,OVERLAPPED*ov){assert(p==33&&size==64&&ov->hEvent==22);calls.push_back(write?3:2);*n=scenario==2?63:64;if(scenario==3){last_error=5;return FALSE;}if(scenario>=4){*n=0;last_error=ERROR_IO_PENDING;return FALSE;}last_error=91;return TRUE;}
BOOL ReadFile(HANDLE p,void*d,DWORD s,DWORD*n,OVERLAPPED*o){return transfer(false,p,d,s,n,o);}
BOOL WriteFile(HANDLE p,void*d,DWORD s,DWORD*n,OVERLAPPED*o){return transfer(true,p,d,s,n,o);}
DWORD WaitForMultipleObjects(DWORD count,HANDLE*h,BOOL all,DWORD ms){assert(count==2&&h[0]==11&&h[1]==22&&!all&&ms==1500);calls.push_back(4);last_error=scenario==7?6:123;return scenario==5?WAIT_OBJECT_0:scenario==6?WAIT_TIMEOUT:scenario==7?WAIT_FAILED:WAIT_OBJECT_0+1;}
BOOL CancelIoEx(HANDLE p,OVERLAPPED*o){assert(p==33&&o->hEvent==22);calls.push_back(5);last_error=44;return TRUE;}
BOOL GetOverlappedResult(HANDLE p,OVERLAPPED*o,DWORD*n,BOOL wait){assert(p==33&&o->hEvent==22);calls.push_back(wait?6:7);*n=scenario==9?63:64;last_error=wait?995:scenario==8?109:456;return scenario==8||wait?FALSE:TRUE;}
'''
# Inject time only at the API seam, leaving both production function bodies intact.
shim += '#define GetTickCount64 tick\n'
main = r'''
DWORD value(const char*l){for(auto&v:logs)if(v.first==l)return v.second;assert(false&&"missing fixed io DWORD diagnostic");return 0;}
int main(){for(int direction=0;direction<2;direction++)for(scenario=0;scenario<10;scenario++)for(int huge=0;huge<2;huge++){
 elapsed=huge?0x100000004ULL:37; ticks=0;calls.clear();logs.clear();last_error=42;
 bool old=baseline_io(33,nullptr,64,direction);DWORD old_error=last_error;auto old_calls=calls;
 ticks=0;calls.clear();logs.clear();last_error=42;
 bool got=io(33,nullptr,64,direction);DWORD got_error=last_error;
 assert(got==old&&got_error==old_error&&calls==old_calls);
 if(got){assert(logs.empty());continue;}
 assert(logs.size()==10);
 assert(logs[0].first==(scenario==0?"admission-io-event":scenario>=5&&scenario<=7?"admission-io-wait":"admission-io-transfer"));
 assert(value("admission-io-write")==DWORD(direction));
 assert(value("admission-io-sync-ok")==DWORD(scenario==2));
 assert(value("admission-io-requested")==64);
 assert(value("admission-io-done")==DWORD(scenario==0||scenario==3? (scenario==0?0:64):scenario==2||scenario==9?63:64));
 assert(value("admission-io-elapsed-ms")==DWORD(huge?0xffffffffu:37));
 assert(value("admission-io-initial-error")==DWORD(scenario==3?5:scenario>=4?997:0));
 assert(value("admission-io-native-error")==DWORD(scenario==0?8:scenario==3?5:scenario>=5&&scenario<=7?995:scenario==8?109:0));
 assert(value("admission-io-wait-error")==DWORD(scenario==7?6:0));
 assert(value("admission-io-wait-result")==DWORD(scenario<4?WAIT_FAILED:scenario==5?0:scenario==6?258:scenario==7?WAIT_FAILED:1));
 }puts("40 extracted io differential cases: return/LastError/ordered OS calls identical; fixed DWORD diagnostics, failure-only and elapsed clamp passed; native not run");}
'''
with tempfile.TemporaryDirectory(prefix='admission-io-', dir='/root/.hermes/cache/scratch') as directory:
    root = Path(directory)
    (root / 'test.cpp').write_text(shim + (extract(baseline) if baseline else BASELINE_IO).replace('bool io(', 'bool baseline_io(', 1) + '\n' + extract(source) + main)
    subprocess.run(['g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', str(root / 'test.cpp'), '-o', str(root / 'test')], check=True)
    subprocess.run([str(root / 'test')], check=True)
