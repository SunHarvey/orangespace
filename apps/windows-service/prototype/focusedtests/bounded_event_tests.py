"""Actual fixed event logger extraction; long public errors must retain a bounded prefix."""
from pathlib import Path
import subprocess,tempfile
r=Path(__file__).resolve().parents[4];s=(r/'apps/windows-service/prototype/service_win.cpp').read_text()
body='void report_fixed('+s.split('void report_fixed(',1)[1].split('\nstruct Failure',1)[0]
code=r'''#include <algorithm>
#include <cstring>
#include <string>
#include <cassert>
using HANDLE=int;using DWORD=unsigned;using LPCWSTR=const wchar_t*;
constexpr unsigned CP_UTF8=65001,EVENTLOG_ERROR_TYPE=1;namespace p{constexpr wchar_t kService[]=L"service";}
std::wstring captured;
int RegisterEventSourceW(void*,const wchar_t*){return 1;}void DeregisterEventSource(int){}
int MultiByteToWideChar(unsigned,unsigned,const char*s,int count,wchar_t*out,int capacity){int n=count<0?int(std::strlen(s))+1:count;if(n>capacity)return 0;for(int i=0;i<n;++i)out[i]=s[i];return n;}
bool ReportEventW(int,unsigned,unsigned,unsigned,void*,unsigned,unsigned,LPCWSTR*strings,void*){captured=strings[0];return true;}
FUNCTION
int main(){std::string label="exact-filter-metadata(flags=65,wanted-flags=65,weight-type=4,weight="+std::string(180,'7');report_fixed(label.c_str(),13);assert(captured.rfind(L"exact-filter-metadata(flags=",0)==0);assert(captured.size()==127);report_fixed("short-label",13);assert(captured==L"short-label");}
'''.replace('FUNCTION',body)
with tempfile.TemporaryDirectory(prefix='bounded-event-',dir='/var/tmp/hermes-runtime/tmp') as t:
 p=Path(t);(p/'t.cpp').write_text(code);subprocess.run(['c++','-std=c++20','-Wall','-Wextra','-Werror',str(p/'t.cpp'),'-o',str(p/'t')],check=True);subprocess.run([str(p/'t')],check=True)
print('PASS actual logger retains bounded long public prefix and original short label')
for label,call in [('service-observation-publish','observation.publish('),('service-control-construct','orangespace::service::win::PrototypeControl control('),('service-control-start','control.start();'),('service-running-status','status(SERVICE_RUNNING);')]:
 pos=s.index(call,s.index('stage="offline-WFP-install-readback";'))
 assert s[:pos].rstrip().endswith('stage="'+label+'";'), 'stale stage before '+call
print('PASS each post-WFP startup operation has its own preceding fixed stage')

assert 'const char* fixed_startup_error(' in s, "missing fixed-only startup error classification"
classifier=s.split('const char* fixed_startup_error(',1)[1].split('\nstruct Failure',1)[0]
classifier='const char* fixed_startup_error('+classifier
fixture='#include <cstring>\n#include <cassert>\n#include <string>\n'+classifier+'\nint main(){std::string v="trust path is not administrator protected";const char*p=fixed_startup_error(v.c_str());assert(p && p!=v.c_str() && std::strcmp(p,v.c_str())==0);assert(fixed_startup_error("secret-token-or-path:untrusted")==nullptr);assert(fixed_startup_error(nullptr)==nullptr);assert(fixed_startup_error("invalid platform session data"));}\n'
with tempfile.TemporaryDirectory(prefix="fixed-error-",dir="/var/tmp/hermes-runtime/tmp") as t:
 p=Path(t);(p/"t.cpp").write_text(fixture);subprocess.run(["c++","-std=c++20","-Wall","-Wextra","-Werror",str(p/"t.cpp"),"-o",str(p/"t")],check=True);subprocess.run([str(p/"t")],check=True)
print("PASS fixed-only error classification never echoes arbitrary text")
