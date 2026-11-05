"""Extract the actual Service WFP initialization block; injected policy, not native evidence."""
from pathlib import Path
import subprocess,tempfile
r=Path(__file__).resolve().parents[4]
s=(r/'apps/windows-service/prototype/service_win.cpp').read_text()
a=s.index('stage="offline-WFP-install-readback";')
b=s.index('observation.publish(',a)
block=s[a:b]
code=r'''#include <cassert>
#include <stdexcept>
#include <string>
constexpr unsigned ERROR_INVALID_DATA=13;
const char*stage="entry";std::string label;unsigned reported=0;
void report_fixed(const char*s,unsigned n){label=s;reported=n;}
namespace orangespace::wfp_prototype {struct NetworkPolicy{void installOffline(const std::wstring&){throw std::runtime_error("install-final-path:13");}};}
struct Path{std::wstring wstring(){return L"C:\\Program Files\\Owned\\client.exe";}};
struct Runtime{Path exe;}runtime;
struct O{void publish(){}}observation;
int main(){bool threw=false;try{BLOCK}catch(const std::runtime_error&){threw=true;}assert(threw);assert(label=="install-final-path:13"&&reported==13);}
'''.replace('BLOCK',block)
with tempfile.TemporaryDirectory(prefix='wfp-attribution-',dir='/var/tmp/hermes-runtime/tmp') as t:
 p=Path(t);(p/'test.cpp').write_text(code)
 subprocess.run(['c++','-std=c++20','-Wall','-Wextra','-Werror',str(p/'test.cpp'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True)
print('PASS actual WFP initialization keeps public module error and rethrows unchanged')
