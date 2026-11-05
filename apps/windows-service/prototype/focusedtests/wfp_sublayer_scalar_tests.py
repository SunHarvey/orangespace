"""Actual WFP sublayer predicate/error extraction; injected scalar policy, not native."""
from pathlib import Path
import tempfile,subprocess
r=Path(__file__).resolve().parents[4]
s=(r/'drivers/wfp-prototype/network_policy_win.cpp').read_text()
body=s.split('  void metadata() {',1)[1].split('  std::vector<VerifiedFilter> inventory(',1)[0]
code=r'''#include <string>
#include <stdexcept>
#include <cassert>
using GUID=unsigned;using DWORD=unsigned;constexpr unsigned FWPM_PROVIDER_FLAG_PERSISTENT=1,FWPM_SUBLAYER_FLAG_PERSISTENT=1,ERROR_INVALID_DATA=13;
bool eq(unsigned a,unsigned b){return a==b;}
[[noreturn]] void fail(const char* op,DWORD code){throw std::runtime_error(std::string(op)+":"+std::to_string(code));}
void require(bool b,const char* op){if(!b)fail(op,13);}void check(const char* op,unsigned e){if(e)fail(op,e);}
struct Blob{unsigned size=0;};struct FWPM_PROVIDER0{GUID providerKey=11;unsigned flags=1;Blob providerData;void*serviceName=nullptr;};
struct FWPM_SUBLAYER0{GUID subLayerKey=22;unsigned flags=1;GUID*providerKey=nullptr;unsigned weight=65535;Blob providerData;}actual;
FWPM_PROVIDER0 prov;template<class T>struct Memory{T*p=nullptr;};
unsigned FwpmProviderGetByKey0(unsigned,const GUID*,FWPM_PROVIDER0**p){*p=&prov;return 0;}
unsigned FwpmSubLayerGetByKey0(unsigned,const GUID*,FWPM_SUBLAYER0**p){*p=&actual;return 0;}
struct Policy{bool package=false;unsigned engine=1;GUID provider=11,sublayer=22;void metadata(){BODY};};
int main(){Policy p;p.metadata();actual.flags=0;bool caught=false;try{p.metadata();}catch(const std::runtime_error&e){caught=true;assert(std::string(e.what())=="sublayer-scalars(k=1,f=0,p=0,peq=0,w=65535,d=0):13");}assert(caught);}
'''.replace('BODY',body.rsplit('}',1)[0])
with tempfile.TemporaryDirectory(prefix='sublayer-scalars-',dir='/var/tmp/hermes-runtime/tmp') as t:
 p=Path(t);(p/'test.cpp').write_text(code);subprocess.run(['c++','-std=c++20','-Wall','-Wextra','-Werror',str(p/'test.cpp'),'-o',str(p/'test')],check=True);subprocess.run([str(p/'test')],check=True)
print('PASS actual metadata preserves strict predicate and identifies rejecting public scalar')
