from pathlib import Path
import subprocess,tempfile,sys
root=Path(__file__).resolve().parents[4]
src=Path(sys.argv[1]) if len(sys.argv)>1 else root/'apps/windows-service/prototype/service_win.cpp'
s=src.read_text();assert 'void diagnose_private_offer(' in s,'missing private offer failure scalars'
a=s.index('void diagnose_private_offer(');b=s.index('\nHandle pipe_for',a);fn=s[a:b]
assert 'if(!valid_private_offer)diagnose_private_offer(o,private_now);need(valid_private_offer);' in s
code=r"""
#include "private_channel.hpp"
#include <cassert>
#include <map>
#include <algorithm>
using DWORD=unsigned;constexpr DWORD MAXDWORD=0xffffffffu;
namespace p=orangespace::prototype;
static DWORD err=17;DWORD GetLastError(){return err;}void SetLastError(DWORD e){err=e;}
std::map<std::string,DWORD> rows;
void report_fixed(const char* label,DWORD v){rows[label]=v;err=999;}
"""+fn+r"""
int main(){p::PrivateOffer o{};o.started=100;o.ttl=30000;o.deadline=o.binding_deadline=30100;o.proof=101;o.port=1;o.generation=1;o.expiry=1;
for(auto* s:{&o.user,&o.sandbox,&o.node,&o.tunnel})std::memcpy(s->data(),"33333333-3333-4333-8333-333333333333",36);
o.username_size=o.password_size=16;std::memset(o.username.data(),'a',16);std::memset(o.password.data(),'b',16);
for(auto now:{102LL,3100LL,3101LL,30100LL}){rows.clear();err=17;diagnose_private_offer(o,now);assert(err==17);assert(rows.size()==6);assert(rows["private-offer-proof-valid"]==(now-101<3000));assert(rows["private-offer-proof-age-ms"]==now-101);assert(rows["private-offer-budget-valid"]==(now<30100));assert(rows["private-offer-binding-valid"]);assert(rows["private-offer-secrets-valid"]);}
o.proof=500;rows.clear();diagnose_private_offer(o,499);assert(!rows["private-offer-proof-valid"]);assert(rows["private-offer-proof-age-ms"]==MAXDWORD);
o.username_size=1;diagnose_private_offer(o,501);assert(!rows["private-offer-secrets-valid"]);
o.node[0]='G';diagnose_private_offer(o,501);assert(!rows["private-offer-binding-valid"]);
}
"""
with tempfile.TemporaryDirectory(prefix='offer-scalar-',dir='/root/.hermes/cache/scratch') as d:
 p=Path(d);(p/'t.cpp').write_text(code)
 subprocess.run(['g++','-std=c++20','-I'+str(root/'apps/windows-client/prototype'),str(p/'t.cpp'),'-o',str(p/'t')],check=True)
 subprocess.run([str(p/'t')],check=True)
print('extracted private-offer DWORD diagnostics: freshness/budget/binding/secrets/LastError passed; no native evidence')
