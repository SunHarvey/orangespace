from pathlib import Path
import re, subprocess, tempfile
s=(Path(__file__).resolve().parents[1]/'service_win.cpp').read_text()
m=re.search(r'need\((f->filterId==v.filterId[^;]+)\);',s)
assert m is not None
expr=m.group(1)
cpp='''#include <cassert>
#include <cstdint>
enum class IdentityScope {ExecutablePath,ExactAppContainerSid};
constexpr unsigned FWP_ACTION_BLOCK=1,FWP_UINT64=2;
struct Weight {unsigned type;std::uint64_t* uint64;};
struct Filter {std::uint64_t filterId;struct {unsigned type;} action;unsigned numFilterConditions;void*filterCondition;void*providerKey;Weight weight,effectiveWeight;};
struct Verified {std::uint64_t filterId;IdentityScope identityScope;};
bool actual(Filter* f,Verified v){return EXPR;}
int main(){int value;std::uint64_t weight=1;Filter f{1,{1},1,&value,nullptr,{2,&weight},{2,&weight}};
 assert(actual(&f,{1,IdentityScope::ExecutablePath}));
 assert(!actual(&f,{1,IdentityScope::ExactAppContainerSid}));
 f.providerKey=&value;
 assert(actual(&f,{1,IdentityScope::ExactAppContainerSid}));
 assert(!actual(&f,{1,IdentityScope::ExecutablePath}));
}
'''.replace('EXPR',expr)
with tempfile.TemporaryDirectory(dir='/var/tmp/hermes-runtime/tmp') as d:
 p=Path(d);(p/'test.cpp').write_text(cpp)
 subprocess.run(['g++','-std=c++20','-Wall','-Wextra','-Werror',str(p/'test.cpp'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True)
print('actual snapshot metadata predicate 4 provider-scope cases pass; injected policy, not Windows BFE')
