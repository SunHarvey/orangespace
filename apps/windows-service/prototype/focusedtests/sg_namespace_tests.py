"""SG development copy namespace isolation; portable policy, not native WFP evidence."""
from pathlib import Path
import subprocess,tempfile,re
R=Path(__file__).resolve().parents[4]
source='''#include <cassert>
#include <string_view>
#include "orangespace/prototype_namespace.hpp"
#include "admission_protocol.hpp"
#include "operator-private/orangespace/install_identity.hpp"
int main(){
using namespace orangespace::prototype;
assert(std::wstring_view(kService)==L"OrangeSpaceSinglePrototype.SG.v25");
assert(std::wstring_view(kPipe)==LR"(\\\\.\\pipe\\OrangeSpace.SinglePrototype.SG.v25.Admission.v1)");
assert(std::wstring_view(orangespace::prototype_operator_install_identity::service_name)==std::wstring_view(kService));
assert(std::wstring_view(orangespace::prototype_operator_install_identity::pipe_prefix)==LR"(\\\\.\\pipe\\OrangeSpace.SinglePrototype.SG.v25.Control.v1.session.)");
auto paths=orangespace::service::win::prototype_namespace_paths(L"C:\\\\Program Files\\\\OrangeSpace-SG-v25\\\\");
assert(paths.anchor==L"C:\\\\Program Files\\\\OrangeSpace-SinglePrototype-SG-v25-State\\\\namespace.anchor");
assert(paths.state==L"C:\\\\Program Files\\\\OrangeSpace-SinglePrototype-SG-v25-State\\\\service-state.json");
assert(paths.next==L"C:\\\\Program Files\\\\OrangeSpace-SinglePrototype-SG-v25-State\\\\service-state.next");
}
'''
with tempfile.TemporaryDirectory(prefix='sg-namespace-',dir='/var/tmp/hermes-runtime/tmp') as t:
 p=Path(t);(p/'test.cpp').write_text(source)
 subprocess.run(['c++','-std=c++20','-UNDEBUG','-Wall','-Wextra','-Werror','-I'+str(R/'apps/windows-service/include'),'-I'+str(R/'apps/windows-client/include'),'-I'+str(R/'apps/windows-client/prototype'),str(p/'test.cpp'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True)
s=(R/'drivers/wfp-prototype/network_policy_win.cpp').read_text()
for old in ['0xdbacf1e1','0xdbacf1e2','0xdbacf200','0xdbad01e1','0xdbad01e2','0xdbad0200']:
 assert old not in s,'must preserve original v24 namespace: '+old
for new in ['0xdbad11e1','0xdbad11e2','0xdbad1200','0xdbad21e1','0xdbad21e2','0xdbad2200']:
 assert new in s,'new SG namespace absent: '+new
print('PASS actual namespace paths/protocol bindings; separate WFP keys')
