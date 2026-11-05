"""Portable extracted policy + source integration, not Windows IPC acceptance."""
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[3]
CONTROL = ROOT / 'apps/windows-service/prototype/online_control_win.cpp'
P = Path('/var/tmp/hermes-runtime/tmp/orangespace-single-prototype-20261102')
class ControlTests(unittest.TestCase):
    def test_trusted_metadata_and_renewed_live_tuple(self):
        self.assertTrue(CONTROL.exists(), 'missing trusted PrototypeControl implementation')
        source = CONTROL.read_text().split('// CONTROL_POLICY_BEGIN\n')[1].split('// CONTROL_POLICY_END')[0]
        body = r'''
#include "orangespace/service_chain.hpp"
#include <cassert>
''' + source + r'''
int main() {
 namespace c=orangespace::service::chain; namespace p=orangespace::service::win::control_detail;
 c::Binding b{"11111111-1111-4111-8111-111111111111","22222222-2222-4222-8222-222222222222","33333333-3333-4333-8333-333333333333","44444444-4444-4444-8444-444444444444",1};
 auto diag=[&](bool fresh,std::int64_t expiry,std::int64_t deadline,std::int64_t observed){return "{\"ok\":true,\"browser_allowed\":false,\"binding\":"+c::binding_json(b)+",\"server_expiry\":"+std::to_string(expiry)+",\"deadline_ms\":"+std::to_string(deadline)+",\"clock\":\""+std::string(c::nd::lease_clock)+"\",\"observed_at_ms\":"+std::to_string(observed)+",\"fresh_proof\":"+(fresh?"true":"false")+",\"reason\":\"verified\"}";};
 auto rejects=[&](auto f){bool denied=false;try{f();}catch(...){denied=true;}assert(denied);};
 auto full=p::full_binding(diag(true,200,20000,9000),b,10000,100);
 assert(full==b && full.server_expiry==200 && full.deadline_ms==20000);
 rejects([&]{p::full_binding(diag(false,200,20000,9000),b,10000,100);});
 rejects([&]{p::full_binding(diag(true,100,20000,9000),b,10000,100);});
 rejects([&]{p::full_binding(diag(true,200,10000,9000),b,10000,100);});
 rejects([&]{p::full_binding(diag(true,200,20000,7000),b,10000,100);});
 rejects([&]{p::full_binding(diag(true,200,20000,10001),b,10000,100);});
 auto wrong=b;wrong.generation=2;rejects([&]{p::full_binding(diag(true,200,20000,9000),wrong,10000,100);});
 auto floating=diag(true,200,20000,9000);floating.replace(floating.find("20000"),5,"20000.0");
 rejects([&]{p::full_binding(floating,b,10000,100);});
 const auto status="{\"ok\":true,\"auth_id\":\"a\",\"user_id\":"+c::quote(b.user)+",\"node_id\":"+c::quote(b.node)+",\"browser_allowed\":false,\"tunnels\":[{\"binding\":"+c::binding_json(b)+",\"process_started\":true,\"tunnel_authenticated\":true,\"forwarding_verified\":true}]}";
 // Initial deadline is deliberately in the past: current Engine status owns renewal authority.
 b.deadline_ms=1;p::live_status(status,"a",b);
 rejects([&]{p::live_status(status,"wrong-auth",b);});
 b.generation=2;rejects([&]{p::live_status(status,"a",b);});
}
'''
        with tempfile.TemporaryDirectory(prefix='control-policy-', dir=P) as d:
            cpp=Path(d)/'test.cpp'; cpp.write_text(body); exe=Path(d)/'test'
            subprocess.run(['g++','-std=c++20','-Wall','-Wextra','-Werror','-I'+str(ROOT/'apps/windows-service/include'),'-I'+str(ROOT/'apps/windows-client/include'),str(cpp),'-o',str(exe)],check=True)
            subprocess.run([str(exe)],check=True)
    def test_glue_ownership_and_namespace(self):
        self.assertTrue(CONTROL.exists(), 'missing trusted PrototypeControl implementation')
        s=CONTROL.read_text()
        for token in ['make_prototype_platform_chain_backend()', 'make_prototype_chain_namespace()', 'serve_owned_connection(', 'dispatch_platform_chain(', 'engine.diagnose(', 'take_local_channel(', 'engine.poll()', 'engine.tick()', 'SetEvent(service_stop)', 'ORANGESPACE_PROTOTYPE_NODE_UUID']:
            self.assertIn(token,s)
        self.assertLess(s.index('if (delivered && prepared)'),s.index('take_local_channel('))
        self.assertNotIn('CreateProcess',s)
        self.assertNotIn('NetworkIsolation',s)
        self.assertIn('3000',s)
        self.assertIn('200',s)
if __name__ == '__main__': unittest.main()
