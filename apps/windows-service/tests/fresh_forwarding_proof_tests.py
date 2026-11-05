"""Extract the real control method; fake only OS/Engine/time dependencies.
Not Windows IPC, network forwarding, or browsing acceptance.
"""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
CONTROL = ROOT / 'apps/windows-service/prototype/online_control_win.cpp'
SCRATCH = Path(os.environ.get('TMPDIR', '/root/.hermes/cache/scratch'))


class FreshForwardingProofTests(unittest.TestCase):
    def test_real_method_probe_and_fail_closed_fences(self):
        source = CONTROL.read_text()
        signature = 'std::int64_t PrototypeControl::fresh_forwarding_proof(const LocalChannel& channel) {'
        self.assertIn(signature, source, 'missing actual forwarding probe refresh; old immutable proof expires during Root setup')
        method = source[source.index(signature):source.index('\nvoid PrototypeControl::publish_root', source.index(signature))]
        # Deterministic clocks only. All identity/budget/probe/full_binding logic is extracted verbatim.
        method = method.replace('nd::monotonic_ms()', 'test_now()')
        policy = source.split('// CONTROL_POLICY_BEGIN\n')[1].split('// CONTROL_POLICY_END')[0]
        harness = r'''
#include "orangespace/prototype_local_channel.hpp"
#include "private_channel.hpp"
#include <cassert>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
''' + policy + r'''
namespace orangespace::service::win {
namespace nd=chain::nd;
static std::int64_t clock_ms=10000,wall=100;
std::int64_t test_now(){return clock_ms;}
std::int64_t chain_now(){return wall;}
constexpr int WAIT_TIMEOUT=258;
struct Event {int value{};int* get(){return &value;}};
int WaitForSingleObject(int* e,int){return *e?0:WAIT_TIMEOUT;}
struct FakeEngine {
 std::function<std::string()> run;
 std::string diagnose(int,std::string_view auth,const chain::Binding&){assert(auth=="auth");return run();}
};
struct PrototypeControl {
 struct Impl {
  struct Published {std::string auth;std::shared_ptr<const LocalChannel> channel;};
  std::mutex mutex;std::shared_ptr<const Published> published;
  Event stop,service;int* service_stop=service.get();int peer=7;FakeEngine engine;
  std::function<void()> on_check;int checks=0;
  auto snapshot(){std::lock_guard lock(mutex);return published;}
  void check(const Published&){++checks;assert(mutex.try_lock());mutex.unlock();if(on_check)on_check();nd::require(!stop.value&&!service.value);}
 };
 std::unique_ptr<Impl> impl_=std::make_unique<Impl>();
 std::int64_t fresh_forwarding_proof(const LocalChannel& channel);
};
''' + method + r'''
}
int main(){
 namespace c=orangespace::service::chain;namespace w=orangespace::service::win;
 c::Binding b{"11111111-1111-4111-8111-111111111111","22222222-2222-4222-8222-222222222222","33333333-3333-4333-8333-333333333333","44444444-4444-4444-8444-444444444444",1,200,35000};
 auto channel=std::make_shared<const w::LocalChannel>(b,c::LeaseBudget{std::string(c::nd::lease_clock),5000,30000,35000},1234,"1234567890123456","abcdefghijklmnop",6547);
 using Published=w::PrototypeControl::Impl::Published;
 int cases=0;
 auto scenario=[&](std::string name,bool accept,std::function<void(w::PrototypeControl&)> setup){
  w::clock_ms=10000;w::wall=100;w::PrototypeControl ctl;auto& i=*ctl.impl_;
  i.published=std::make_shared<const Published>(Published{"auth",channel});
  int probes=0;
  i.engine.run=[&]{++probes;assert(i.mutex.try_lock());i.mutex.unlock();w::clock_ms+=10;return "{\"ok\":true,\"browser_allowed\":false,\"binding\":"+c::binding_json(b)+",\"server_expiry\":210,\"deadline_ms\":40000,\"clock\":\""+std::string(c::nd::lease_clock)+"\",\"observed_at_ms\":"+std::to_string(w::clock_ms)+",\"fresh_proof\":true,\"reason\":\"verified\"}";};
  setup(ctl);bool ok=false;std::int64_t proof=-1;
  try{proof=ctl.fresh_forwarding_proof(*channel);ok=true;}catch(...){}
  if(ok!=accept){std::cerr<<"scenario "<<name<<" expected "<<accept<<" got "<<ok<<"\n";std::abort();}
  if(ok){assert(proof==10000);assert(probes==1);assert(i.checks==2);}
  if(ok){
   namespace p=orangespace::prototype;
   p::Reply base{};base.status=2;base.pid=base.root_pid=1;base.created=base.root_created=2;
   p::PrivateOffer offer{};offer.base=base;offer.nonce[0]=1;
   auto copy=[](auto& out,const auto& text){std::memcpy(out.data(),text.data(),out.size());};
   copy(offer.user,b.user);copy(offer.sandbox,b.sandbox);copy(offer.node,b.node);copy(offer.tunnel,b.tunnel);
   offer.generation=b.generation;offer.expiry=b.server_expiry;offer.binding_deadline=b.deadline_ms;
   offer.started=channel->budget.request_started_ms;offer.ttl=channel->budget.remaining_ttl_ms;offer.deadline=channel->budget.deadline_ms;
   offer.port=channel->port;offer.username_size=offer.password_size=16;
   std::memcpy(offer.username.data(),channel->username.view().data(),16);std::memcpy(offer.password.data(),channel->password.view().data(),16);
   offer.proof=channel->proof_observed_at_ms;auto original=offer;
   assert(!p::ValidPrivateOffer(offer,base,10000)); // Native's exact 3453ms age.
   offer.proof=proof;assert(p::ValidPrivateOffer(offer,base,w::clock_ms));
   assert(p::ValidPrivateOffer(offer,base,12999));assert(!p::ValidPrivateOffer(offer,base,13000)); // same offer at final ACK.
   offer.proof=original.proof;assert(!std::memcmp(&offer,&original,sizeof(offer)));
  }
  assert(channel->proof_observed_at_ms==6547&&channel->budget.request_started_ms==5000&&channel->budget.deadline_ms==35000&&channel->binding.same_authority(b));
  ++cases;std::cout<<"PASS "<<name<<"\n";
 };
 scenario("3453ms-old-proof-is-replaced-by-real-probe-lower-bound-with-renewed-authority",true,[](auto&){});
 auto wrap=[&](auto& ctl,auto action){auto old=ctl.impl_->engine.run;ctl.impl_->engine.run=[old,action]{auto d=old();action(d);return d;};};
 scenario("probe-2999ms",true,[&](auto& ctl){wrap(ctl,[](auto&){w::clock_ms=12999;});});
 scenario("probe-3000ms",false,[&](auto& ctl){wrap(ctl,[](auto&){w::clock_ms=13000;});});
 scenario("probe-5000ms",false,[&](auto& ctl){wrap(ctl,[](auto&){w::clock_ms=15000;});});
 scenario("absent-published-before-probe",false,[](auto& ctl){ctl.impl_->published.reset();});
 scenario("foreign-channel-before-probe",false,[&](auto& ctl){auto foreign=std::make_shared<const w::LocalChannel>(b,channel->budget,1234,"1234567890123456","abcdefghijklmnop",6547);ctl.impl_->published=std::make_shared<const Published>(Published{"auth",foreign});});
 scenario("replacement-during-probe-same-channel",false,[&](auto& ctl){wrap(ctl,[&ctl,&channel](auto&){ctl.impl_->published=std::make_shared<const Published>(Published{"auth",channel});});});
 scenario("logout-during-probe",false,[&](auto& ctl){wrap(ctl,[&ctl](auto&){ctl.impl_->published.reset();});});
 scenario("stop-before-probe",false,[](auto& ctl){ctl.impl_->stop.value=1;});
 scenario("service-stop-during-probe",false,[&](auto& ctl){wrap(ctl,[&ctl](auto&){ctl.impl_->service.value=1;});});
 scenario("stop-during-probe",false,[&](auto& ctl){wrap(ctl,[&ctl](auto&){ctl.impl_->stop.value=1;});});
 scenario("helper-lost-before-probe",false,[](auto& ctl){ctl.impl_->on_check=[]{c::nd::require(false);};});
 scenario("helper-lost-after-probe",false,[](auto& ctl){ctl.impl_->on_check=[&ctl]{c::nd::require(ctl.impl_->checks!=2);};});
 scenario("replacement-in-precheck-never-probes",false,[&](auto& ctl){ctl.impl_->on_check=[&ctl]{if(ctl.impl_->checks==1)ctl.impl_->published.reset();};ctl.impl_->engine.run=[]()->std::string{assert(false&&"must fence owner again after precheck and before network");return {};};});
 scenario("budget-expires-in-precheck-never-probes",false,[&](auto& ctl){w::clock_ms=34995;ctl.impl_->on_check=[]{w::clock_ms=35000;};ctl.impl_->engine.run=[]()->std::string{assert(false&&"must fence original budget after precheck and before network");return {};};});
 scenario("original-budget-expired-before-probe",false,[](auto&){w::clock_ms=35000;});
 scenario("original-budget-expired-during-probe-despite-renewal",false,[](auto&){w::clock_ms=34995;});
 auto change=[](auto& d,std::string_view old,std::string_view next){auto at=d.find(old);assert(at!=std::string::npos);d.replace(at,old.size(),next);(void)orangespace::json::parse(d);};
 scenario("renewal-identity-mismatch",false,[&](auto& ctl){wrap(ctl,[change](auto& d){change(d,"\"generation\":1","\"generation\":2");});});
 scenario("stale-server-authority",false,[&](auto& ctl){wrap(ctl,[change](auto& d){change(d,"\"server_expiry\":210","\"server_expiry\":100");});});
 scenario("stale-monotonic-authority",false,[&](auto& ctl){wrap(ctl,[change](auto& d){change(d,"\"deadline_ms\":40000","\"deadline_ms\":10000");});});
 scenario("negative-real-probe",false,[&](auto& ctl){wrap(ctl,[change](auto& d){change(d,"\"fresh_proof\":true","\"fresh_proof\":false");});});
 scenario("engine-probe-throws",false,[](auto& ctl){ctl.impl_->engine.run=[]()->std::string{throw 1;};});
 scenario("replacement-in-final-check",false,[&](auto& ctl){ctl.impl_->on_check=[&ctl,&channel]{if(ctl.impl_->checks==2)ctl.impl_->published=std::make_shared<const Published>(Published{"auth",channel});};});
 scenario("budget-expires-in-final-check",false,[](auto& ctl){ctl.impl_->on_check=[&ctl]{if(ctl.impl_->checks==2)w::clock_ms=35000;};});
 scenario("proof-expires-in-final-check",false,[](auto& ctl){ctl.impl_->on_check=[&ctl]{if(ctl.impl_->checks==2)w::clock_ms=13000;};});
 scenario("clock-rewinds-after-probe",false,[&](auto& ctl){ctl.impl_->on_check=[&ctl]{if(ctl.impl_->checks==2)w::clock_ms=9999;};});
 std::cout<<cases<<" scenarios passed\n";
}
'''
        with tempfile.TemporaryDirectory(prefix='fresh-forward-proof-', dir=SCRATCH) as d:
            cpp = Path(d) / 'test.cpp'
            cpp.write_text(harness)
            exe = Path(d) / 'test'
            subprocess.run(['g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pthread', '-I'+str(ROOT/'apps/windows-service/include'), '-I'+str(ROOT/'apps/windows-client/include'), '-I'+str(ROOT/'apps/windows-client/prototype'), str(cpp), '-o', str(exe)], check=True)
            subprocess.run([str(exe)], check=True)

    def test_only_private_offer_proof_refreshes(self):
        s = (ROOT/'apps/windows-service/prototype/service_win.cpp').read_text()
        self.assertIn('o.proof=control.fresh_forwarding_proof(*channel);', s)
        self.assertNotIn('o.proof=channel->proof_observed_at_ms;', s)
        self.assertIn('p::ValidPrivateOffer(o,reply,orangespace::service::chain::nd::monotonic_ms())', s)
        method = CONTROL.read_text().split('std::int64_t PrototypeControl::fresh_forwarding_proof', 1)[-1].split('void PrototypeControl::publish_root', 1)[0]
        for forbidden in ['revoke()', 'impl_->lifecycle', 'same_authority', 'take_local_channel', 'catch(']:
            self.assertNotIn(forbidden, method)


if __name__ == '__main__':
    unittest.main()
