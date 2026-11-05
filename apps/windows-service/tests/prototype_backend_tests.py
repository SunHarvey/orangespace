"""Actual extracted backend methods, explicit OS/FFI seams; NOT Windows proof."""
from pathlib import Path
import importlib.util,subprocess,sys
r=Path(__file__).resolve().parents[3];out=Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True)
spec=importlib.util.spec_from_file_location('extract',Path(__file__).with_name('extract_lease_v2_backend.py'))
assert spec is not None and spec.loader is not None
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
s=(r/'apps/windows-service/src/chain_windows.cpp').read_text()
h=m.generate(s)
h=h.replace('bool prototype_mixed_{};','bool prototype_mixed_{true}, platform_mode_{true};')
h=h.replace('throw std::runtime_error("unexpected prototype constructor");','return reinterpret_cast<void*>(1);')
take=m.block(s,'LocalChannel take_local_channel(').replace(' override','')
h=h.rsplit('};',1)[0]+take+'\n};\n'
(out/'lease_v2_backend_under_test.hpp').write_text(h)
f=Path(__file__).with_name('lease_v2_backend_tests.cpp').read_text().split('int main() {')[0]
f=f.replace('#include "orangespace/service_chain.hpp"','#include "orangespace/prototype_local_channel.hpp"\nusing namespace orangespace::service::win;')
pos=f.index('#define ORANGESPACE_TEST_ACTUAL_CALL')
f=f[:pos]+'''static int takes=0;
static std::function<void()> on_take;
static std::string take_reply;
std::ptrdiff_t os_runtime_take_local_channel_v1(void*,const std::uint8_t*,std::size_t,std::uint8_t* out,std::size_t capacity) {
 ++takes;assert(capacity==4096);if(on_take)on_take();
 std::copy(take_reply.begin(),take_reply.end(),out);return take_reply.size();
}
'''+f[pos:]
f=f.replace('#include <array>','#include <array>\n#include <cassert>')
f+='''int main() {
 Binding tuple{"11111111-1111-4111-8111-111111111111","22222222-2222-4222-8222-222222222222","33333333-3333-4333-8333-333333333333","44444444-4444-4444-8444-444444444444",1,131,110000};
 LeaseBudget grant{std::string(nd::lease_clock),100000,10000,110000};
 LeaseResult lease("{}",grant,131);
 take_reply="{\\"schema\\":2,\\"binding\\":"+binding_json(tuple)+",\\"host\\":\\"127.0.0.1\\",\\"port\\":19080,\\"username\\":\\"FIXTURE_ONLY_USER\\",\\"password\\":\\"FIXTURE_ONLY_PASSWORD\\",\\"clock\\":"+quote(grant.clock)+",\\"request_started_ms\\":100000,\\"remaining_ttl_ms\\":10000,\\"deadline_ms\\":110000,\\"proof_observed_at_ms\\":100000}";
 for(int mode=0;mode<14;++mode) {
  mono=100000;takes=0;on_take={};ffi_reply={};ExtractedBackend b;b.reserve("realm",tuple);
  if(mode!=1)(void)b.start("realm",tuple,lease);
  Binding arg=tuple;
  if(mode==2)arg.generation++;
  if(mode==3)arg.server_expiry++;
  if(mode==4)mono=110000;
  if(mode==5)b.poisoned_=true;
  if(mode==6)b.realms_.at("realm")->retired=true;
  if(mode==7)b.close("realm",tuple);
  if(mode==8)on_take=[&]{b.realms_.at("realm")->active.erase(tuple.tunnel);};
  if(mode==9)on_take=[]{mono=110000;};
  if(mode==10)on_take=[]{mono=103000;};
  if(mode==11)b.renew("realm",tuple,RenewResult{132,{std::string(nd::lease_clock),100000,11000,111000}});
  auto dead_root=[&] {
    ffi_reply=[&](std::string_view,std::uint8_t* output,std::size_t){
      const auto wire="{\\"exited\\":[{\\"binding\\":"+binding_json(tuple)+"}]}";
      std::copy(wire.begin(),wire.end(),output);return static_cast<std::ptrdiff_t>(wire.size());
    };
  };
  if(mode==12)dead_root();
  if(mode==13)on_take=dead_root;
  if(mode==0) {
   auto channel=b.take_local_channel("realm",arg);assert(channel.port==19080 && channel.budget.deadline_ms==110000);
   denies([&]{(void)b.take_local_channel("realm",arg);});assert(takes==1);
  } else {
   denies([&]{(void)b.take_local_channel("realm",arg);});
   assert(takes==((mode>=8 && mode<=10) || mode==13 ? 1 : 0));
   if(mode==9 || mode==10){mono=100000;denies([&]{(void)b.take_local_channel("realm",arg);});assert(takes==1);}
  }
 }
 std::cout<<"actual extracted prototype backend: once-only, exact authority, original deadline, proof age, retirement/poison/close/renew fences passed (injected OS/FFI)\\n";
}
'''
(out/'test.cpp').write_text(f)
subprocess.run(['g++','-std=c++20','-pthread','-Wall','-Wextra','-Werror','-I'+str(r/'apps/windows-service/include'),'-I'+str(r/'apps/windows-client/include'),'-I'+str(out),str(out/'test.cpp'),'-o',str(out/'test')],check=True)
subprocess.run([str(out/'test')],check=True)
