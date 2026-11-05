"""Execute extracted production browser_request/check/finish_run with real Engine.

Portable deterministic policy/interleaving evidence, not native Windows IPC/WFP.
Only Win32 events/publication mutex are injected; Engine expiry and cleanup are real.
"""
from pathlib import Path
import argparse
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
CONTROL = ROOT / 'apps/windows-service/prototype/online_control_win.cpp'
SCRATCH = Path('/root/.hermes/cache/scratch')


def method(source, signature):
    start = source.index(signature)
    brace = source.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


def program(source):
    # Existing stateful backend/session seams; real service_chain.hpp Engine.
    existing = (ROOT / 'apps/windows-service/tests/chain_tests.cpp').read_text()
    seams = existing[:existing.index('void lease_v2_engine_tests()')]
    policy = source.split('// CONTROL_POLICY_BEGIN\n')[1].split('// CONTROL_POLICY_END')[0]
    methods = '\n'.join(method(source, s) for s in [
        'chain::Response browser_request(', 'std::shared_ptr<const Published> snapshot()',
        'void check(const Published& p)', 'void PrototypeControl::finish_run('])
    methods = methods.replace('void PrototypeControl::finish_run(', 'void finish_run(')
    return seams + r'''
#include "private_channel.hpp"
#include <cstring>
#include <iostream>
''' + policy + r'''
namespace test {
namespace chain=orangespace::service::chain;
namespace json=orangespace::json;
namespace prototype=orangespace::prototype;
namespace nd=chain::nd;
namespace control_detail=orangespace::service::win::control_detail;
using orangespace::service::Peer;
using DWORD=std::uint32_t;
constexpr int WAIT_TIMEOUT=258;
struct Event { int get() const{return 0;} };
int WaitForSingleObject(int,int){return WAIT_TIMEOUT;}
void ResetEvent(int){}
struct Mutex {
  std::mutex value;
  bool held=false;
  int unlocks=0;
  std::function<void(int)> after_unlock;
  void lock(){value.lock();held=true;}
  void unlock(){held=false;value.unlock();++unlocks;if(after_unlock)after_unlock(unlocks);}
};
struct LocalChannel { chain::Binding binding; };
struct ObservedEngine {
  Engine& real; Mutex& publication; int status_calls=0;
  std::string status(const Peer& p,std::string_view auth){
    ++status_calls;::check(!publication.held,"Engine status must not hold publication mutex");
    return real.status(p,auth);
  }
  chain::Cursor stop(const Peer& p,std::string_view auth,const chain::Cursor& cursor){
    ::check(!publication.held,"Engine stop must not hold publication mutex");
    return real.stop(p,auth,cursor);
  }
};
struct Control {
  struct Published {std::string auth;std::shared_ptr<const LocalChannel> channel;};
  Peer peer{"S-1-5-21-100",1,99};
  std::int64_t wall=100,mono=100000;
  FakeBackend backend;
  Engine real{peer,backend,[this]{return wall;},std::make_shared<Namespace>(),[this]{return mono;}};
  Mutex mutex;
  ObservedEngine engine{real,mutex};
  std::mutex lifecycle;
  std::shared_ptr<const Published> published,last;
  prototype::BrowserFrame browser,pending_command;
  std::string package_sid="package",profile_name="profile",auth;
  DWORD process_id=40;
  std::uint64_t process_birth=123,sequence=0;
  bool desktop=false,close_requested=false,launch_reserved=true;
  Event stop,ready;int service_stop=0;
  Control* impl_=this;
  Control(){
    auth=real.authorize(peer,"closed-status","{}");backend.last->clock=[this]{return mono;};
    auto binding=real.start(peer,auth);
    published=std::make_shared<const Published>(Published{auth,std::make_shared<const LocalChannel>(LocalChannel{binding})});
    browser.phase=3;
  }
''' + methods + r'''
  std::string request(int command=0,std::string request_auth="",std::optional<Binding> binding={}){
    auto owner=published?published:last;
    nd::JsonGuard doc("{\"auth_id\":"+chain::quote(request_auth.empty()?auth:request_auth)+
      ",\"binding\":"+chain::binding_json(binding?*binding:owner->channel->binding)+
      ",\"command\":"+std::to_string(command)+",\"url\":\"https://example.com/\"}");
    return browser_request(doc.value).body;
  }
  void finish(){auto channel=published->channel;finish_run(*channel);}
};
template<class F> void denied(F f,const char* message){bool rejected=false;try{f();}catch(...){rejected=true;}::check(rejected,message);}
void expired_closed(){
  Control c;c.finish();c.wall=1000;
  denied([&]{c.real.status(c.peer,c.auth);},"real Engine.status must reject expired Auth");
  const auto calls=c.engine.status_calls;
  std::cout<<"BASELINE real Engine.status expired rejection confirmed; requesting exact finished last owner"<<std::endl;
  auto response=c.request();
  nd::JsonGuard doc(response);const auto& b=nd::field(doc.value,"browser");nd::object(b,14);
  ::check(nd::integer(nd::field(b,"phase"),0)==0 && nd::integer(nd::field(b,"process_id"),0)==0,
    "expired exact last owner must report closed and pid zero");
  ::check(c.engine.status_calls==calls,"closed snapshot must not call expired get/status");
  c.real.retire(c.peer,c.auth);
  ::check(c.backend.last->logouts==0,"retire cleanup never logs out shared session");
  std::cout<<"PASS expired closed snapshot -> real cleanup_get retire\n";
}
void expiry_during_finish(){
  Control c;c.wall=1000;
  denied([&]{c.finish();},"finish_run's existing expired Engine.stop must still throw");
  ::check(!c.published && c.last && c.browser.phase==0 && c.process_id==0,"actual finish_run retains closed receipt before stop");
  (void)c.request();::check(c.engine.status_calls==0,"closed receipt after expired stop skips status");
  auto foreign=c.peer;++foreign.logon;
  denied([&]{c.real.retire(foreign,c.auth);},"cleanup still rejects foreign OS peer");
  c.real.retire(c.peer,c.auth);
  ::check(c.backend.closed>0 && c.backend.last->revokes>0,"real cleanup_get must close and revoke retained tunnel");
  ::check(c.backend.last->logouts==0,"retire must preserve login");
  std::cout<<"PASS expiry during actual finish_run -> exact-peer retire\n";
}
void ownership_negatives(){
  Control c;c.finish();c.wall=1000;
  denied([&]{c.request(0,"foreign-auth");},"foreign Auth must reject closed read");
  auto original=c.last->channel->binding;
  for(int field=0;field<5;++field){
    auto wrong=original;
    if(field==0)wrong.user="55555555-5555-4555-8555-555555555555";
    if(field==1)wrong.node="55555555-5555-4555-8555-555555555555";
    if(field==2)wrong.sandbox="55555555-5555-4555-8555-555555555555";
    if(field==3)wrong.tunnel="55555555-5555-4555-8555-555555555555";
    if(field==4)++wrong.generation;
    denied([&]{c.request(0,c.auth,wrong);},"full Binding tuple/generation mismatch must reject");
  }
  ::check(c.engine.status_calls==0,"foreign owner denied before Engine");
  c.last.reset();
  // Explicit wire value so missing last is exercised inside production method.
  nd::JsonGuard doc("{\"auth_id\":"+chain::quote(c.auth)+",\"binding\":"+chain::binding_json(original)+",\"command\":0,\"url\":\"\"}");
  denied([&]{c.browser_request(doc.value);},"unknown last owner must never report closed");
  std::cout<<"PASS foreign Auth / all five Binding fields / unknown owner\n";
}
void nonclosed_negatives(){
  for(int scenario=0;scenario<8;++scenario){
    Control c;
    if(scenario<6)c.finish();
    if(scenario<4)c.browser.phase=scenario+1;
    if(scenario==4)c.process_id=99;
    if(scenario==5){c.browser.phase=3;c.process_id=40;} // helper lost but browser not confirmed closed
    if(scenario==6){c.browser.phase=0;c.process_id=0;} // a live publication is not a closed receipt
    c.wall=1000;
    denied([&]{c.request();},"running/helper-lost/unknown closed state must keep expired get gate");
    ::check(c.engine.status_calls==1,"nonclosed owner must still consult Engine.status");
  }
  for(int command=1;command<=6;++command){
    Control c;c.finish();c.wall=1000;
    denied([&]{c.request(command);},"closed receipt must not authorize any command");
    ::check(c.engine.status_calls==1 && c.pending_command.command==0 && !c.close_requested && !c.desktop,
      "commands preserve original expired gate and no side effect");
  }
  std::cout<<"PASS running / all nonzero phases / pid / publication / commands 1..6 retain expiry gate\n";
}
void publication_races(){
  for(int scenario=0;scenario<7;++scenario){
    Control c;c.finish();c.wall=1000;
    const auto base=c.mutex.unlocks;
    c.mutex.after_unlock=[&](int count){
      // snapshot() releases once, captured owner/classification releases second.
      if(count!=base+(scenario==6?1:2))return;
      if(scenario==0||scenario==6)c.published=c.last;
      if(scenario==1)c.last=std::make_shared<const Control::Published>(*c.last);
      if(scenario==2)c.last.reset();
      if(scenario==3)c.browser.phase=3;
      if(scenario==4)c.process_id=41;
      if(scenario==5){auto changed=std::make_shared<LocalChannel>(*c.last->channel);++changed->binding.generation;
        c.last=std::make_shared<const Control::Published>(Control::Published{c.auth,changed});}
    };
    denied([&]{c.request();},"replacement/publication/phase/pid race must not return stale closed");
    ::check(c.engine.status_calls==(scenario==6?1:0),"short local recheck must reject race; no network under publication lock");
  }
  std::cout<<"PASS initial publication and final exact-owner/publication/phase/pid interleavings\n";
}
void active_gates(){
  {Control c;(void)c.request();::check(c.engine.status_calls==2,"live read retains status and actual check");}
  for(int command=1;command<=6;++command){
    Control c;
    if(command==6)c.browser.phase=1;
    (void)c.request(command);
    ::check(c.engine.status_calls==2,"active command retains Engine.status and actual check");
    if(command==6)::check(c.desktop&&c.browser.phase==2,"desktop command keeps original phase gate");
    else ::check(c.pending_command.command==static_cast<unsigned>(command),"active command still dispatched");
  }
  {Control c;c.pending_command.command=2;denied([&]{c.request(1);},"pending command gate remains");}
  {Control c;c.browser.phase=2;denied([&]{c.request(1);},"navigate phase gate remains");}
  {Control c;denied([&]{c.request(6);},"desktop phase gate remains");}
  {Control c;c.backend.living=false;denied([&]{c.request();},"actual check denies helper loss");}
  std::cout<<"PASS active status/check/pending/phase/helper gates\n";
}
}
int main(){try{
  test::expired_closed();test::expiry_during_finish();test::ownership_negatives();
  test::nonclosed_negatives();test::publication_races();test::active_gates();return 0;
}catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, default=CONTROL)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='closed-status-', dir=SCRATCH) as temporary:
        output = args.output or Path(temporary)
        output.mkdir(parents=True, exist_ok=True)
        cpp = output / 'extracted.cpp'
        exe = output / 'extracted-test'
        cpp.write_text(program(args.source.read_text()))
        subprocess.run(['g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pthread',
                        '-I'+str(ROOT/'apps/windows-service/include'),
                        '-I'+str(ROOT/'apps/windows-client/include'),
                        '-I'+str(ROOT/'apps/windows-client/prototype'),
                        str(cpp), '-o', str(exe)], check=True)
        subprocess.run([str(exe)], check=True)


if __name__ == '__main__':
    main()
