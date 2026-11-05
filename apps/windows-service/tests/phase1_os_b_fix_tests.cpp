// Portable deterministic protocol models, NOT native Windows/API evidence.
#include "phase1_os_b_policy.hpp"
#include "orangespace/credential_store.hpp"
#include <barrier>
#include <thread>
#include <iostream>
using namespace phase1_os_b;
void check(bool b,const char* message){if(!b)throw std::runtime_error(message);}
void sc1(){
 namespace ns=orangespace::node_session;
 for(auto prefix:{std::string{},std::string("/nodes/11111111-1111-4111-8111-111111111111")}){
  ns::detail::NodeEntry node{"a","11111111-1111-4111-8111-111111111111","node.example",443,prefix};
  check(capture_entropy("S-1-5-21-1-2-3-1001",node.node_id,ns::detail::api_origin(node))==ns::credential_detail::entropy("S-1-5-21-1-2-3-1001",node),"actual production entropy adapter equality");
 }
 // Both tokens belong to the SAME server user. Only replacement B is live.
 std::string canonical="stale-A",held=canonical;std::barrier rendezvous(2);
 bool store_passed=false,exact_called=false,rejected=false;
 std::thread replace([&]{rendezvous.arrive_and_wait();canonical="live-B";rendezvous.arrive_and_wait();});
 rendezvous.arrive_and_wait();rendezvous.arrive_and_wait();replace.join();
 try{capture_positive(held,[&]{check(canonical=="live-B","replacement store positive");store_passed=true;},[&](std::string_view bytes){exact_called=true;check(bytes=="live-B","exact captured object is stale despite same user");});}catch(...){rejected=true;}
 check(store_passed,"old production positive passes replacement");
 check(rejected&&exact_called,"SC1: wrong-object positive must not authorize stale held bytes");
 held="live-B";unsigned positives=0;capture_positive(held,[&]{++positives;},[&](std::string_view bytes){check(bytes==held,"same buffer");++positives;});
 check(positives==2,"both live positives required");
 bool skipped=true;try{capture_positive(held,[]{throw std::runtime_error("store failure");},[&](std::string_view){skipped=false;});}catch(...){}check(skipped,"store failure cannot be bypassed by raw positive");
}
void sc2(){
 struct Ops{std::string calls;char fail=0;bool step(char c){calls+=c;return c!=fail;}bool reap(){return step('R');}bool unload(){return step('U');}bool erase_profile(){return step('P');}bool profile_absent(){return step('V');}bool no_profile(){return step('N');}bool account_matches(){return step('M');}bool erase_account(){return step('A');}bool account_absent(){return step('Z');}};
 // Mirrors fresh_profile_sid failing before profile_attempted becomes true.
 for(const char* forced:{"preexisting registry","preexisting hive","read failure"}){
  (void)forced;CleanupFacts unknown{true,true,false,false,false};Ops ops;
  check(!cleanup(unknown,ops)&&ops.calls=="R","SC2: unknown/unexpected pre-profile state must preserve owned SAM + SID");
 }
 for(auto list:{Presence::absent,Presence::present,Presence::unknown})for(auto hive:{Presence::absent,Presence::present,Presence::unknown}){
  CleanupFacts f{true,true,false,false,false,profile_probe(list,hive)};Ops ops;bool ok=cleanup(f,ops);
  check(ok==(list==Presence::absent&&hive==Presence::absent),"tri-state registry/hive matrix");
  check(ops.calls==(ok?"RNMAZ":"R"),"whole cleanup ordering for pre-profile state");
 }
 for(auto state:{ProfileState::unknown,ProfileState::unexpected_present,ProfileState::attempted}){
  CleanupFacts f{true,true,true,true,true,state};Ops ops;check(!cleanup(f,ops)&&ops.calls=="R","unbound profile preserves SAM");
 }
 CleanupFacts owned{true,true,true,true,true,ProfileState::owned_loaded};Ops owned_ops;check(cleanup(owned,owned_ops)&&owned_ops.calls=="RUPVMAZ","exact owned cleanup before SAM");
 owned.profile_state=ProfileState::owned_removed;Ops retry;check(cleanup(owned,retry)&&retry.calls=="RVMAZ","removed retry verifies absence before SAM");
 CleanupFacts never_loaded{true,true,false,false,false,ProfileState::verified_no_profile};
 for(char fault:std::string("RNMAZ")){Ops ops;ops.fail=fault;check(!cleanup(never_loaded,ops)&&ops.calls.back()==fault,"never-loaded cleanup stops at first failed recheck/SAM dependency");}
 Ops gap;never_loaded.sid_owned=false;check(!cleanup(never_loaded,gap)&&gap.calls=="R","NetUserAdd-to-SID receipt gap cannot authorize name deletion");
}
void le1(){
 check(remaining_ms(0,UINT32_MAX)!=UINT32_MAX,"LE1: finite deadline must never become native INFINITE wait");
 struct Delayed {bool unbounded=false,done=false,cancelled=false,cancel_succeeds=true;unsigned waited=0;bool cancel(){cancelled=true;return cancel_succeeds;}void drain_unbounded(){unbounded=true;done=true;}void wait_cancel(unsigned ms){waited+=ms;}bool completed(){return done;}} op;
 auto outcome=cancel_pending(op);
 check(!op.unbounded&&op.cancelled&&op.waited<=50&&outcome==CancelOutcome::retained,"LE1: delayed cancel must not drain unbounded or free pending operation");
 struct Owned {
  bool* done;unsigned* destroyed;std::string buffer=std::string(max_frame+4,'s');
  ~Owned(){++*destroyed;std::fill(buffer.begin(),buffer.end(),'\0');}
  bool completed()noexcept{return *done;}
 };
 bool done=false;unsigned destroyed=0;IoBudget<Owned> budget;
 check(budget.reserve()&&!budget.reserve(),"reserve before issue enforces one operation");
 auto owned=std::make_unique<Owned>();owned->done=&done;owned->destroyed=&destroyed;auto* kernel_view=owned.get();
 budget.quarantine(std::move(owned));
 for(unsigned i=0;i<10000;++i)check(!budget.reserve(),"quarantine cannot grow repeated allocations");
 check(!budget.reap_retained()&&destroyed==0&&kernel_view->buffer.back()=='s',"pending buffer and operation survive caller unwinding");
 done=true;check(budget.reap_retained()&&destroyed==1&&!budget.has_retained(),"only real completion releases retained operation");
 check(!budget.reserve(),"reaped poison is permanent: no silent channel reset");
 for(bool cancel_succeeds:{false,true}){
  Delayed fault;fault.cancel_succeeds=cancel_succeeds;check(cancel_pending(fault)==CancelOutcome::retained,"cancel success/failure is not completion");
  fault.done=true;check(cancel_pending(fault)==CancelOutcome::completed,"terminal completion can free, never promotes timeout to success");
 }
 // Model a fragmented header then body, or stalled write, sharing ONE end.
 const std::uint64_t deadline=100;std::uint64_t now=0;
 for(auto advance:{20u,30u,40u}){now+=advance;check(remaining_ms(now,deadline)==deadline-now,"partial transfer consumes same budget");}
 check(remaining_ms(99,deadline)==1&&remaining_ms(100,deadline)==0&&remaining_ms(101,deadline)==0,"partial body/stalled write cannot reset deadline");
 IoProgress header(4,deadline);check(header.advance(1)&&header.left()==3&&header.remaining(20)==80,"partial header");
 check(header.advance(3)&&header.complete(),"header completed");IoProgress body(10,header.deadline);
 check(body.advance(3)&&body.left()==7&&body.remaining(90)==10&&body.remaining(100)==0,"partial body retains header deadline");
 IoProgress write(max_frame+4,deadline);check(write.advance(2)&&write.remaining(100)==0,"stalled write shares absolute deadline");
 check(!write.advance(0)&&!body.advance(8),"closed peer/invalid completion cannot count as success");
 std::barrier rendezvous(2);IoBudget<Owned> concurrent;bool worker_reserved=false;
 std::thread worker([&]{worker_reserved=concurrent.reserve();rendezvous.arrive_and_wait();rendezvous.arrive_and_wait();concurrent.release();});
 rendezvous.arrive_and_wait();check(!concurrent.reserve(),"concurrent issue denied before kernel call");rendezvous.arrive_and_wait();worker.join();check(worker_reserved&&concurrent.reserve(),"completion permits next reservation");concurrent.release();
}
int main(int argc,char** argv){try{std::string id=argc>1?argv[1]:"SC1";if(id=="SC1")sc1();else if(id=="SC2")sc2();else if(id=="LE1")le1();else throw std::runtime_error("unknown slice");std::cout<<id<<" portable protocol model GREEN\n";return 0;}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
