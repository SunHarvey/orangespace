#pragma once
#include <cstdint>
#include <array>
#include <vector>
namespace phase1_guardian {
enum class State { unknown, stopped, start_pending, stop_pending, running };
enum class Code : unsigned { ok, inspection_unknown, ownership_unknown, journal_failed, stop_failed, terminate_failed, exit_unknown, delete_failed, absence_unknown, capture_failed };
enum class Action { stop, terminate_root, terminate_helper, remove };
struct IntentSet {
 std::array<bool,5> written{};
 template<class Writer>void prepare(bool root,unsigned helper_mask,Writer write){
  auto attempt=[&](Action action,unsigned index,unsigned slot){if(written[slot])return;try{written[slot]=write(action,index);}catch(...){written[slot]=false;}};
  if(root)attempt(Action::terminate_root,0,1);
  for(unsigned i=0;i<2;++i)if(helper_mask&(1u<<i))attempt(Action::terminate_helper,i,2+i);
  attempt(Action::stop,0,0);attempt(Action::remove,0,4);
 }
 bool permits(Action a,unsigned i=0)const{
  switch(a){case Action::stop:return written[0];case Action::terminate_root:return written[1];case Action::terminate_helper:return i<2&&written[2+i];case Action::remove:return written[4];}return false;
 }
};
struct Status { State state=State::unknown; std::uint32_t pid=0; };
struct Report { bool removed=false; bool quiesced=false; std::vector<Code> errors; };
struct Adapter {
 virtual ~Adapter()=default;
 virtual Status query()=0;
 virtual bool capture(std::uint32_t)=0;
 virtual bool has_root() const=0;
 virtual bool start_attempted() const=0;
 virtual bool valid_root()=0;
 virtual bool root_exited()=0;
 virtual unsigned helpers() const=0;
 virtual bool valid_helper(unsigned)=0;
 virtual bool helper_exited(unsigned)=0;
 virtual bool before(Action,unsigned=0)=0;
 virtual bool stop()=0;
 virtual bool terminate_root()=0;
 virtual bool terminate_helper(unsigned)=0;
 virtual bool remove_and_verify_absence()=0;
 virtual void pause()=0;
 virtual bool record(Code)=0;
};
// Budgets bound polls, not the duration of an SCM RPC performed by the adapter.
inline Report cleanup(Adapter& a, unsigned budget=20, [[maybe_unused]] bool remove_registration=true) {
 Report r;
 auto call=[](auto fn, auto fallback) { try { return fn(); } catch (...) { return fallback; } };
 auto error=[&](Code c) { r.errors.push_back(c); if(!call([&]{return a.record(c);},false)) r.errors.push_back(Code::journal_failed); };
 auto permit=[&](Action action,unsigned i=0) { if(call([&]{return a.before(action,i);},false))return true;error(Code::journal_failed);return false; };
 auto inspect=[&] { auto s=call([&]{return a.query();},Status{});if(s.state==State::unknown)error(Code::inspection_unknown);
   if(call([&]{return a.start_attempted()&&!a.has_root();},false)&&!call([&]{return a.capture(s.pid);},false))error(Code::capture_failed);
   return s; };
 for(unsigned i=0;i<budget;++i){auto s=inspect();
   if(s.state==State::running&&permit(Action::stop)&&!call([&]{return a.stop();},false))error(Code::stop_failed);
   if(s.state==State::stopped&&call([&]{return a.has_root()&&a.root_exited();},false))break;
   call([&]{a.pause();return true;},false);
 }
 // Retained objects are independent: an invalid root never suppresses helper cleanup.
 if(call([&]{return a.has_root();},false)&&!call([&]{return a.root_exited();},false)){
   if(!call([&]{return a.valid_root();},false))error(Code::ownership_unknown);
   else if(permit(Action::terminate_root)&&!call([&]{return a.terminate_root();},false))error(Code::terminate_failed);
 }
 unsigned n=call([&]{return a.helpers();},0u);
 for(unsigned h=0;h<n;++h)if(!call([&]{return a.helper_exited(h);},false)){
   if(!call([&]{return a.valid_helper(h);},false))error(Code::ownership_unknown);
   else if(permit(Action::terminate_helper,h)&&!call([&]{return a.terminate_helper(h);},false))error(Code::terminate_failed);
 }
 bool exited=false;Status last;
 for(unsigned i=0;i<budget;++i){last=inspect();
   exited=call([&]{return a.has_root()?a.root_exited():!a.start_attempted();},false);
   for(unsigned h=0;h<n;++h) if(!call([&]{return a.helper_exited(h);},false))exited=false;
   if(exited&&last.state==State::stopped)break;
   call([&]{a.pause();return true;},false);
 }
 if(!exited){error(call([&]{return a.has_root();},false)?Code::exit_unknown:Code::ownership_unknown);return r;}
 if(last.state!=State::stopped){error(Code::inspection_unknown);return r;}
 r.quiesced=true;
 if(!remove_registration)return r;
 if(permit(Action::remove)){
   r.removed=call([&]{return a.remove_and_verify_absence();},false);
   if(!r.removed)error(Code::absence_unknown);
 }
 return r;
}
}
