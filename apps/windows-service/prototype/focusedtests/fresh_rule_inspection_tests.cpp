// Actual production scheduler, deterministic capture barriers; no Windows claim.
#include "fresh_rule_inspection.hpp"
#include <cassert>
#include <chrono>
#include <future>
#include <iostream>
#include <memory>
using namespace std::chrono_literals;
namespace p=orangespace::prototype;
namespace orangespace::prototype {
struct FreshRuleInspectionTestAccess {
 static auto issue(FreshRuleInspection&s){std::lock_guard l(s.mutex_);auto seq=s.issue_locked();s.cv_.notify_all();return seq;}
 static auto wait(FreshRuleInspection&s,std::uint64_t seq){std::unique_lock l(s.mutex_);return s.wait_locked(l,seq);}
 static void exhaust(FreshRuleInspection&s){std::lock_guard l(s.mutex_);s.requested_=UINT64_MAX;}
};
}
using Access=p::FreshRuleInspectionTestAccess;
struct Capture {
 std::mutex mutex;std::condition_variable cv;unsigned calls=0,released=0;bool fail=false;
 p::FreshRuleInspection::Digest operator()(){std::unique_lock l(mutex);auto n=++calls;cv.notify_all();assert(cv.wait_for(l,2s,[&]{return released>=n;}));if(fail)throw std::runtime_error("capture");p::FreshRuleInspection::Digest d{};d[0]=static_cast<unsigned char>(n);return d;}
 void started(unsigned n){std::unique_lock l(mutex);assert(cv.wait_for(l,2s,[&]{return calls>=n;}));}
 void release(unsigned n){std::lock_guard l(mutex);released=n;cv.notify_all();}
};
int main(){
 {Capture c;p::FreshRuleInspection s([&]{return c();});
  auto first=Access::issue(s);c.started(1);
  auto second=Access::issue(s),third=Access::issue(s); // both registered before capture 2
  auto waiting=std::async(std::launch::async,[&]{return Access::wait(s,second);});
  c.release(1);c.started(2);
  assert(waiting.wait_for(20ms)==std::future_status::timeout); // midcapture cannot consume 1
  assert(Access::wait(s,first)[0]==1);
  c.release(2);assert(waiting.get()[0]==2);assert(Access::wait(s,third)[0]==2);
  auto ack=std::async(std::launch::async,[&]{return s.snapshot();});c.started(3);
  assert(ack.wait_for(20ms)==std::future_status::timeout); // later ACK cannot reuse offer
  c.release(3);assert(ack.get()[0]==3);assert(c.calls==3);
 }
 {Capture c;p::FreshRuleInspection s([&]{return c();});auto a=Access::issue(s);c.started(1);auto b=Access::issue(s);{std::lock_guard l(c.mutex);c.fail=true;}c.release(1);
  for(auto seq:{a,b}){bool failed=false;try{(void)Access::wait(s,seq);}catch(...){failed=true;}assert(failed);}
  bool failed=false;try{(void)s.snapshot();}catch(...){failed=true;}assert(failed&&c.calls==1);
 }
 {Capture c;p::FreshRuleInspection s([&]{return c();});auto a=Access::issue(s);c.started(1);auto b=Access::issue(s);
  s.stop();for(auto seq:{a,b}){bool failed=false;try{(void)Access::wait(s,seq);}catch(...){failed=true;}assert(failed);}c.release(1);
 }
 { // A stored success is not authority after stop (including future callers).
  p::FreshRuleInspection s([]{p::FreshRuleInspection::Digest d{};d[0]=7;return d;});assert(s.snapshot()[0]==7);s.stop();
  bool failed=false;try{(void)s.snapshot();}catch(...){failed=true;}assert(failed);
 }
 { // Destructor joins the actual in-flight capture before captured state dies.
  Capture c;auto s=std::make_unique<p::FreshRuleInspection>([&]{return c();});Access::issue(*s);c.started(1);
  auto destruction=std::async(std::launch::async,[&]{s.reset();});
  assert(destruction.wait_for(20ms)==std::future_status::timeout);c.release(1);destruction.get();
 }
 {p::FreshRuleInspection s([]{return p::FreshRuleInspection::Digest{};});Access::exhaust(s);bool failed=false;try{(void)s.snapshot();}catch(...){failed=true;}assert(failed);}
 std::cout<<"fresh capture batching, midcapture/later-phase freshness, latched failure, stop, overflow passed\n";
}
