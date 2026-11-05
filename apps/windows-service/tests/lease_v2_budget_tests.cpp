// Portable production-budget/owned-result regression; NOT WinHTTP/Windows acceptance.
#include <cstdlib>
#include <new>
#include <cstring>
static void* last_allocation{};
static void* watched{};
static std::size_t watched_size{};
static bool saw_release{}, wiped{};
void* operator new(std::size_t n) {
  if (auto p=std::malloc(n?n:1)) {last_allocation=p;return p;}
  throw std::bad_alloc();
}
void operator delete(void* p) noexcept {
  if(p && p==watched) {
    saw_release=true;wiped=true;
    for(std::size_t i=0;i<watched_size;++i)if(static_cast<unsigned char*>(p)[i])wiped=false;
    watched=nullptr;
  }
  std::free(p);
}
void operator delete(void* p,std::size_t) noexcept {::operator delete(p);}
#include "orangespace/service_chain.hpp"
#include <iostream>
#include <type_traits>
using namespace orangespace::service::chain;
static_assert(!std::is_copy_constructible_v<LeaseResult>);
static_assert(!std::is_move_constructible_v<LeaseResult>);
static_assert(std::is_nothrow_destructible_v<LeaseResult>);
void check(bool condition,const char* message) {if(!condition)throw std::runtime_error(message);}
template<class F> void denies(F run) {bool rejected=false;try{run();}catch(...){rejected=true;}check(rejected,"expected budget denial");}
std::int64_t late_clock() {watched=last_allocation;watched_size=128;saw_release=false;throw 7;}
int main() {
  LeaseBudget budget{std::string(nd::lease_clock),100000,29000,129000};
  budget.validate(100000);budget.validate(128999);
  denies([&]{budget.validate(129000);});denies([&]{budget.validate(99999);});
  for(int test=0;test<12;++test) {
    auto bad=budget;
    switch(test) {
      case 0:bad.clock="opaque-origin";break;
      case 1:bad.clock=nd::lease_clock=="linux-clock-monotonic-ms-v1"?"windows-gettickcount64-ms-v1":"linux-clock-monotonic-ms-v1";break;
      case 2:bad.remaining_ttl_ms=0;break;
      case 3:bad.remaining_ttl_ms=-1;break;
      case 4:bad.remaining_ttl_ms=30001;break;
      case 5:bad.deadline_ms++;break;
      case 6:bad.request_started_ms=-1;break;
      case 7:bad.request_started_ms=100101;break;
      case 8:bad.deadline_ms=nd::max_exact_integer+1;break;
      case 9:bad.request_started_ms=nd::max_exact_integer;bad.remaining_ttl_ms=1;break;
      case 10:bad.clock.clear();break;
      case 11:bad.deadline_ms=-1;break;
    }
    denies([&]{bad.validate(100100);});
  }
  LeaseBudget edge{std::string(nd::lease_clock),nd::max_exact_integer-1,1,nd::max_exact_integer};
  edge.validate(nd::max_exact_integer-1);
  denies([&]{edge.validate(nd::max_exact_integer);});
  const auto root=orangespace::json::parse(budget_json(budget));nd::object(root,4);
  check(nd::text(nd::field(root,"clock"))==nd::lease_clock && nd::integer(nd::field(root,"deadline_ms"))==129000,"exact four-field wire budget");
  Binding old{"u","s","n","t",1,1000,120000};
  RenewResult equal{1000,budget};check(renewed_deadline(old,equal,110000)==120000,"equal server expiry grants no extension");
  RenewResult newer{1002,budget};check(renewed_deadline(old,newer,110000)==122000,"server expiry delta caps extension");
  newer.expires_at=1010;check(renewed_deadline(old,newer,110000)==129000,"original new request deadline caps extension");
  newer.expires_at=999;denies([&]{(void)renewed_deadline(old,newer,110000);});
  denies([&]{(void)renewed_deadline(old,equal,120000);});
  newer.expires_at=nd::max_exact_integer;denies([&]{(void)renewed_deadline(old,newer,110000);});
  const auto before=nd::monotonic_ms();check(nd::monotonic_ms()>=before,"shared OS clock is monotonic");
  // Allocation observer positive control: an ordinary string is not wiped.
  {
    std::string control(128,'x');watched=control.data();watched_size=128;saw_release=false;
  }
  check(saw_release && !wiped,"allocation observer positive control");
  {
    LeaseResult result(std::string(128,'x'),budget,1000);
    watched=result.payload.data();watched_size=result.payload.size();saw_release=false;
  }
  check(saw_release && wiped,"owned secret result wipes payload on release");
  try {LeaseResult result(std::string(128,'x'),budget,1000,late_clock);check(false,"late constructor must fail");}catch(int){}
  check(saw_release && wiped,"completed guarded owner wipes when final clock check throws");
  std::cout<<"PASS v2 exact common-clock budgets, integer/renewal boundaries, and owned secret-result normal/exception wiping (portable policy only)\n";
}
