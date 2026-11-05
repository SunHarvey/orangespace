#include "orangespace/service_chain.hpp"
#include "orangespace_runtime.h"
#include <set>
#include <cstdlib>
#include <new>
#include <iostream>
using namespace orangespace::service::chain;
static bool fail_allocations=false;
void* operator new(std::size_t n) {if(fail_allocations)throw std::bad_alloc();if(auto p=std::malloc(n?n:1))return p;throw std::bad_alloc();}
void operator delete(void* p) noexcept {std::free(p);}
void operator delete(void* p,std::size_t) noexcept {std::free(p);}
#include "release_under_test.hpp"
void require(bool ok){if(!ok)std::abort();}
int main(){
  ReleaseUnderTest backend;
  const std::string a="11111111-1111-4111-8111-111111111111",b="22222222-2222-4222-8222-222222222222";
  auto old=std::make_shared<ReleaseUnderTest::Realm>(),other=std::make_shared<ReleaseUnderTest::Realm>();
  constexpr std::string_view helper="/usr/bin/true";
  old->runtime=os_runtime_new(reinterpret_cast<const uint8_t*>(helper.data()),helper.size(),1000);
  other->runtime=os_runtime_new(reinterpret_cast<const uint8_t*>(helper.data()),helper.size(),1000);
  require(old->runtime && other->runtime);
  auto token=old->runtime;
  backend.realms_.emplace(a,old);backend.realms_.emplace(b,other);
  fail_allocations=true;
  backend.release(a);backend.release(a);backend.release("33333333-3333-4333-8333-333333333333");
  fail_allocations=false;
  require(old->retired && !old->runtime && !other->retired && other->runtime && backend.realms_.size()==1);
  constexpr std::string_view poll=R"({"schema":2,"op":"poll"})";
  std::array<uint8_t,65536> out{};
  require(os_runtime_call(token,reinterpret_cast<const uint8_t*>(poll.data()),poll.size(),out.data(),out.size())==OS_RUNTIME_ERROR_HANDLE);
  require(os_runtime_call(other->runtime,reinterpret_cast<const uint8_t*>(poll.data()),poll.size(),out.data(),out.size())>0);
  fail_allocations=true;backend.release(b);fail_allocations=false;
  require(other->retired && !other->runtime && backend.realms_.empty());
  std::cout<<"PASS exact production release body: persistent C++ OOM, same shared object invalidated, foreign realm preserved; real Linux Rust handles freed (no helper launch / Windows claim)\n";
}
