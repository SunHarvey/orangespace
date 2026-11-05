// Portable S6 ownership/fault tests. Does not exercise Win32 or HTTP.
#include "phase1_contract.hpp"
#include <cstdlib>
#include <cstddef>
#include <cstdio>
#include <new>
#include <cstring>
#include <type_traits>
namespace faults {
struct alignas(std::max_align_t) Header {std::size_t size;bool tracked;};
static bool active=false,dirty=false;
static std::size_t index=0,fail_at=0,live=0;
constexpr char marker[]="S6_unique_secret_bytes_";
}
void* operator new(std::size_t n){
 if(faults::active && ++faults::index==faults::fail_at)throw std::bad_alloc();
 auto*h=static_cast<faults::Header*>(std::malloc(sizeof(faults::Header)+n));if(!h)throw std::bad_alloc();
 h->size=n;h->tracked=faults::active;if(h->tracked)++faults::live;return h+1;
}
void operator delete(void*p)noexcept{
 if(!p)return;
 auto*h=static_cast<faults::Header*>(p)-1;
 if(h->tracked){
  --faults::live;const auto*b=static_cast<const char*>(p);
  for(std::size_t i=0;i+sizeof(faults::marker)-1<=h->size;++i)
   if(std::memcmp(b+i,faults::marker,sizeof(faults::marker)-1)==0)faults::dirty=true;
 }
 std::free(h);
}
void operator delete(void*p,std::size_t)noexcept{::operator delete(p);}
void* operator new[](std::size_t n){return ::operator new(n);}
void operator delete[](void*p)noexcept{::operator delete(p);}
void operator delete[](void*p,std::size_t)noexcept{::operator delete(p);}
void check(bool b){if(!b)throw 17;}
int main(){try{
 check(!std::is_copy_constructible_v<phase1::Bootstrap> && !std::is_copy_assignable_v<phase1::Bootstrap>);
 check(std::is_nothrow_move_constructible_v<phase1::Bootstrap> && std::is_nothrow_move_assignable_v<phase1::Bootstrap>);
 for(std::string_view text:{std::string_view("tiny"),std::string_view("S6_unique_secret_bytes_longer_than_any_SSO")}){
  phase1::BootstrapSecret source;source=text;phase1::BootstrapSecret moved(std::move(source));
  check(std::string_view(moved)==text && source.empty());
  for(std::size_t i=0;i<257;++i)check(source.data()[i]==0);
  phase1::BootstrapSecret assigned;assigned="old";assigned=std::move(moved);check(std::string_view(assigned)==text);
  for(std::size_t i=0;i<257;++i)check(moved.data()[i]==0);
  auto* same=&assigned;assigned=std::move(*same);check(std::string_view(assigned)==text);
  alignas(phase1::BootstrapSecret) unsigned char storage[sizeof(phase1::BootstrapSecret)]{};
  auto* object=new(storage)phase1::BootstrapSecret;*object=text;object->~BootstrapSecret();
  for(auto c:storage)check(c==0);
 }
 const std::string input=R"({"schema":1,"alias_a":"a","alias_b":"b","username_a":"S6_unique_secret_bytes_username_a","password_a":"S6_unique_secret_bytes_password_a","username_b":"S6_unique_secret_bytes_username_b","password_b":"S6_unique_secret_bytes_password_b","expiry_budget_seconds":180,"renew_seconds":35})";
 std::size_t total=0;
 faults::active=true;faults::fail_at=0;faults::index=0;
 {auto b=phase1::parse_bootstrap(input);auto moved=std::move(b);check(std::string_view(moved.password_a)=="S6_unique_secret_bytes_password_a");}
 faults::active=false;total=faults::index;check(total>0 && faults::live==0 && !faults::dirty);
 for(std::size_t i=1;i<=total;++i){
  faults::active=true;faults::fail_at=i;faults::index=0;bool failed=false;
  try{auto b=phase1::parse_bootstrap(input);(void)b;}catch(const std::bad_alloc&){failed=true;}
  faults::active=false;check(failed && faults::live==0 && !faults::dirty);
 }
 std::printf("S6 no-elide: move/source/destructor wipe; bad_alloc every allocation 1..%zu passed; no tracked leaks or heap secret marker at delete\n",total);
 return 0;
}catch(...){faults::active=false;std::puts("S6 fault tests FAILED");return 1;}}
