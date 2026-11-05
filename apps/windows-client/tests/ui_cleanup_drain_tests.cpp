#include "orangespace/ui_lifecycle.hpp"
#include <cstdlib>
#include <new>
#include <cstdio>
#include <memory>
static long fail=-1;
static bool sticky=true;
void* operator new(std::size_t n) {
  if(fail==0) {if(!sticky)fail=-1;throw std::bad_alloc();}
  if(fail>0)--fail;
  if(auto p=std::malloc(n?n:1))return p;
  throw std::bad_alloc();
}
void operator delete(void* p) noexcept {std::free(p);}
void operator delete(void* p,std::size_t) noexcept {std::free(p);}
#define CHECK(x) do {if(!(x)){fail=-1;std::fprintf(stderr,"FAIL %s:%d %s\n",__FILE__,__LINE__,#x);return 1;}}while(0)
int main(int argc,char**) {
 using D=orangespace::ui_lifecycle::Drain<std::shared_ptr<int>>;
 // Both pre-dispatch node allocations may fail; rollback must leave no phantom ticket.
 for(bool persistent:{false,true})for(int n=0;n<3;++n){
  D d;sticky=persistent;fail=n;std::optional<D::Ticket> t;
  try{t=d.begin();}catch(const std::bad_alloc&){}
  if(t){d.finish(*t);}d.close();CHECK(d.ready());fail=-1;
 }
 if(argc==1) {
  for(bool persistent:{false,true})for(int n=0;n<8;++n){
   D d;auto owner=std::make_shared<int>(17);auto t=*d.begin();d.close();sticky=persistent;fail=n;
   bool threw=false;try{d.finish(t,owner);}catch(...){threw=true;}
   CHECK(!threw);CHECK(!d.ready());fail=-1;
   int calls=0;d.retry([&](const auto& p){if(*p!=17)std::abort();++calls;return true;});
   CHECK(calls==1 && d.ready());
  }
  std::puts("finish exact owner persistent/transient sweep PASS");
 } else {
  for(bool persistent:{false,true})for(int n=0;n<8;++n){
   D d;auto owner=std::make_shared<int>(23);auto t=*d.begin();d.finish(t,owner);d.close();sticky=persistent;fail=n;
   bool threw=false;try{d.retry([](const auto&){return false;});}catch(...){threw=true;}
   CHECK(!d.ready());fail=-1;
   int calls=0;d.retry([&](const auto& p){if(*p!=23)std::abort();++calls;return true;});
   CHECK(calls==1 && d.ready());CHECK(!threw);
  }
  std::puts("retry allocation failure retains owner and unlatches cleaning PASS");
 }
}
