// Portable injected caller-policy test, NOT RPC/HTTPS/native login evidence.
#include "orangespace/ui_lifecycle.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <new>
#include <string_view>
#include <type_traits>

static bool fail_allocations=false;
static unsigned rejected_allocations=0;
void* operator new(std::size_t n) {
  if(fail_allocations) {++rejected_allocations;throw std::bad_alloc();}
  if(auto p=std::malloc(n ? n : 1))return p;
  throw std::bad_alloc();
}
void* operator new[](std::size_t n) {return ::operator new(n);}
void operator delete(void* p) noexcept {std::free(p);}
void operator delete[](void* p) noexcept {std::free(p);}
void operator delete(void* p,std::size_t) noexcept {std::free(p);}
void operator delete[](void* p,std::size_t) noexcept {std::free(p);}
namespace node_session {struct NodeSession {};}
namespace orangespace::service::chain {
/*BINDING_DECLARATION*/
/*CURSOR_DECLARATION*/
}
namespace sc {
namespace chain=orangespace::service::chain;
// Exact production declaration extracted by runner; private constructor intact.
/*GRANT_DECLARATION*/
static unsigned authorized=0,retired=0;
static bool cancel_at_return=false;
static bool* cancellation=nullptr;
Grant authorize(std::string_view,const node_session::NodeSession&) {
  Grant result(std::string(72,'g'),std::string(72,'u'),std::string(72,'n'));
  ++authorized;
  if(cancel_at_return)*cancellation=true;
  fail_allocations=true; // Sticky through caller catch, retention and cleanup.
  return result;
}
void retire(const Grant& grant) {
  assert(grant.id()==std::string_view("gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"));
  assert(grant.user().size()==72 && grant.node().size()==72);
  ++retired;
}
static bool new_binding_live=false;
static unsigned new_binding_stops=0;
chain::Binding start_tunnel(const Grant&,std::optional<chain::Cursor>) {
  chain::Binding result{std::string(72,'u'),std::string(72,'s'),std::string(72,'n'),std::string(72,'t'),42};
  new_binding_live=true;
  if(cancel_at_return)*cancellation=true;
  fail_allocations=true;
  return result;
}
chain::Cursor sandbox_cursor(const Grant&,std::string_view) {throw std::bad_alloc();}
void stop_retained(const Grant& grant,const chain::Binding& binding) {
  assert(grant.id().size()==72);
  if(binding.generation==42) {
    assert(binding.user==std::string_view("uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu"));
    assert(binding.sandbox==std::string_view("ssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss"));
    assert(binding.node==std::string_view("nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn"));
    assert(binding.tunnel==std::string_view("tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"));
    assert(new_binding_live);new_binding_live=false;++new_binding_stops;
  } else assert(binding.generation==41);
}
}
static_assert(!std::is_default_constructible_v<sc::Grant>);
static_assert(!std::is_move_assignable_v<sc::Grant>);
static_assert(std::is_nothrow_move_constructible_v<sc::Grant>);
static_assert(std::is_nothrow_move_assignable_v<sc::chain::Binding>);
static_assert(noexcept(std::declval<orangespace::ui_lifecycle::SharedReturnSlot<sc::Grant>&&>()
                      .adopt(std::declval<sc::Grant&&>())));
struct Mailbox {bool cancelled=false;};
enum class Job {tunnel};
struct Operation {std::int64_t expiry=100;};
/*LEASE_DECLARATION*/
struct Completion {
  std::shared_ptr<sc::Grant> grant;node_session::NodeSession* session=nullptr;bool failed=false;
  Job job{};Operation operation;std::string local_sandbox;
  std::shared_ptr<TunnelLease> tunnel;
  std::optional<sc::chain::Cursor> cursor;
};
static std::int64_t now() {return 1;}
static void tunnel_caller(Completion& out,Mailbox& box,const std::shared_ptr<sc::Grant>& grant,
                          const std::string& local,Operation op,std::optional<sc::chain::Cursor> cursor,
                          std::shared_ptr<TunnelLease> old) {
/*TUNNEL_CALLER*/
}
static void authorize_caller(Completion& out,Mailbox& box) {
  struct {std::string_view alias="fixture-policy-only";} ticket;
/*AUTHORIZE_CALLER*/
  if(box.cancelled)out.failed=true;
}
static bool grant_case(bool cancel,bool old_control) {
  node_session::NodeSession unused;
  Completion out;out.session=&unused;Mailbox box;
  sc::cancel_at_return=cancel;sc::cancellation=&box.cancelled;
  const auto before=sc::authorized,cleanup=sc::retired;
  rejected_allocations=0;
  bool threw=false;
  try {
    if(old_control)out.grant=std::make_shared<sc::Grant>(sc::authorize("policy",unused));
    else authorize_caller(out,box);
  } catch(const std::bad_alloc&) {threw=true;out.failed=true;}
  assert(fail_allocations && sc::authorized==before+1);
  if(old_control) {
    const bool reproduced=threw && !out.grant && rejected_allocations>0;
    fail_allocations=false;
    return reproduced;
  }
  const bool retained=!threw && out.grant && rejected_allocations==0 && out.failed==cancel;
  if(out.grant) {sc::retire(*out.grant);out.grant.reset();}
  const bool cleaned=sc::retired==cleanup+1;
  fail_allocations=false;
  return retained && cleaned;
}
static bool tunnel_case(bool cancel,bool old_control) {
  // Allocate all fixture inputs BEFORE the injected successful return seam.
  node_session::NodeSession unused;
  orangespace::ui_lifecycle::SharedReturnSlot<sc::Grant> slot;
  sc::cancel_at_return=false;
  auto grant=std::move(slot).adopt(sc::authorize("policy",unused));
  fail_allocations=false;
  auto old=std::make_shared<TunnelLease>();old->grant=grant;old->binding.generation=41;
  std::weak_ptr<TunnelLease> prior=old;
  std::string local(72,'l');
  std::optional<sc::chain::Cursor> cursor=sc::chain::Cursor{std::string(72,'s'),41};
  Completion out;Mailbox box;
  sc::cancel_at_return=cancel;sc::cancellation=&box.cancelled;
  const auto stopped=sc::new_binding_stops;
  rejected_allocations=0;
  bool threw=false;
  try {
    if(old_control) {
      out.tunnel=old;
      auto lease=std::make_shared<TunnelLease>();lease->grant=grant;lease->local=local;
      lease->binding=sc::start_tunnel(*grant,cursor);
      old.reset();
      out.cursor=sc::chain::Cursor{lease->binding.sandbox,lease->binding.generation};
      out.tunnel=std::move(lease);
    } else tunnel_caller(out,box,grant,local,Operation{},cursor,std::move(old));
  } catch(const std::bad_alloc&) {threw=true;out.failed=true;}
  assert(fail_allocations && threw && rejected_allocations>0 && !out.cursor && sc::new_binding_live);
  assert(box.cancelled==cancel);
  const bool retained=out.tunnel && out.tunnel->binding.generation==42 && out.tunnel->grant==grant && out.tunnel->local==local;
  if(out.tunnel)sc::stop_retained(*out.tunnel->grant,out.tunnel->binding);
  out.tunnel.reset();
  const bool cleaned=!sc::new_binding_live && sc::new_binding_stops==stopped+1;
  const bool prior_released=prior.expired();
  sc::retire(*grant);grant.reset(); // Exact grant cleanup remains allocation-free.
  fail_allocations=false;
  return old_control ? !retained && !cleaned : retained && cleaned && prior_released;
}
static bool preallocation_failure_case() {
  node_session::NodeSession unused;
  Completion out;out.session=&unused;Mailbox box;
  const auto before=sc::authorized;
  fail_allocations=true;
  bool threw=false;
  try {authorize_caller(out,box);}catch(const std::bad_alloc&) {threw=true;}
  const bool safe=threw && !out.grant && sc::authorized==before;
  fail_allocations=false;
  return safe;
}
int main() {
  assert(preallocation_failure_case());
  std::puts("PASS preallocation failure: authorize seam never reached");
  assert(grant_case(false,true));
  std::puts("PASS positive control: OLD grant order loses acknowledged owner under sticky allocation failure");
  if(!grant_case(false,false)) {std::puts("FAIL grant retention: acknowledged Grant missing after postreturn allocation failure");return 1;}
  if(!grant_case(true,false)) {std::puts("FAIL cancelled grant: exact retained Grant not retired");return 1;}
  std::puts("PASS extracted authorize caller: retained and retired exact Grant, including cancellation, zero postreturn allocation attempts");
  assert(tunnel_case(false,true));
  std::puts("PASS positive control: OLD cursor-before-owner order loses acknowledged binding");
  if(!tunnel_case(false,false)) {std::puts("FAIL tunnel retention: cursor-copy exception loses new binding or cleans wrong generation");return 2;}
  if(!tunnel_case(true,false)) {std::puts("FAIL cancelled tunnel: exact new binding not retained/cleaned after cursor-copy exception");return 2;}
  std::puts("PASS extracted tunnel caller: exact new binding retained/stopped and prior owner released on cursor-copy exception, including cancellation");
}
