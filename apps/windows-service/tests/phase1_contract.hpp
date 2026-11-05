#pragma once
#include "orangespace/node_session.hpp"
#include <array>
#include <algorithm>
namespace phase1 {
// Fixed-capacity ownership: secrets never use std::string SSO or allocate.
// In particular an exception constructing a later member cannot bypass wiping
// an earlier member, and moving always clears the complete source storage.
class BootstrapSecret {
 std::array<char,257> bytes_{};
 std::size_t size_=0;
 void clear() noexcept {orangespace::node_session::detail::wipe(bytes_.data(),bytes_.size());size_=0;}
 public:
 BootstrapSecret()=default;
 BootstrapSecret(const BootstrapSecret&)=delete;
 BootstrapSecret& operator=(const BootstrapSecret&)=delete;
 BootstrapSecret(BootstrapSecret&& other) noexcept:bytes_(other.bytes_),size_(other.size_){other.clear();}
 BootstrapSecret& operator=(BootstrapSecret&& other) noexcept {
  if(this!=&other){clear();bytes_=other.bytes_;size_=other.size_;other.clear();}return *this;
 }
 BootstrapSecret& operator=(std::string_view value){
  orangespace::node_session::detail::require(!value.empty()&&value.size()<=256&&orangespace::node_session::detail::safe_utf8(value,true));
  clear();std::copy(value.begin(),value.end(),bytes_.begin());size_=value.size();return *this;
 }
 ~BootstrapSecret(){clear();}
 char* data() noexcept{return bytes_.data();}
 const char* data() const noexcept{return bytes_.data();}
 std::size_t size() const noexcept{return size_;}
 bool empty() const noexcept{return size_==0;}
 operator std::string_view() const noexcept{return {data(),size()};}
};
struct Bootstrap {
 std::string alias_a,alias_b;
 BootstrapSecret username_a,password_a,username_b,password_b;
 unsigned expiry_budget_seconds=0,renew_seconds=0;
 Bootstrap()=default;
 Bootstrap(const Bootstrap&)=delete;
 Bootstrap& operator=(const Bootstrap&)=delete;
 Bootstrap(Bootstrap&&) noexcept=default;
 Bootstrap& operator=(Bootstrap&&) noexcept=default;
};
inline Bootstrap parse_bootstrap(std::string_view input) {
 namespace nd=orangespace::node_session::detail;
 nd::require(input.size()<=32768 && nd::safe_utf8(input));
 nd::JsonGuard doc(input); nd::object(doc.value,9);
 nd::require(nd::integer(nd::field(doc.value,"schema"))==1);
 Bootstrap b;
 b.alias_a=nd::text(nd::field(doc.value,"alias_a")); b.alias_b=nd::text(nd::field(doc.value,"alias_b"));
 for(const auto*p:{&b.alias_a,&b.alias_b}) {nd::require(!p->empty()&&p->size()<=64);for(char c:*p)nd::require((c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='_'||c=='-');}
 nd::require(b.alias_a!=b.alias_b);
 b.username_a=nd::text(nd::field(doc.value,"username_a"));b.password_a=nd::text(nd::field(doc.value,"password_a"));
 b.username_b=nd::text(nd::field(doc.value,"username_b"));b.password_b=nd::text(nd::field(doc.value,"password_b"));
 for(const auto*p:{&b.username_a,&b.password_a,&b.username_b,&b.password_b}) nd::require(!p->empty()&&p->size()<=256&&nd::safe_utf8(*p,true));
 const auto expiry=nd::integer(nd::field(doc.value,"expiry_budget_seconds"));
 const auto renew=nd::integer(nd::field(doc.value,"renew_seconds"));
 nd::require(expiry<=240&&expiry>=35&&renew>=35&&renew<=60);
 b.expiry_budget_seconds=static_cast<unsigned>(expiry);b.renew_seconds=static_cast<unsigned>(renew);
 return b;
}
}
