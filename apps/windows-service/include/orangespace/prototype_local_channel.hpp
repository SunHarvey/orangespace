#pragma once
// Trusted Service-only ownership. Not an OSP DTO or browser authorization.
#include "orangespace/service_chain.hpp"
#include "orangespace/platform_session.hpp"
#include <array>
namespace orangespace::service::win {
struct LocalChannel {
  chain::Binding binding;
  chain::LeaseBudget budget;
  std::uint16_t port{};
  platform_session::SerializedSecret username, password;
  std::int64_t proof_observed_at_ms{};
  LocalChannel(chain::Binding b, chain::LeaseBudget grant, std::uint16_t p,
      std::string_view u, std::string_view secret, std::int64_t proof)
      : binding(std::move(b)), budget(std::move(grant)), port(p),
        username(u), password(secret), proof_observed_at_ms(proof) {}
  LocalChannel(const LocalChannel&)=delete;
  LocalChannel& operator=(const LocalChannel&)=delete;
  LocalChannel(LocalChannel&&) noexcept=default;
  LocalChannel& operator=(LocalChannel&&) noexcept=default;
};
struct LocalChannelBuffer {
  std::array<std::uint8_t,4096> bytes{};
  ~LocalChannelBuffer() { chain::nd::wipe(bytes.data(),bytes.size()); }
  LocalChannelBuffer()=default;
  LocalChannelBuffer(const LocalChannelBuffer&)=delete;
  LocalChannelBuffer& operator=(const LocalChannelBuffer&)=delete;
};
inline LocalChannel decode_local_channel(std::string_view input,const chain::Binding& expected,
    const chain::LeaseBudget& original,std::int64_t received) {
  namespace nd=chain::nd;
  nd::require(!input.empty() && input.size()<=4096 && nd::safe_utf8(input));
  original.validate(received);
  nd::exact_wire_integers(input);
  nd::JsonGuard document(input);
  const auto& root=document.value;
  nd::object(root,11);
  nd::require(nd::integer(nd::field(root,"schema"))==2);
  nd::require(chain::parse_binding(nd::field(root,"binding"))==expected);
  nd::require(nd::text(nd::field(root,"host"))=="127.0.0.1");
  nd::require(nd::text(nd::field(root,"clock"))==original.clock);
  nd::require(nd::integer(nd::field(root,"request_started_ms"),0)==original.request_started_ms &&
    nd::integer(nd::field(root,"remaining_ttl_ms"))==original.remaining_ttl_ms &&
    nd::integer(nd::field(root,"deadline_ms"))==original.deadline_ms);
  const auto port=nd::integer(nd::field(root,"port"));nd::require(port<=65535);
  const auto proof=nd::integer(nd::field(root,"proof_observed_at_ms"),0);
  nd::require(proof>=original.request_started_ms && proof<=received && received-proof<3000);
  const auto& user=nd::text(nd::field(root,"username"));
  const auto& password=nd::text(nd::field(root,"password"));
  for(const auto value:{std::string_view(user),std::string_view(password)}) {
    nd::require(value.size()>=16 && value.size()<=255);
    for(unsigned char c:value)nd::require(c>=33 && c<=126);
  }
  return LocalChannel(expected,original,static_cast<std::uint16_t>(port),user,password,proof);
}
// Only the explicit prototype factory returns this capability. The caller must
// first complete Engine.start + ACK adoption and retain exact provisional cleanup.
// Failure after consumption is terminal: close/revoke outside the runtime IO lock.
struct PrototypePlatformBackend : chain::Backend {
  virtual LocalChannel take_local_channel(std::string_view realm,const chain::Binding&)=0;
};
}
