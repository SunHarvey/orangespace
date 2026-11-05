#pragma once
#include "orangespace/service_chain.hpp"
#include "orangespace/prototype_local_channel.hpp"
namespace orangespace::service::win {
std::unique_ptr<chain::Backend> make_chain_backend();
std::unique_ptr<chain::Backend> make_platform_chain_backend();
std::unique_ptr<PrototypePlatformBackend> make_prototype_platform_chain_backend();
std::shared_ptr<chain::Namespace> make_chain_namespace();
std::shared_ptr<chain::Namespace> make_prototype_chain_namespace();
std::int64_t chain_now();
chain::Response dispatch_chain(chain::Engine&, const Peer&, std::span<const std::uint8_t>);
chain::Response dispatch_platform_chain(chain::Engine&, const Peer&, std::span<const std::uint8_t>);
}
