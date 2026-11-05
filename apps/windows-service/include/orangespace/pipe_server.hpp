#pragma once
#include "orangespace/windows_service.hpp"
#include "orangespace/chain_response.hpp"
namespace orangespace::service::win {
using OwnedChainHandler=std::function<chain::Response(std::span<const std::uint8_t>)>;
bool serve_owned_connection(HANDLE,const Peer&,HANDLE,const OwnedChainHandler&);
}
