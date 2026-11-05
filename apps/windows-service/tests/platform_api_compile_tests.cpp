#include "orangespace/chain_windows.hpp"
#include "orangespace/service_client.hpp"
#include "orangespace/platform_session.hpp"
#include <type_traits>
using namespace orangespace;
static_assert(std::is_same_v<decltype(service::win::make_platform_chain_backend()),std::unique_ptr<service::chain::Backend>>);
static_assert(std::is_same_v<decltype(service_client::authorize_platform(std::declval<const platform_session::Session&>(),std::declval<const platform_session::NodeRef&>())),service_client::Grant>);
static_assert(std::is_same_v<decltype(service_client::register_sandbox(std::declval<const service_client::Grant&>(),std::string_view{})),service::chain::Cursor>);
static_assert(std::is_same_v<decltype(service_client::start_registered_tunnel(std::declval<const service_client::Grant&>(),std::string_view{})),service::chain::Binding>);
int main(){return 0;}
