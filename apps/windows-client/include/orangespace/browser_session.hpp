#pragma once
#include "orangespace/service_client.hpp"
#include <cstdint>
#include <string>
#include <string_view>
namespace orangespace::browser_session {
// Existing OS-authenticated OSP3 channel, exact Grant + Binding. This is not a
// new authority or a BrowserPermit and cannot make missing kernel policy ready.
enum class Command : unsigned { status=0, navigate=1, back=2, forward=3, reload=4, close=5, station_configured=6 };
enum class Phase : unsigned { closed=0, awaiting_desktop=1, starting=2, running=3, failed=4 };
struct State {
 Phase phase{Phase::closed};
 std::string sandbox,node,package_sid,profile_name,url,title,error;
 std::uint64_t generation{},process_birth{};
 std::uint32_t process_id{};
 bool loading{},can_go_back{},can_go_forward{};
};
#ifdef _WIN32
// Never accepts service/pipe names, executable paths, credentials or ready flags.
// Non-status work must still match the live exact owner binding in Service.
State exchange(const service_client::Grant&,const service::chain::Binding&,
               Command command=Command::status,std::string_view url={});
#endif
}
