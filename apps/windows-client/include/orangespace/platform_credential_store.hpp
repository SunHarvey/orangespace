#pragma once
#include "orangespace/platform_session.hpp"
#include <algorithm>
#include <optional>

namespace orangespace::platform_session {
namespace credential_detail {
inline constexpr std::wstring_view directory_name = L"OrangeSpace-Platform-Credentials-v1";
// Revalidate the protected config's exact origin, preserving explicit :443.
inline Bootstrap validate_origin(std::string_view value) {
  node_session::detail::require(value.size() <= 300 && value.find_first_of("\"\\\r\n\t") == std::string_view::npos);
  return detail::validate_bootstrap("{\"schema\":1,\"api_origin\":\"" + std::string(value) + "\"}");
}
inline bool storage_id(std::string_view value) {
  return value.size() == 64 && std::all_of(value.begin(), value.end(), [](char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
  });
}
inline std::string entropy(std::string_view sid, std::string_view api_origin) {
  namespace nd = node_session::detail;
  nd::require(!sid.empty() && sid.size() <= 184 && sid.starts_with("S-1-"));
  for (char c : sid) nd::require((c >= '0' && c <= '9') || c == '-' || c == 'S');
  (void)validate_origin(api_origin);
  std::string result("OrangeSpace/PlatformCredentialStore/v1/central-session");
  result.push_back('\0'); result += sid;
  result.push_back('\0'); result += api_origin;
  return result;
}
// The stored item is a session renewal (Session::export_renewal), never an
// access credential. Parsing here is a persistence admission check, never
// authentication: load signs in again through Session::resume.
inline void validate_renewal(std::string_view api_origin, std::string_view input, std::int64_t now) {
  namespace nd = node_session::detail;
  (void)validate_origin(api_origin);
  nd::require(!input.empty() && input.size() <= 16384 && nd::safe_utf8(input));
  nd::exact_wire_integers(input);
  nd::JsonGuard doc(input); nd::object(doc.value, 11);
  nd::require(nd::integer(nd::field(doc.value, "schema")) == 1);
  nd::require(nd::text(nd::field(doc.value, "namespace")) == "orangespace.platform.renewal");
  nd::require(nd::text(nd::field(doc.value, "api_origin")) == api_origin);
  nd::require(nd::uuid(nd::text(nd::field(doc.value, "central_user_id"))) &&
              nd::uuid(nd::text(nd::field(doc.value, "central_session_id"))));
  (void)nd::text(nd::field(doc.value, "username")); (void)nd::text(nd::field(doc.value, "role"));
  (void)nd::integer(nd::field(doc.value, "user_epoch"));
  const auto deadline = nd::integer(nd::field(doc.value, "session_deadline"));
  const auto expiry = nd::integer(nd::field(doc.value, "refresh_expires_at"));
  nd::require(deadline > now && expiry > now && expiry <= deadline);
  nd::validate_token(nd::text(nd::field(doc.value, "refresh_token")));
}
} // namespace credential_detail

// Interactive current-user DPAPI only, fixed product root and SHA-256(origin)
// storage key. No arbitrary path, caller SID, node ID or LocalMachine option.
// A failed erase is NOT completed logout: preserve/retry its pending marker.
//
// Remember-login: save stores the session's current renewal (replace it after
// every refresh: only the latest works). load returns nothing when nothing is
// saved; otherwise it signs in again through Session::resume and saves the new
// renewal before returning. A saved item that is invalid, expired or refused by
// the Centre (HTTP 401/403) is erased; a network or server failure keeps it for
// the next attempt and throws SavedSignInKept.
class SavedSignInKept final : public std::runtime_error {
 public:
  SavedSignInKept() : std::runtime_error("the Centre could not be reached; the saved sign-in is kept") {}
};
class CredentialStore {
 public:
  static void save(const PlatformConfig&, const Session&);
  static std::optional<Session> load(const PlatformConfig&);
  static std::optional<Session> load(const PlatformConfig&, Transport&, std::function<std::int64_t()> clock);
  static void erase(const PlatformConfig&);
};
} // namespace orangespace::platform_session
