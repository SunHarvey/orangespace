#pragma once
#include "orangespace/platform_session.hpp"
#include <algorithm>

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
// Central's eight-field envelope is NOT the legacy node envelope. Parsing here
// is a persistence admission check, never authentication. load calls restore.
inline void validate_envelope(std::string_view api_origin, std::string_view input, std::int64_t now) {
  namespace nd = node_session::detail;
  (void)validate_origin(api_origin);
  nd::require(!input.empty() && input.size() <= 16384 && nd::safe_utf8(input));
  nd::exact_wire_integers(input);
  nd::JsonGuard doc(input); nd::object(doc.value, 8);
  nd::require(nd::integer(nd::field(doc.value, "schema")) == 1);
  nd::require(nd::text(nd::field(doc.value, "namespace")) == "orangespace.platform.session");
  nd::require(nd::text(nd::field(doc.value, "api_origin")) == api_origin);
  nd::require(nd::uuid(nd::text(nd::field(doc.value, "central_user_id"))) &&
              nd::uuid(nd::text(nd::field(doc.value, "central_session_id"))));
  (void)nd::integer(nd::field(doc.value, "user_epoch"));
  nd::require(nd::integer(nd::field(doc.value, "expires_at")) > now);
  nd::validate_token(nd::text(nd::field(doc.value, "access_token")));
}
} // namespace credential_detail

// Interactive current-user DPAPI only, fixed product root and SHA-256(origin)
// storage key. No arbitrary path, caller SID, node ID or LocalMachine option.
// A failed erase is NOT completed logout: preserve/retry its pending marker.
class CredentialStore {
 public:
  static void save(const PlatformConfig&, const Session&);
  // Decryption alone never signs in: restore performs real central revalidation.
  static Session load(const PlatformConfig&);
  static void erase(const PlatformConfig&);
};
} // namespace orangespace::platform_session
