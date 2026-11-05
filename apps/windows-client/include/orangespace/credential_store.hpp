#pragma once
#include "orangespace/node_session.hpp"

namespace orangespace::node_session {
namespace credential_detail {
// `privileged` here means exclusively the current process SID or LocalSystem,
// not Administrators. No other principal may read even an encrypted credential.
inline bool secure_user_acl(bool owner, bool protected_dacl, bool present,
                            const std::vector<detail::Ace>& entries) {
  if (!owner || !protected_dacl || !present || entries.empty()) return false;
  for (const auto& ace : entries) {
    if (ace.kind == detail::AceKind::unsupported) return false;
    if (ace.kind == detail::AceKind::allow && !ace.privileged && ace.mask) return false;
  }
  return true;
}
inline std::string entropy(std::string_view sid, const detail::NodeEntry& node) {
  detail::require(!sid.empty() && sid.size() <= 184 && sid.starts_with("S-1-"));
  for (char c : sid) detail::require((c >= '0' && c <= '9') || c == '-' || c == 'S');
  std::string result("OrangeSpace/CredentialStore/v1/api-session");
  for (const auto& component : {std::string(sid), node.node_id, detail::api_origin(node)}) {
    result.push_back('\0'); result += component;
  }
  return result;
}
inline void require_no_pending(bool pending) {detail::require(!pending);}
// Caller holds the protected per-node cross-process lock for this transaction.
// A failed commit MUST NOT be reported as durable logout; subsequent failures
// retain the committed marker. Never clear until the exact blob is absent.
template<class Storage> void pending_erase(Storage& storage) {
  storage.commit();
  storage.remove_blob();
  storage.verify_absent();
  storage.clear();
}
} // namespace credential_detail

// UI current-user store only: refuses SYSTEM, service identities, session 0 and
// impersonation. No caller-supplied path/SID or LocalMachine mode. Store contents
// are never authentication authority: load reauthenticates against the catalog.
class CredentialStore {
 public:
  static void save(const TrustedCatalog& catalog, std::string_view alias, const NodeSession& session);
  static NodeSession load(const TrustedCatalog& catalog, std::string_view alias);
  // Write-ahead protected node intent precedes deletion; load/save refuse any
  // pending intent. Successful return verifies the exact blob and intent absent.
  // Exception means NOT COMPLETE (possibly NOT COMMITTED if persistence failed);
  // never infer durable logout from a failed call. Retry erase before saving a
  // fresh password login. Normal window close must not call erase.
  static void erase(const TrustedCatalog& catalog, std::string_view alias);
};
} // namespace orangespace::node_session
