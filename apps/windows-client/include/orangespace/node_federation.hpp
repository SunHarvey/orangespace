#pragma once
// Checks that bind a Centre node reference to the pinned node catalog and to
// the node's federation exchange. Every check is exact: a node, user, mapping,
// grant or epoch that differs from what the Centre listed is refused.
#include "orangespace/node_session.hpp"
#include "orangespace/platform_session.hpp"

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>

namespace orangespace::node_federation {
namespace nd = node_session::detail;
using platform_session::NodeRef;

// JSON string literal for request bodies built by hand.
inline std::string quote(std::string_view input) {
  std::string out = "\"";
  constexpr char hex[] = "0123456789abcdef";
  for (unsigned char c : input) {
    if (c == '"' || c == '\\') {
      out += '\\';
      out += static_cast<char>(c);
    } else if (c < 32) {
      out += "\\u00";
      out += hex[c >> 4];
      out += hex[c & 15];
    } else {
      out += static_cast<char>(c);
    }
  }
  return out + '"';
}

// The node the Centre listed is the one this computer pins (id, TLS name, origin).
inline void match_catalog(const NodeRef& n, const nd::NodeEntry& pin) {
  nd::require(n.node_id == pin.node_id && n.tls_server_name == pin.host);
  // The static schema-1 catalog pins HTTPS host, port and node, not signing fingerprints.
  const auto explicit_origin = nd::api_origin(pin);
  const auto default_origin = "https://" + pin.host + pin.api_prefix;
  nd::require(n.api_origin == explicit_origin || (pin.port == 443 && n.api_origin == default_origin));
}

// A node listed again (after revalidation) is still exactly the same binding.
inline void same_node(const NodeRef& a, const NodeRef& b) {
  nd::require(a.node_id == b.node_id && a.alias == b.alias && a.api_origin == b.api_origin &&
              a.tls_server_name == b.tls_server_name && a.key_fingerprint == b.key_fingerprint &&
              a.grant_id == b.grant_id && a.mapping_id == b.mapping_id &&
              a.remote_legacy_user_id == b.remote_legacy_user_id && a.node_epoch == b.node_epoch &&
              a.config_revision == b.config_revision && a.grant_epoch == b.grant_epoch &&
              a.mapping_epoch == b.mapping_epoch);
  auto x = a.scopes, y = b.scopes;
  std::sort(x.begin(), x.end());
  std::sort(y.begin(), y.end());
  nd::require(x == y);
}

// The node's exchange reply names this Centre session, this node binding and
// its epochs, and expires no later than the Centre session. Returns the expiry.
inline std::int64_t validate_exchange(const json::Value& root, const platform_session::CentralIdentity& c,
                                      const NodeRef& n, std::int64_t now) {
  nd::object(root, 3);
  nd::require(nd::integer(nd::field(root, "schema")) == 1);
  const auto& f = nd::field(root, "federation");
  nd::object(f, 9);
  nd::require(nd::uuid(nd::text(nd::field(f, "federation_session_id"))));
  nd::require(nd::text(nd::field(f, "central_user_id")) == c.central_user_id &&
              nd::text(nd::field(f, "central_session_id")) == c.central_session_id &&
              nd::text(nd::field(f, "node_id")) == n.node_id &&
              nd::text(nd::field(f, "legacy_user_id")) == n.remote_legacy_user_id &&
              nd::text(nd::field(f, "mapping_id")) == n.mapping_id &&
              nd::text(nd::field(f, "grant_id")) == n.grant_id);
  const auto& e = nd::field(f, "epochs");
  nd::object(e, 4);
  nd::require(nd::integer(nd::field(e, "user_epoch")) == c.user_epoch &&
              nd::integer(nd::field(e, "node_epoch")) == n.node_epoch &&
              nd::integer(nd::field(e, "mapping_epoch")) == n.mapping_epoch &&
              nd::integer(nd::field(e, "grant_epoch")) == n.grant_epoch);
  const auto expiry = nd::integer(nd::field(f, "expires_at"));
  nd::require(expiry > now && expiry <= c.expires_at);
  const auto& credential = nd::field(root, "node_credential");
  nd::object(credential, 5);
  nd::require(nd::integer(nd::field(credential, "schema")) == 1 &&
              nd::text(nd::field(credential, "node_id")) == n.node_id &&
              nd::text(nd::field(credential, "api_origin")) == n.api_origin &&
              nd::integer(nd::field(credential, "expires_at")) == expiry);
  nd::validate_token(nd::text(nd::field(credential, "access_token")));
  return expiry;
}

}  // namespace orangespace::node_federation
