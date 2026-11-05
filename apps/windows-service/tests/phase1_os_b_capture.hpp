#pragma once
#include "phase1_os_b_win.hpp"
#include "orangespace/credential_store.hpp"
#include "orangespace/service_client.hpp"
namespace phase1_os_b {
// Limited A client only, AFTER its real save/load and live service binding.
// Captures ONLY its current-user encrypted store bytes + learned grant/binding;
// not the envelope, bearer token, or Node A API password. Return is memory-only.
// The existing A-controller private channel must relay this body without logging.
// Both production Store.load and DPAPI+production restore of the exact captured
// buffer must succeed. This adds real normal-TLS A requests BEFORE the negative
// audit interval; neither path compares only a user ID to bind ciphertext.
Wiped capture_input(const orangespace::node_session::TrustedCatalog& catalog,
 std::string_view alias_a,std::string_view alias_b,
 const orangespace::node_session::NodeSession& actual_a,
 const orangespace::service_client::Grant& grant,
 const orangespace::service::chain::Binding& binding,
 std::string_view username_b,std::string_view password_b,std::uint32_t held_service_pid);
}
