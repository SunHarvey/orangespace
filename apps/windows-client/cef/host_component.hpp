#pragma once

// Compiled only by the explicit CEF build-validation project. It remains absent
// from the default executable and cannot be reached from its denying bootstrap.
#include "include/cef_client.h"
#include "include/cef_request_context.h"
#include "include/views/cef_browser_view.h"
#include "include/views/cef_window.h"

#include <filesystem>
#include <string>

namespace orangespace::cef_host {
struct Profile {
  std::string user_id;
  std::string sandbox_id;
  std::string node_id;
  std::filesystem::path profile_root;
};

// Called on the CEF UI thread, after protected bootstrap initialized CEF with
// root_cache_path == profile_root and a real non-null Chromium sandbox_info.
// Current implementation always denies because Windows enforcement is absent.
// Never call CefInitialize until the same service authorization is implemented
// at bootstrap entry, before any Network Service process can be created.
CefRefPtr<CefWindow> CreateProtectedWindow(const Profile& profile,
                                          CefRefPtr<CefClient> client);
}  // namespace orangespace::cef_host
