#include "host_component.hpp"
#include "orangespace/model.hpp"

#include "include/cef_request_context_handler.h"
#include "include/wrapper/cef_helpers.h"

#include <stdexcept>

namespace orangespace::cef_host {
namespace {
class BrowserDelegate final : public CefBrowserViewDelegate {
 public:
  cef_runtime_style_t GetBrowserRuntimeStyle() override { return CEF_RUNTIME_STYLE_CHROME; }
 private:
  IMPLEMENT_REFCOUNTING(BrowserDelegate);
};

class WindowDelegate final : public CefWindowDelegate {
 public:
  explicit WindowDelegate(CefRefPtr<CefBrowserView> browser) : browser_(browser) {}
  cef_runtime_style_t GetWindowRuntimeStyle() override { return CEF_RUNTIME_STYLE_CHROME; }
  void OnWindowCreated(CefRefPtr<CefWindow> window) override {
    window->SetTitle("OrangeSpace");
    window->AddChildView(browser_);
    window->Show();
  }
  bool CanClose(CefRefPtr<CefWindow>) override {
    const auto browser = browser_->GetBrowser();
    return !browser || browser->GetHost()->TryCloseBrowser();
  }
  void OnWindowDestroyed(CefRefPtr<CefWindow>) override { browser_ = nullptr; }
  CefSize GetPreferredSize(CefRefPtr<CefView>) override { return CefSize(1280, 850); }
 private:
  CefRefPtr<CefBrowserView> browser_;
  IMPLEMENT_REFCOUNTING(WindowDelegate);
};
}  // namespace

CefRefPtr<CefWindow> CreateProtectedWindow(const Profile& profile, CefRefPtr<CefClient> client) {
  CEF_REQUIRE_UI_THREAD();
  if (!browser_launch_decision().allowed)
    throw std::runtime_error("protected CEF host unavailable: WFP/DNS enforcement is not implemented");
  if (!valid_uuid(profile.user_id) || !valid_uuid(profile.sandbox_id) || !valid_uuid(profile.node_id) ||
      !profile.profile_root.is_absolute() || !client)
    throw std::runtime_error("invalid protected browser profile");

  // Separate BrowserHost process per sandbox. The global CEF root_cache_path
  // must be exactly this sandbox's profile_root; Default is a child profile.
  CefRequestContextSettings context_settings;
  CefString(&context_settings.cache_path) = (profile.profile_root / "Default").wstring();
  const auto context = CefRequestContext::CreateContext(context_settings, nullptr);
  if (!context) throw std::runtime_error("CEF request context creation failed");
  CefBrowserSettings settings;
  const auto browser = CefBrowserView::CreateBrowserView(client, "about:blank", settings,
                                                        nullptr, context, new BrowserDelegate());
  if (!browser) throw std::runtime_error("CEF Chrome-style BrowserView creation failed");
  return CefWindow::CreateTopLevelWindow(new WindowDelegate(browser));
}
}  // namespace orangespace::cef_host
