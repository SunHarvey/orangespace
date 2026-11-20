#include "host_client_win.hpp"

#include "include/wrapper/cef_helpers.h"

namespace orangespace::browserhost {
namespace {
std::string Utf8(const CefString& s) { return s.ToString(); }

bool MainFrameUrlAllowed(const std::string& url) {
  // about:blank#... and about:srcdoc are internal documents; everything else
  // top-level must be a plain web URL.
  return allowed_url(url) || url.rfind("about:blank", 0) == 0;
}

bool SubframeUrlAllowed(const std::string& url) {
  // Sub-frames may use document-local schemes, but never local files or
  // privileged browser pages.
  for (const char* scheme : {"file:", "chrome:", "chrome-untrusted:", "devtools:", "view-source:", "filesystem:"}) {
    if (url.size() >= std::strlen(scheme) && _strnicmp(url.c_str(), scheme, std::strlen(scheme)) == 0) return false;
  }
  return true;
}
}  // namespace

HostClient::Tab* HostClient::find(int id) {
  const auto it = tabs_.find(id);
  return it == tabs_.end() ? nullptr : &it->second;
}

HostClient::Tab* HostClient::target(int id) { return find(id == 0 ? active_ : id); }

void HostClient::OpenTab(const std::string& url) {
  CEF_REQUIRE_UI_THREAD();
  if (closing_) return;
  RECT area{};
  GetClientRect(parent(), &area);
  CefWindowInfo info;
  info.SetAsChild(parent(), CefRect(0, 0, area.right - area.left, area.bottom - area.top));
  info.runtime_style = CEF_RUNTIME_STYLE_ALLOY;
  CefBrowserSettings settings;
  if (!CefBrowserHost::CreateBrowser(info, this, url, settings, nullptr, nullptr))
    events_.send(error_event("create browser failed"));
}

void HostClient::Execute(const Command& c) {
  CEF_REQUIRE_UI_THREAD();
  switch (c.op) {
    case Op::new_tab: OpenTab(c.url); return;
    case Op::resize: Layout(); return;
    case Op::shutdown: CloseAll(); return;
    case Op::select_tab:
      if (find(c.tab)) Activate(c.tab);
      return;
    default: break;
  }
  Tab* tab = target(c.tab);
  if (!tab) {
    events_.send(error_event("no such tab"));
    return;
  }
  auto& b = tab->browser;
  switch (c.op) {
    case Op::navigate: b->GetMainFrame()->LoadURL(c.url); break;
    case Op::back: b->GoBack(); break;
    case Op::forward: b->GoForward(); break;
    case Op::reload: b->Reload(); break;
    case Op::stop: b->StopLoad(); break;
    case Op::close_tab: b->GetHost()->CloseBrowser(false); break;
    default: break;
  }
}

void HostClient::Resize() { Layout(); }

void HostClient::Layout() {
  RECT area{};
  if (!GetClientRect(parent(), &area)) return;
  for (auto& [id, tab] : tabs_) {
    const HWND hwnd = tab.browser->GetHost()->GetWindowHandle();
    if (!hwnd) continue;
    if (id == active_) {
      SetWindowPos(hwnd, HWND_TOP, 0, 0, area.right - area.left, area.bottom - area.top,
                   SWP_NOACTIVATE | SWP_SHOWWINDOW);
    } else {
      ShowWindow(hwnd, SW_HIDE);
    }
  }
}

void HostClient::Activate(int id) {
  const int previous = active_;
  active_ = id;
  Layout();
  if (auto* prev = find(previous); prev && previous != id) {
    prev->state.active = false;
    Publish(*prev);
  }
  if (auto* now = find(id)) {
    now->state.active = true;
    now->browser->GetHost()->SetFocus(true);
    Publish(*now);
  }
}

void HostClient::Publish(Tab& tab) { events_.send(tab_event(tab.state)); }

void HostClient::CloseAll() {
  CEF_REQUIRE_UI_THREAD();
  closing_ = true;
  if (tabs_.empty()) {
    CefQuitMessageLoop();
    return;
  }
  for (auto& [id, tab] : tabs_) tab.browser->GetHost()->CloseBrowser(true);
}

bool HostClient::OnBeforePopup(CefRefPtr<CefBrowser>, CefRefPtr<CefFrame>, int, const CefString& target_url,
                               const CefString&, cef_window_open_disposition_t, bool, const CefPopupFeatures&,
                               CefWindowInfo& windowInfo, CefRefPtr<CefClient>& client, CefBrowserSettings&,
                               CefRefPtr<CefDictionaryValue>&, bool*) {
  if (closing_) return true;
  const auto url = Utf8(target_url);
  if (!url.empty() && !MainFrameUrlAllowed(url)) return true;  // cancel
  // Keep window.opener: the popup becomes another tab of this sandbox, created
  // as a child of the same container and the same request context.
  RECT area{};
  GetClientRect(parent(), &area);
  windowInfo.SetAsChild(parent(), CefRect(0, 0, area.right - area.left, area.bottom - area.top));
  windowInfo.runtime_style = CEF_RUNTIME_STYLE_ALLOY;
  client = this;
  return false;
}

void HostClient::OnAfterCreated(CefRefPtr<CefBrowser> browser) {
  CEF_REQUIRE_UI_THREAD();
  const int id = browser->GetIdentifier();
  Tab tab;
  tab.browser = browser;
  tab.state.tab = id;
  tabs_[id] = std::move(tab);
  Activate(id);
}

bool HostClient::DoClose(CefRefPtr<CefBrowser>) {
  return false;  // let CEF destroy the child window
}

void HostClient::OnBeforeClose(CefRefPtr<CefBrowser> browser) {
  CEF_REQUIRE_UI_THREAD();
  const int id = browser->GetIdentifier();
  tabs_.erase(id);
  events_.send(tab_closed_event(id));
  if (closing_) {
    if (tabs_.empty()) CefQuitMessageLoop();
    return;
  }
  if (active_ == id) {
    active_ = 0;
    if (!tabs_.empty()) Activate(tabs_.rbegin()->first);
  }
}

void HostClient::OnAddressChange(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame, const CefString& url) {
  if (!frame->IsMain()) return;
  if (auto* tab = find(browser->GetIdentifier())) {
    tab->state.url = Utf8(url);
    Publish(*tab);
  }
}

void HostClient::OnTitleChange(CefRefPtr<CefBrowser> browser, const CefString& title) {
  if (auto* tab = find(browser->GetIdentifier())) {
    tab->state.title = Utf8(title);
    Publish(*tab);
  }
}

void HostClient::OnLoadingStateChange(CefRefPtr<CefBrowser> browser, bool loading, bool can_back,
                                      bool can_forward) {
  if (auto* tab = find(browser->GetIdentifier())) {
    tab->state.loading = loading;
    tab->state.can_back = can_back;
    tab->state.can_forward = can_forward;
    Publish(*tab);
  }
}

bool HostClient::OnBeforeBrowse(CefRefPtr<CefBrowser>, CefRefPtr<CefFrame> frame, CefRefPtr<CefRequest> request,
                                bool, bool) {
  const auto url = Utf8(request->GetURL());
  return frame->IsMain() ? !MainFrameUrlAllowed(url) : !SubframeUrlAllowed(url);  // true = cancel
}

bool HostClient::OnOpenURLFromTab(CefRefPtr<CefBrowser>, CefRefPtr<CefFrame>, const CefString& target_url,
                                  cef_window_open_disposition_t, bool) {
  // Middle-click / ctrl-click: open as a new tab of this sandbox.
  const auto url = Utf8(target_url);
  if (allowed_url(url)) OpenTab(url);
  return true;
}

bool HostClient::GetAuthCredentials(CefRefPtr<CefBrowser>, const CefString&, bool isProxy, const CefString& host,
                                    int port, const CefString&, const CefString& scheme,
                                    CefRefPtr<CefAuthCallback> callback) {
  // Only answer this sandbox's own loopback proxy. Never hand the proxy
  // credentials to a website or another proxy.
  if (!isProxy || Utf8(host) != "127.0.0.1" || port != config_.proxy_port || Utf8(scheme) != "basic") {
    // Visible to the owner so a misrouted challenge is diagnosable; never
    // includes credentials.
    events_.send(error_event(std::string("auth challenge declined: ") + (isProxy ? "proxy " : "server ") +
                             Utf8(host) + ":" + std::to_string(port) + " scheme=" + Utf8(scheme)));
    return false;
  }
  callback->Continue(config_.proxy_username, config_.proxy_password);
  return true;
}

void HostClient::OnRenderProcessTerminated(CefRefPtr<CefBrowser> browser, TerminationStatus, int, const CefString&) {
  if (auto* tab = find(browser->GetIdentifier())) {
    tab->state.loading = false;
    tab->state.title = "(crashed)";
    Publish(*tab);
  }
}

void HostApp::OnBeforeCommandLineProcessing(const CefString& process_type, CefRefPtr<CefCommandLine> cl) {
  if (!process_type.empty() || !config_) return;
  // Browser process: all traffic goes through this sandbox's authenticated
  // loopback HTTP proxy. "<-loopback>" removes Chromium's implicit loopback
  // bypass so even localhost requests go through the proxy (and are refused
  // there), instead of reaching local services directly.
  cl->AppendSwitchWithValue("proxy-server", "http://127.0.0.1:" + std::to_string(config_->proxy_port));
  cl->AppendSwitchWithValue("proxy-bypass-list", "<-loopback>");
  cl->AppendSwitch("disable-quic");
  cl->AppendSwitch("dns-prefetch-disable");
  cl->AppendSwitchWithValue("force-webrtc-ip-handling-policy", "disable_non_proxied_udp");
  cl->AppendSwitchWithValue("webrtc-ip-handling-policy", "disable_non_proxied_udp");
  // No background calls home that would bypass the per-tab request context.
  cl->AppendSwitch("disable-background-networking");
  cl->AppendSwitch("disable-component-update");
  cl->AppendSwitch("no-pings");
  // Route every auth challenge to HostClient::GetAuthCredentials instead of
  // Chrome's login dialog: the dialog would invite the user to type (or a page
  // to phish) the sandbox proxy credentials. GetAuthCredentials answers only
  // this sandbox's own proxy and declines everything else.
  cl->AppendSwitch("disable-chrome-login-prompt");
}

}  // namespace orangespace::browserhost
