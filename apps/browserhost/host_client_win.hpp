#pragma once
// CEF client for one sandbox's BrowserHost process. All tabs of the sandbox live
// in this process, share one request context (the sandbox profile) and are
// native child windows of the owner's container window.
#include "host_protocol.hpp"

#include "include/cef_app.h"
#include "include/cef_browser.h"
#include "include/cef_client.h"
#include "include/cef_dialog_handler.h"
#include "include/cef_display_handler.h"
#include "include/cef_download_handler.h"
#include "include/cef_life_span_handler.h"
#include "include/cef_load_handler.h"
#include "include/cef_request_handler.h"
#include "include/cef_resource_request_handler.h"

#include <windows.h>

#include <functional>
#include <map>
#include <mutex>
#include <string>

namespace orangespace::browserhost {

// Writes one event line to the owner. Thread-safe.
class EventSink {
 public:
  explicit EventSink(HANDLE out) : out_(out) {}
  void send(const std::string& line) {
    std::lock_guard lock(mutex_);
    if (broken_) return;
    std::string data = line;
    data.push_back('\n');
    DWORD written{};
    if (!WriteFile(out_, data.data(), static_cast<DWORD>(data.size()), &written, nullptr) || written != data.size())
      broken_ = true;
  }

 private:
  HANDLE out_;
  std::mutex mutex_;
  bool broken_{};
};

class HostClient final : public CefClient,
                         public CefLifeSpanHandler,
                         public CefDisplayHandler,
                         public CefLoadHandler,
                         public CefRequestHandler,
                         public CefResourceRequestHandler,
                         public CefDownloadHandler,
                         public CefDialogHandler {
 public:
  HostClient(Config config, EventSink& events) : config_(std::move(config)), events_(events) {}

  // UI thread only below.
  void OpenTab(const std::string& url);
  void Execute(const Command& command);
  void Resize();
  void CloseAll();  // quits the message loop once every tab has closed
  bool closing() const { return closing_; }

  CefRefPtr<CefLifeSpanHandler> GetLifeSpanHandler() override { return this; }
  CefRefPtr<CefDisplayHandler> GetDisplayHandler() override { return this; }
  CefRefPtr<CefLoadHandler> GetLoadHandler() override { return this; }
  CefRefPtr<CefRequestHandler> GetRequestHandler() override { return this; }
  CefRefPtr<CefDownloadHandler> GetDownloadHandler() override { return this; }
  CefRefPtr<CefDialogHandler> GetDialogHandler() override { return this; }

  // Life span.
  bool OnBeforePopup(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame, int popup_id,
                     const CefString& target_url, const CefString& target_frame_name,
                     cef_window_open_disposition_t target_disposition, bool user_gesture,
                     const CefPopupFeatures& popupFeatures, CefWindowInfo& windowInfo,
                     CefRefPtr<CefClient>& client, CefBrowserSettings& settings,
                     CefRefPtr<CefDictionaryValue>& extra_info, bool* no_javascript_access) override;
  void OnAfterCreated(CefRefPtr<CefBrowser> browser) override;
  bool DoClose(CefRefPtr<CefBrowser> browser) override;
  void OnBeforeClose(CefRefPtr<CefBrowser> browser) override;

  // Display / load state -> owner events.
  void OnAddressChange(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame, const CefString& url) override;
  void OnTitleChange(CefRefPtr<CefBrowser> browser, const CefString& title) override;
  void OnLoadingStateChange(CefRefPtr<CefBrowser> browser, bool loading, bool can_back, bool can_forward) override;

  // Requests.
  bool OnBeforeBrowse(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame, CefRefPtr<CefRequest> request,
                      bool user_gesture, bool is_redirect) override;
  bool OnOpenURLFromTab(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame, const CefString& target_url,
                        cef_window_open_disposition_t target_disposition, bool user_gesture) override;
  bool GetAuthCredentials(CefRefPtr<CefBrowser> browser, const CefString& origin_url, bool isProxy,
                          const CefString& host, int port, const CefString& realm, const CefString& scheme,
                          CefRefPtr<CefAuthCallback> callback) override;
  CefRefPtr<CefResourceRequestHandler> GetResourceRequestHandler(CefRefPtr<CefBrowser>, CefRefPtr<CefFrame>,
                                                                 CefRefPtr<CefRequest>, bool, bool,
                                                                 const CefString&, bool& disable) override {
    disable = false;
    return this;
  }
  void OnProtocolExecution(CefRefPtr<CefBrowser>, CefRefPtr<CefFrame>, CefRefPtr<CefRequest>,
                           bool& allow_os_execution) override {
    allow_os_execution = false;  // never launch external handlers (mailto:, ms-settings:, ...)
  }
  void OnRenderProcessTerminated(CefRefPtr<CefBrowser> browser, TerminationStatus status, int error_code,
                                 const CefString& error_string) override;

  // Downloads and file chooser are bridged to the node file area in P3. Until
  // then nothing touches the local disk.
  bool CanDownload(CefRefPtr<CefBrowser>, const CefString&, const CefString&) override { return false; }
  bool OnBeforeDownload(CefRefPtr<CefBrowser>, CefRefPtr<CefDownloadItem>, const CefString&,
                        CefRefPtr<CefBeforeDownloadCallback>) override {
    return true;  // handled: never continued
  }
  bool OnFileDialog(CefRefPtr<CefBrowser>, FileDialogMode, const CefString&, const CefString&,
                    const std::vector<CefString>&, const std::vector<CefString>&, const std::vector<CefString>&,
                    CefRefPtr<CefFileDialogCallback> callback) override {
    callback->Cancel();
    return true;
  }

 private:
  struct Tab {
    CefRefPtr<CefBrowser> browser;
    TabState state;
  };
  HWND parent() const { return reinterpret_cast<HWND>(static_cast<std::uintptr_t>(config_.parent_window)); }
  Tab* find(int id);
  Tab* target(int id);  // 0 = active tab
  void Activate(int id);
  void Publish(Tab& tab);
  void Layout();

  Config config_;
  EventSink& events_;
  std::map<int, Tab> tabs_;
  int active_{};
  bool closing_{};
  IMPLEMENT_REFCOUNTING(HostClient);
};

class HostApp final : public CefApp, public CefBrowserProcessHandler {
 public:
  // config is null in sub-processes; they never see proxy settings.
  HostApp(const Config* config, std::function<void()> on_context_initialized)
      : config_(config), on_context_initialized_(std::move(on_context_initialized)) {}
  void OnBeforeCommandLineProcessing(const CefString& process_type, CefRefPtr<CefCommandLine> command_line) override;
  CefRefPtr<CefBrowserProcessHandler> GetBrowserProcessHandler() override { return this; }
  void OnContextInitialized() override {
    if (on_context_initialized_) on_context_initialized_();
  }

 private:
  const Config* config_;
  std::function<void()> on_context_initialized_;
  IMPLEMENT_REFCOUNTING(HostApp);
};

}  // namespace orangespace::browserhost
