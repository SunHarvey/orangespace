// OrangeSpace: the user's sandboxes, each a Linux desktop in its own window
// whose traffic leaves only through its bound node.
//
//   OrangeSpace.exe [--trust <directory>] [--username <account> --password-stdin]
//
// --password-stdin (acceptance runs only) signs in with the password read from
// a redirected standard input, so a test never types or shows it.
//
// 记住登录 (on by default) keeps the Centre session's renewal in the current
// user's DPAPI store (platform_session::CredentialStore), replaced after every
// refresh. The next start signs in from it; closing the window keeps it, 退出登录
// revokes the session and erases it.
//
// The trust directory (default: "trust" next to this program) holds the
// administrator-protected platform.json (Centre) and catalog.json (node pins);
// both loaders refuse files a normal user could change. An optional probe.json
// there names an HTTPS service the guest checks through each tunnel.
//
// Signing in opens the Centre session; the sandbox list on this computer is per
// Centre user. Opening a sandbox gets a node lease and starts its desktop;
// closing this window stops every desktop and lets every lease lapse. 文件…
// opens a sandbox's files window: personal files on its node beside its
// Downloads folder (see files_window.hpp).
#include "orangespace/files_window.hpp"
#include "orangespace/json.hpp"
#include "orangespace/node_session.hpp"
#include "orangespace/platform_credential_store.hpp"
#include "orangespace/platform_session.hpp"
#include "orangespace/sandbox_engine.hpp"
#include "orangespace/sandbox_status.hpp"
#include "orangespace/sandbox_store.hpp"
#include "orangespace/system_setup.hpp"
#include "orangespace/wsl_runtime.hpp"

#include <bcrypt.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <windowsx.h>

#include <algorithm>
#include <cstdio>
#include <array>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace {
namespace ps = orangespace::platform_session;
namespace ns = orangespace::node_session;
namespace nd = orangespace::node_session::detail;
namespace sb = orangespace::sandbox;
namespace ss = orangespace::system_setup;
namespace wsl = orangespace::wsl;
namespace json = orangespace::json;
namespace fs = std::filesystem;

constexpr UINT kAgentReady = WM_APP + 1;
constexpr UINT kSignedIn = WM_APP + 2;
constexpr UINT kErased = WM_APP + 3;
constexpr UINT kStopped = WM_APP + 4;  // engine shut down (sign-out or exit)
constexpr UINT kSetupProgress = WM_APP + 5;  // lparam: new std::wstring
constexpr UINT kRemoved = WM_APP + 6;        // lparam: new std::wstring (empty: done)
constexpr UINT_PTR kTick = 1;

enum Id : int { Username = 100, Password, SignIn, List, Name, Node, Create, Open, Stop, Rebind, Delete, SignOut, Files, RemoveData, Remember };

std::wstring widen(std::string_view s) {
  const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
  std::wstring out(n > 0 ? n : 0, L'\0');
  if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
  return out;
}

std::string narrow(std::wstring_view w) {
  const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
  std::string out(n > 0 ? n : 0, '\0');
  if (n > 0) WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), out.data(), n, nullptr, nullptr);
  return out;
}

std::string uuid4() {
  unsigned char b[16];
  if (BCryptGenRandom(nullptr, b, sizeof b, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) throw std::runtime_error("no randomness");
  b[6] = static_cast<unsigned char>((b[6] & 0x0f) | 0x40);
  b[8] = static_cast<unsigned char>((b[8] & 0x3f) | 0x80);
  static constexpr char hex[] = "0123456789abcdef";
  std::string out;
  for (int i = 0; i < 16; ++i) {
    if (i == 4 || i == 6 || i == 8 || i == 10) out += '-';
    out += hex[b[i] >> 4];
    out += hex[b[i] & 15];
  }
  return out;
}

std::wstring window_text(HWND h) {
  std::wstring s(static_cast<std::size_t>(GetWindowTextLengthW(h)) + 1, L'\0');
  s.resize(static_cast<std::size_t>(GetWindowTextW(h, s.data(), static_cast<int>(s.size()))));
  return s;
}

// Plain words for what the engine reports; the raw reason stays in the log.
std::wstring hint(const std::string& error) {
  if (error.empty()) return L"";
  if (error.rfind("Centre HTTP 401", 0) == 0) return L"中心登录已失效，请退出后重新登录";
  if (error.rfind("Centre HTTP", 0) == 0 || error == "Centre access expired") return L"无法连接中心，正在重试";
  if (error.rfind("node HTTP 401", 0) == 0 || error.rfind("node HTTP 403", 0) == 0) return L"节点拒绝了本沙盒，正在重新授权";
  if (error.rfind("node HTTP", 0) == 0) return L"节点暂时不可用，正在重试（期间不联网）";
  if (error.find("grants no access") != std::string::npos || error.find("no tunnel grant") != std::string::npos)
    return L"中心未授权此节点";
  if (error.find("WSL agent") != std::string::npos) return L"WSL 已停止，请重新打开橙域";
  if (error == "the desktop stopped") return L"桌面已意外停止";
  return L"出错：" + widen(error);
}

// Non-secret probe settings, passed to the guest as they are (it validates them).
std::string load_probe(const fs::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return {};
  std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  if (text.size() > 4096) throw std::runtime_error("probe.json is too large");
  if (text.rfind("\xEF\xBB\xBF", 0) == 0) text.erase(0, 3);
  const auto v = json::parse(text);
  const auto* o = std::get_if<json::Value::Object>(&v.data);
  if (!o) throw std::runtime_error("probe.json must be an object");
  std::string out = "{";
  for (const auto& [key, value] : *o) {
    if (key != "ipv4" && key != "port" && key != "tls_name" && key != "path") throw std::runtime_error("probe.json: unknown field");
    out += (out.size() > 1 ? "," : "") + std::string("\"") + key + "\":";
    if (const auto* s = std::get_if<std::string>(&value.data)) {
      for (const unsigned char c : *s)
        if (c < 0x20 || c == '"' || c == '\\') throw std::runtime_error("probe.json: invalid text");
      out += "\"" + *s + "\"";
    } else if (const auto* n = std::get_if<double>(&value.data)) {
      out += std::to_string(static_cast<long long>(*n));
    } else {
      throw std::runtime_error("probe.json: invalid value");
    }
  }
  return out + "}";
}

// One line per event in client.log, prefixed with the local time. Events only
// (tunnel IDs, generations, reasons), never credentials. Lines come from the
// refresher and every sandbox worker, so writes are serialized.
std::function<void(const std::string&)> event_log(fs::path path) {
  return [path = std::move(path)](const std::string& line) {
    static std::mutex lock;
    SYSTEMTIME t{};
    GetLocalTime(&t);
    char stamp[32];
    std::snprintf(stamp, sizeof stamp, "%04u-%02u-%02u %02u:%02u:%02u ", t.wYear, t.wMonth, t.wDay, t.wHour,
                  t.wMinute, t.wSecond);
    std::lock_guard guard(lock);
    std::ofstream(path, std::ios::app | std::ios::binary) << stamp << line << "\n";
  };
}

fs::path user_directory(const std::string& central_user_id) {
  PWSTR base = nullptr;
  if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_CREATE, nullptr, &base)))
    throw std::runtime_error("no local application data folder");
  fs::path dir = fs::path(base) / L"OrangeSpace" / L"users" / widen(central_user_id);
  CoTaskMemFree(base);
  fs::create_directories(dir);
  return dir;
}

struct AgentResult {
  std::unique_ptr<wsl::Agent> agent;
  std::wstring error;
};

struct SignInResult {
  std::unique_ptr<ps::Session> session;
  std::vector<ps::NodeRef> nodes;
  std::wstring error;
  bool remembered{false};  // the session's renewal is saved and kept current
  std::wstring warning;    // signed in, but remembering it failed
};

class App {
 public:
  App(fs::path trust, std::string username, std::shared_ptr<std::string> password)
      : trust_(std::move(trust)), auto_user_(std::move(username)), auto_password_(std::move(password)) {}

  void create(HWND window) {
    window_ = window;
    dpi_ = GetDpiForWindow(window);
    font_ = CreateFontW(-px(15), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Microsoft YaHei UI");
    title_font_ = CreateFontW(-px(22), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                              CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Microsoft YaHei UI");
    heading_ = control(L"STATIC", L"登录橙域", SS_LEFT);
    SendMessageW(heading_, WM_SETFONT, reinterpret_cast<WPARAM>(title_font_), TRUE);
    username_label_ = control(L"STATIC", L"账号", SS_LEFT);
    username_ = control(L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL, Username, WS_EX_CLIENTEDGE);
    password_label_ = control(L"STATIC", L"密码", SS_LEFT);
    password_ = control(L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL | ES_PASSWORD, Password, WS_EX_CLIENTEDGE);
    SendMessageW(username_, EM_LIMITTEXT, 64, 0);
    SendMessageW(password_, EM_LIMITTEXT, 1024, 0);
    remember_ = control(L"BUTTON", L"记住登录", WS_TABSTOP | BS_AUTOCHECKBOX, Remember);
    SendMessageW(remember_, BM_SETCHECK, BST_CHECKED, 0);
    sign_in_ = control(L"BUTTON", L"登录", WS_TABSTOP | BS_DEFPUSHBUTTON, SignIn);
    remove_data_ = control(L"BUTTON", L"删除本机全部数据…", WS_TABSTOP, RemoveData);

    identity_ = control(L"STATIC", L"", SS_LEFT);
    sign_out_ = control(L"BUTTON", L"退出登录", WS_TABSTOP, SignOut);
    list_ = control(WC_LISTVIEWW, L"", WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS, List,
                    WS_EX_CLIENTEDGE);
    ListView_SetExtendedListViewStyle(list_, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
    const struct { const wchar_t* title; int width; } columns[] = {
        {L"沙盒", 150}, {L"节点", 110}, {L"桌面", 150}, {L"网络", 90}, {L"租约", 130}, {L"提示", 260}};
    for (int i = 0; i < 6; ++i) {
      LVCOLUMNW c{LVCF_TEXT | LVCF_WIDTH};
      c.pszText = const_cast<wchar_t*>(columns[i].title);
      c.cx = px(columns[i].width);
      ListView_InsertColumn(list_, i, &c);
    }
    open_ = control(L"BUTTON", L"打开", WS_TABSTOP, Open);
    stop_ = control(L"BUTTON", L"停止", WS_TABSTOP, Stop);
    delete_ = control(L"BUTTON", L"删除…", WS_TABSTOP, Delete);
    files_ = control(L"BUTTON", L"文件…", WS_TABSTOP, Files);
    name_label_ = control(L"STATIC", L"名称", SS_LEFT);
    name_ = control(L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL, Name, WS_EX_CLIENTEDGE);
    SendMessageW(name_, EM_LIMITTEXT, sb::kMaxNameChars, 0);
    SendMessageW(name_, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"新沙盒的名称"));
    node_label_ = control(L"STATIC", L"节点", SS_LEFT);
    node_ = control(WC_COMBOBOXW, L"", WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL, Node);
    create_ = control(L"BUTTON", L"新建沙盒", WS_TABSTOP, Create);
    rebind_ = control(L"BUTTON", L"改用此节点", WS_TABSTOP, Rebind);
    notice_ = control(L"STATIC", L"", SS_LEFT | SS_NOPREFIX);

    load_trust();
    start_agent();
    show_main(false);
    SetTimer(window_, kTick, 1000, nullptr);
    if (auto_password_) {
      SetWindowTextW(username_, widen(auto_user_).c_str());
      begin_sign_in(auto_user_, std::move(auto_password_));
    } else {
      begin_resume();
    }
  }

  void layout() {
    RECT rc;
    GetClientRect(window_, &rc);
    const int w = rc.right, h = rc.bottom, m = px(20), row = px(30), gap = px(10);
    if (!signed_in()) {
      const int x = (std::max)(m, (w - px(360)) / 2), y = (std::max)(m, (h - px(300)) / 2);
      MoveWindow(heading_, x, y, px(360), px(36), TRUE);
      MoveWindow(username_label_, x, y + px(56), px(360), px(22), TRUE);
      MoveWindow(username_, x, y + px(80), px(360), row, TRUE);
      MoveWindow(password_label_, x, y + px(122), px(360), px(22), TRUE);
      MoveWindow(password_, x, y + px(146), px(360), row, TRUE);
      MoveWindow(remember_, x, y + px(186), px(360), px(26), TRUE);
      MoveWindow(sign_in_, x, y + px(222), px(360), px(34), TRUE);
      MoveWindow(notice_, x, y + px(270), px(360), px(60), TRUE);
      MoveWindow(remove_data_, w - m - px(160), h - m - px(30), px(160), px(30), TRUE);
      return;
    }
    MoveWindow(identity_, m, m, w - 2 * m - px(110), px(24), TRUE);
    MoveWindow(sign_out_, w - m - px(100), m - px(4), px(100), row, TRUE);
    const int bottom = h - m - px(44);
    const int list_top = m + px(36), list_bottom = bottom - px(48);
    MoveWindow(list_, m, list_top, w - 2 * m, (std::max)(px(80), list_bottom - list_top), TRUE);
    int x = m;
    for (HWND b : {open_, stop_, files_, delete_}) {
      MoveWindow(b, x, list_bottom + gap, px(90), row, TRUE);
      x += px(90) + gap;
    }
    x = m;
    MoveWindow(name_label_, x, bottom + px(5), px(40), px(22), TRUE);
    MoveWindow(name_, x + px(42), bottom, px(200), row, TRUE);
    MoveWindow(node_label_, x + px(256), bottom + px(5), px(40), px(22), TRUE);
    MoveWindow(node_, x + px(298), bottom, px(200), px(240), TRUE);
    MoveWindow(create_, x + px(512), bottom, px(100), row, TRUE);
    MoveWindow(rebind_, x + px(622), bottom, px(110), row, TRUE);
    MoveWindow(notice_, m, h - m - px(6), w - 2 * m, px(22), TRUE);
  }

  void command(int id) {
    try {
      switch (id) {
        case IDOK:
          if (!signed_in()) sign_in();
          break;
        case SignIn: sign_in(); break;
        case Create: create_sandbox(); break;
        case Open: open_selected(); break;
        case Stop: stop_selected(); break;
        case Rebind: rebind_selected(); break;
        case Delete: delete_selected(); break;
        case Files: open_files(); break;
        case SignOut: sign_out(); break;
        case RemoveData: remove_all_data(); break;
        default: break;
      }
    } catch (const std::exception& e) {
      notice(L"操作未完成：" + widen(e.what()));
    }
    update_buttons();
  }

  void tick() {
    if (!signed_in()) return;
    const auto& records = store_.records();
    for (int i = 0; i < static_cast<int>(records.size()); ++i) {
      const auto s = engine_ ? engine_->status(records[i].id) : sb::Status{};
      set_cell(i, 2, widen(sb::desktop_label(s)));
      set_cell(i, 3, widen(sb::network_label(s)));
      set_cell(i, 4, widen(sb::lease_label(s)));
      set_cell(i, 5, hint(s.error));
    }
    update_buttons();
  }

  void agent_ready(AgentResult* raw) {
    std::unique_ptr<AgentResult> result(raw);
    if (agent_thread_.joinable()) agent_thread_.join();
    if (!result->agent) {
      agent_error_ = result->error;
      notice(result->error);
      return;
    }
    agent_ = std::move(result->agent);
    if (signed_in()) make_engine();
    if (notice_text_ == L"正在启动 WSL……" || (!setup_text_.empty() && notice_text_ == setup_text_)) notice(L"");
  }

  void setup_progress(std::wstring* raw) {
    std::unique_ptr<std::wstring> text(raw);
    setup_text_ = *text;
    notice(setup_text_);
  }

  // Sign-in screen only: no sandbox is running, only the agent.
  void remove_all_data() {
    if (signed_in() || removing_) return;
    if (agent_thread_.joinable()) {
      notice(L"系统组件还在准备，请等它完成后再删除。");
      return;
    }
    if (MessageBoxW(window_,
                    L"将删除这台电脑上属于当前 Windows 用户的全部橙域数据：所有沙盒桌面（含其中的文件、浏览器资料和“下载”）、"
                    L"沙盒列表、日志和保存的登录信息。节点上的个人文件不受影响。\n\n此操作不能撤销。删除后橙域会关闭。要继续吗？",
                    L"橙域", MB_OKCANCEL | MB_ICONWARNING | MB_DEFBUTTON2) != IDOK)
      return;
    removing_ = true;
    EnableWindow(window_, FALSE);
    notice(L"正在删除本机数据……");
    std::shared_ptr<wsl::Agent> agent(std::move(agent_));
    remove_thread_ = std::thread([this, agent] {
      auto error = std::make_unique<std::wstring>();
      try {
        if (agent) agent->shutdown();
        ss::remove_all_local_data();
      } catch (const std::exception& e) {
        *error = widen(e.what());
      }
      if (PostMessageW(window_, kRemoved, 0, reinterpret_cast<LPARAM>(error.get()))) error.release();
    });
  }

  void removed(std::wstring* raw) {
    std::unique_ptr<std::wstring> error(raw);
    if (remove_thread_.joinable()) remove_thread_.join();
    MessageBoxW(window_, error->empty() ? L"本机的橙域数据已删除。" : (L"删除没有全部完成：" + *error).c_str(), L"橙域",
                MB_OK | (error->empty() ? MB_ICONINFORMATION : MB_ICONWARNING));
    exiting_ = true;
    KillTimer(window_, kTick);
    DestroyWindow(window_);
  }

  void signed_in_result(SignInResult* raw) {
    std::unique_ptr<SignInResult> result(raw);
    if (sign_in_thread_.joinable()) sign_in_thread_.join();
    EnableWindow(sign_in_, TRUE);
    EnableWindow(username_, TRUE);
    EnableWindow(password_, TRUE);
    EnableWindow(remember_, TRUE);
    if (!result->session) {
      notice(result->error);
      return;
    }
    remembered_ = result->remembered;
    {
      const auto log_path = user_directory(result->session->identity().central_user_id) / L"client.log";
      std::function<void(const ps::Session&)> refreshed;
      if (remembered_)
        refreshed = [platform = platform_](const ps::Session& s) { ps::CredentialStore::save(*platform, s); };
      centre_ = std::make_shared<sb::Centre>(
          std::move(*result->session),
          event_log(log_path),
          std::move(refreshed));
    }
    nodes_ = std::move(result->nodes);
    const auto identity = centre_->identity();
    directory_ = user_directory(identity.central_user_id);
    {
      // Copies in transit left behind by a client that did not finish them.
      std::error_code ec;
      fs::remove_all(directory_ / L"transfer", ec);
    }
    load_store();
    SetWindowTextW(identity_, (L"已登录：" + widen(identity.username)).c_str());
    SendMessageW(node_, CB_RESETCONTENT, 0, 0);
    for (const auto& n : nodes_) {
      const auto label = widen(n.display_name.empty() ? n.alias : n.display_name);
      SendMessageW(node_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label.c_str()));
    }
    if (!nodes_.empty()) SendMessageW(node_, CB_SETCURSEL, 0, 0);
    if (agent_) make_engine();
    show_main(true);
    fill_list();
    if (!result->warning.empty()) notice(result->warning);
    else if (nodes_.empty()) notice(L"中心没有给这个账号授权可用的节点，请联系管理员。");
    else if (!agent_error_.empty()) notice(agent_error_);
    else if (!agent_) notice(L"正在启动 WSL……");
    else notice(L"");
  }

  void erased(std::string* raw, bool ok) {
    std::unique_ptr<std::string> id(raw);
    if (!signed_in()) return;
    if (!ok) {
      notice(L"删除未完成，本机数据仍在。可以稍后再试。");
      return;
    }
    if (store_.find(*id)) {
      store_.remove(*id);
      save_store();
    }
    fill_list();
    notice(L"沙盒已删除。节点上的个人文件不受影响。");
  }

  // Sign-out and exit both stop every sandbox first, off the UI thread.
  bool close_requested() {
    if (closing_) return false;
    if (engine_ && engine_->any_active() &&
        MessageBoxW(window_, L"关闭橙域会停止所有正在运行的沙盒桌面，未保存的内容会丢失。要关闭吗？", L"橙域",
                    MB_OKCANCEL | MB_ICONQUESTION) != IDOK)
      return false;
    closing_ = true;
    exiting_ = true;
    if (files_windows_) files_windows_->close_all();
    EnableWindow(window_, FALSE);
    notice(L"正在停止所有沙盒……");
    stop_everything();
    return false;
  }

  void stopped() {
    if (stop_thread_.joinable()) stop_thread_.join();
    files_windows_.reset();
    guest_files_.reset();
    engine_.reset();
    centre_.reset();
    if (exiting_) {
      KillTimer(window_, kTick);
      DestroyWindow(window_);
      return;
    }
    closing_ = false;
    remembered_ = false;
    store_ = sb::Store{};
    nodes_.clear();
    ListView_DeleteAllItems(list_);
    show_main(false);
    EnableWindow(window_, TRUE);
    notice(L"已退出登录。");
  }

  void destroyed() {
    for (auto* t : {&agent_thread_, &sign_in_thread_, &stop_thread_, &remove_thread_})
      if (t->joinable()) t->join();
    files_windows_.reset();
    guest_files_.reset();
    engine_.reset();
    if (agent_) agent_->shutdown();
    DeleteObject(font_);
    DeleteObject(title_font_);
  }

  int px(int value) const { return MulDiv(value, static_cast<int>(dpi_), 96); }

  void dpi_changed(UINT dpi) {
    dpi_ = dpi;
    layout();
  }

  void selection_changed() { update_buttons(); }

 private:
  bool signed_in() const { return centre_ != nullptr; }

  HWND control(const wchar_t* kind, const wchar_t* text, DWORD style, int id = 0, DWORD ex = 0) {
    HWND h = CreateWindowExW(ex, kind, text, WS_CHILD | style, 0, 0, 10, 10, window_,
                             reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), nullptr);
    SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(font_), TRUE);
    return h;
  }

  void notice(const std::wstring& text) {
    notice_text_ = text;
    SetWindowTextW(notice_, text.c_str());
  }

  void show_main(bool main) {
    for (HWND h : {heading_, username_label_, username_, password_label_, password_, remember_, sign_in_, remove_data_})
      ShowWindow(h, main ? SW_HIDE : SW_SHOW);
    for (HWND h : {identity_, sign_out_, list_, open_, stop_, files_, delete_, name_label_, name_, node_label_, node_, create_, rebind_})
      ShowWindow(h, main ? SW_SHOW : SW_HIDE);
    ShowWindow(notice_, SW_SHOW);
    layout();
    update_buttons();
    SetFocus(main ? list_ : username_);
  }

  void load_trust() {
    try {
      platform_ = std::make_shared<const ps::PlatformConfig>(ps::PlatformConfig::load((trust_ / L"platform.json").wstring()));
      catalog_ = std::make_shared<const ns::TrustedCatalog>(ns::TrustedCatalog::load((trust_ / L"catalog.json").wstring()));
      probe_ = load_probe(trust_ / L"probe.json");
    } catch (const std::exception&) {
      platform_.reset();
      catalog_.reset();
      notice(L"受保护的配置无法读取（" + trust_.wstring() + L"），请联系管理员重新安装。");
    }
  }

  void start_agent() {
    // Booting WSL here, from the user's own session, is what lets the desktop
    // windows appear on this screen.
    agent_thread_ = std::thread([this] {
      auto result = std::make_unique<AgentResult>();
      try {
        // An installed release first brings this user's distribution to it
        // (first start: import; after an upgrade: replace, keeping the data).
        if (auto setup = ss::SystemSetup::for_this_install())
          setup->run([this](const std::wstring& line) {
            auto text = std::make_unique<std::wstring>(line);
            if (PostMessageW(window_, kSetupProgress, 0, reinterpret_cast<LPARAM>(text.get()))) text.release();
          });
        result->agent = std::make_unique<wsl::Agent>();
      } catch (const ss::SetupError& e) {
        result->error = L"橙域系统组件没有就绪：" + widen(e.what());
      } catch (const std::exception& e) {
        const std::string what = e.what();
        result->error = what.find("not installed") != std::string::npos
                            ? L"本机还没有安装橙域的 WSL 组件，沙盒无法启动。"
                            : L"WSL 启动失败：" + widen(what);
      }
      // Handed to the UI thread, which alone owns agent_.
      if (!PostMessageW(window_, kAgentReady, 0, reinterpret_cast<LPARAM>(result.get()))) return;
      result.release();
    });
  }

  void make_engine() {
    if (engine_ || !agent_ || !centre_ || !catalog_) return;
    const auto log = event_log(directory_ / L"client.log");
    engine_ = std::make_unique<sb::Engine>(*catalog_, *centre_, *agent_, probe_, log);
    guest_files_ = std::make_unique<sb::GuestFiles>(*agent_, centre_->identity().central_user_id);
    files_windows_ = std::make_unique<sb::FilesWindows>(window_, *guest_files_, log);
  }

  void sign_in() {
    if (sign_in_thread_.joinable()) return;
    if (!platform_) {
      notice(L"受保护的配置无法读取，不能登录。");
      return;
    }
    const auto user = narrow(window_text(username_));
    auto wide = window_text(password_);
    SetWindowTextW(password_, L"");
    auto password = std::make_shared<std::string>(narrow(wide));
    nd::wipe(wide.data(), wide.size() * sizeof(wchar_t));
    begin_sign_in(user, std::move(password));
  }

  void begin_sign_in(const std::string& user, std::shared_ptr<std::string> password) {
    if (!platform_ || sign_in_thread_.joinable()) {
      nd::wipe(password->data(), password->size());
      return;
    }
    if (user.empty() || password->empty()) {
      nd::wipe(password->data(), password->size());
      notice(L"请输入账号和密码。");
      return;
    }
    const bool remember = SendMessageW(remember_, BM_GETCHECK, 0, 0) == BST_CHECKED;
    lock_sign_in(L"正在登录……");
    sign_in_thread_ = std::thread([this, user, password, remember] {
      auto result = std::make_unique<SignInResult>();
      try {
        result->session = std::make_unique<ps::Session>(ps::Session::login(*platform_, user, *password));
        for (auto& n : result->session->nodes())
          if (std::find(n.scopes.begin(), n.scopes.end(), "tunnel") != n.scopes.end()) result->nodes.push_back(std::move(n));
        // A password sign-in replaces whatever was remembered before.
        try {
          ps::CredentialStore::erase(*platform_);
          if (remember) {
            ps::CredentialStore::save(*platform_, *result->session);
            result->remembered = true;
          }
        } catch (const std::exception&) {
          result->warning = L"已登录，但没能记住登录，下次需要重新输入密码。";
        }
      } catch (const ps::HttpStatusError& e) {
        result->session.reset();
        result->error = e.status_code() == 401 ? L"账号或密码不正确。" : L"中心拒绝了登录（HTTP " + std::to_wstring(e.status_code()) + L"）。";
      } catch (const std::exception&) {
        result->session.reset();
        result->error = L"无法连接中心，请检查网络后重试。";
      }
      nd::wipe(password->data(), password->size());
      PostMessageW(window_, kSignedIn, 0, reinterpret_cast<LPARAM>(result.release()));
    });
  }

  void lock_sign_in(const wchar_t* text) {
    EnableWindow(sign_in_, FALSE);
    EnableWindow(username_, FALSE);
    EnableWindow(password_, FALSE);
    EnableWindow(remember_, FALSE);
    notice(text);
  }

  // At start: sign in from the remembered renewal, if there is one.
  void begin_resume() {
    if (!platform_ || sign_in_thread_.joinable()) return;
    lock_sign_in(L"正在用保存的登录信息登录……");
    sign_in_thread_ = std::thread([this] {
      auto result = std::make_unique<SignInResult>();
      try {
        auto saved = ps::CredentialStore::load(*platform_);
        if (saved) {
          result->session = std::make_unique<ps::Session>(std::move(*saved));
          result->remembered = true;
          for (auto& n : result->session->nodes())
            if (std::find(n.scopes.begin(), n.scopes.end(), "tunnel") != n.scopes.end()) result->nodes.push_back(std::move(n));
        }
      } catch (const ps::SavedSignInKept&) {
        result->session.reset();
        result->error = L"无法连接中心，暂时不能用保存的登录信息。请检查网络后重新打开橙域，或输入密码登录。";
      } catch (const ps::HttpStatusError& e) {
        result->session.reset();
        result->error = e.status_code() == 401 || e.status_code() == 403
                            ? L"保存的登录已失效，请重新登录。"
                            : L"中心暂时不可用（HTTP " + std::to_wstring(e.status_code()) + L"），请稍后重试或输入密码登录。";
      } catch (const std::exception&) {
        result->session.reset();
        result->error = L"保存的登录信息无法使用，请重新登录。";
      }
      PostMessageW(window_, kSignedIn, 0, reinterpret_cast<LPARAM>(result.release()));
    });
  }

  void sign_out() {
    if (closing_) return;
    if (engine_ && engine_->any_active() &&
        MessageBoxW(window_, L"退出登录会停止所有正在运行的沙盒桌面。要继续吗？", L"橙域", MB_OKCANCEL | MB_ICONQUESTION) != IDOK)
      return;
    closing_ = true;
    if (files_windows_) files_windows_->close_all();
    EnableWindow(window_, FALSE);
    notice(L"正在停止所有沙盒并退出登录……");
    stop_everything();
  }

  // Closing the window keeps a remembered sign-in (the session stays, unused,
  // until its deadline); signing out, or closing without it, ends the session.
  void stop_everything() {
    const bool keep = exiting_ && remembered_, forget = remembered_ && !exiting_;
    stop_thread_ = std::thread([this, keep, forget] {
      if (engine_) engine_->shutdown();
      if (centre_ && !keep) {
        try {
          centre_->logout();
        } catch (const std::exception&) {
          // The Centre session expires on its own; no sandbox is running any more.
        }
      }
      if (forget && platform_) {
        try {
          ps::CredentialStore::erase(*platform_);
        } catch (const std::exception&) {
          // The pending marker stays; the next password sign-in finishes the erase.
        }
      }
      PostMessageW(window_, kStopped, 0, 0);
    });
  }

  void load_store() {
    store_ = sb::Store{};
    const auto path = directory_ / L"sandboxes.json";
    std::ifstream in(path, std::ios::binary);
    if (!in) return;
    std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();
    try {
      store_ = sb::Store::parse(text);
    } catch (const std::exception&) {
      // Keep the unreadable file for inspection; the desktops stay in the distribution.
      std::error_code ec;
      fs::rename(path, directory_ / L"sandboxes.json.unreadable", ec);
      notice(L"本机沙盒列表已损坏，已另存为 sandboxes.json.unreadable。");
    }
  }

  void save_store() {
    const auto path = directory_ / L"sandboxes.json";
    const auto temp = directory_ / L"sandboxes.json.new";
    {
      std::ofstream out(temp, std::ios::binary | std::ios::trunc);
      out << store_.serialize();
      out.flush();
      if (!out) throw std::runtime_error("cannot write the sandbox list");
    }
    if (!MoveFileExW(temp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
      throw std::runtime_error("cannot save the sandbox list");
  }

  const ps::NodeRef* node(const std::string& id) const {
    const auto it = std::find_if(nodes_.begin(), nodes_.end(), [&](const auto& n) { return n.node_id == id; });
    return it == nodes_.end() ? nullptr : &*it;
  }

  std::wstring node_name(const std::string& id) const {
    const auto* n = node(id);
    return n ? widen(n->display_name.empty() ? n->alias : n->display_name) : L"（未授权）";
  }

  void set_cell(int row, int column, const std::wstring& text) {
    wchar_t current[256]{};
    ListView_GetItemText(list_, row, column, current, 256);
    if (text != current) ListView_SetItemText(list_, row, column, const_cast<wchar_t*>(text.c_str()));
  }

  void fill_list() {
    const auto selected = selected_id();
    ListView_DeleteAllItems(list_);
    const auto& records = store_.records();
    for (int i = 0; i < static_cast<int>(records.size()); ++i) {
      auto name = widen(records[i].name);
      LVITEMW item{LVIF_TEXT};
      item.iItem = i;
      item.pszText = name.data();
      ListView_InsertItem(list_, &item);
      set_cell(i, 1, node_name(records[i].node_id));
      if (records[i].id == selected) ListView_SetItemState(list_, i, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    tick();
  }

  std::string selected_id() const {
    const int i = ListView_GetNextItem(list_, -1, LVNI_SELECTED);
    const auto& records = store_.records();
    return i >= 0 && i < static_cast<int>(records.size()) ? records[i].id : std::string();
  }

  const sb::Record* selected() const {
    const auto id = selected_id();
    return id.empty() ? nullptr : store_.find(id);
  }

  const ps::NodeRef* chosen_node() const {
    const auto i = static_cast<int>(SendMessageW(node_, CB_GETCURSEL, 0, 0));
    return i >= 0 && i < static_cast<int>(nodes_.size()) ? &nodes_[i] : nullptr;
  }

  void update_buttons() {
    if (!signed_in()) {
      EnableWindow(sign_in_, !sign_in_thread_.joinable() && platform_ != nullptr);
      return;
    }
    const auto* r = selected();
    const auto s = r && engine_ ? engine_->status(r->id) : sb::Status{};
    const bool idle = s.phase == sb::Phase::stopped || s.phase == sb::Phase::failed;
    EnableWindow(open_, r && engine_ && (idle || s.phase == sb::Phase::running) && node(r->node_id));
    EnableWindow(stop_, r && engine_ && sb::active(s.phase));
    EnableWindow(delete_, r && engine_ && idle);
    EnableWindow(files_, r && files_windows_ && s.phase != sb::Phase::deleting && file_scopes(r->node_id));
    EnableWindow(rebind_, r && idle && chosen_node() && chosen_node()->node_id != r->node_id);
    EnableWindow(create_, chosen_node() && store_.records().size() < sb::kMaxSandboxes);
  }

  sb::Spec spec(const sb::Record& r) const {
    return sb::Spec{r.id, r.node_id, r.name + " · 橙域"};
  }

  void create_sandbox() {
    const auto* n = chosen_node();
    if (!n) return;
    std::string name;
    try {
      name = sb::valid_name(narrow(window_text(name_)));
    } catch (const sb::StoreError&) {
      notice(L"请给沙盒起一个名称（最多 " + std::to_wstring(sb::kMaxNameChars) + L" 个字）。");
      return;
    }
    sb::Record r{uuid4(), name, n->node_id};
    store_.add(r);
    save_store();
    SetWindowTextW(name_, L"");
    fill_list();
    const auto& records = store_.records();
    for (int i = 0; i < static_cast<int>(records.size()); ++i)
      if (records[i].id == r.id) ListView_SetItemState(list_, i, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    if (engine_) {
      engine_->open(spec(r));
      notice(L"已新建「" + widen(name) + L"」，正在启动。");
    } else {
      notice(L"已新建「" + widen(name) + L"」。WSL 就绪后即可打开。");
    }
  }

  void open_selected() {
    const auto* r = selected();
    if (!r || !engine_) return;
    if (!node(r->node_id)) {
      notice(L"中心不再授权这个沙盒的节点，请改用其他节点。");
      return;
    }
    const bool running = engine_->status(r->id).phase == sb::Phase::running;
    engine_->open(spec(*r));
    notice(running ? L"正在打开桌面窗口。" : L"正在启动「" + widen(r->name) + L"」。");
  }

  bool file_scopes(const std::string& node_id) const {
    const auto* n = node(node_id);
    return n && std::find(n->scopes.begin(), n->scopes.end(), "files.read") != n->scopes.end() &&
           std::find(n->scopes.begin(), n->scopes.end(), "files.write") != n->scopes.end();
  }

  void open_files() {
    const auto* r = selected();
    if (!r || !files_windows_ || !centre_ || !file_scopes(r->node_id)) {
      notice(L"中心没有授权这个节点上的个人文件。");
      return;
    }
    sb::FilesTarget target;
    target.sandbox_id = r->id;
    target.sandbox_name = r->name;
    target.node_name = narrow(node_name(r->node_id));
    target.context.central_user_id = centre_->identity().central_user_id;
    target.context.sandbox_id = r->id;
    target.context.node_id = r->node_id;
    target.context.centre = centre_;
    target.context.catalog = catalog_;
    target.staging = directory_ / L"transfer";
    files_windows_->open(target);
  }

  void stop_selected() {
    const auto* r = selected();
    if (!r || !engine_) return;
    engine_->stop(r->id);
    notice(L"正在停止「" + widen(r->name) + L"」。");
  }

  void rebind_selected() {
    const auto* r = selected();
    const auto* n = chosen_node();
    if (!r || !n) return;
    const auto text = L"把「" + widen(r->name) + L"」改为经「" + node_name(n->node_id) +
                      L"」联网？桌面里的文件和浏览器资料保留。";
    if (MessageBoxW(window_, text.c_str(), L"更换节点", MB_OKCANCEL | MB_ICONQUESTION) != IDOK) return;
    store_.rebind(r->id, n->node_id);
    save_store();
    fill_list();
    notice(L"已更换节点，下次打开时生效。");
  }

  void delete_selected() {
    const auto* r = selected();
    if (!r || !engine_) return;
    const auto text = L"删除「" + widen(r->name) +
                      L"」？\n\n这个沙盒在本机的桌面、文件、下载和浏览器资料都会被删除，无法恢复。\n节点上的个人文件不受影响。";
    if (MessageBoxW(window_, text.c_str(), L"删除沙盒", MB_OKCANCEL | MB_ICONWARNING | MB_DEFBUTTON2) != IDOK) return;
    const auto id = r->id;
    if (files_windows_) files_windows_->close(id);
    HWND window = window_;
    engine_->erase(id, [window, id](bool ok, std::string) {
      PostMessageW(window, kErased, ok ? 1 : 0, reinterpret_cast<LPARAM>(new std::string(id)));
    });
    notice(L"正在删除「" + widen(r->name) + L"」……");
  }

  fs::path trust_;
  std::string auto_user_;
  std::shared_ptr<std::string> auto_password_;
  HWND window_{};
  UINT dpi_{96};
  HFONT font_{}, title_font_{};
  HWND heading_{}, username_label_{}, username_{}, password_label_{}, password_{}, remember_{}, sign_in_{}, remove_data_{};
  HWND identity_{}, sign_out_{}, list_{}, open_{}, stop_{}, files_{}, delete_{}, name_label_{}, name_{}, node_label_{}, node_{},
      create_{}, rebind_{}, notice_{};
  std::wstring notice_text_, agent_error_, setup_text_;
  std::thread remove_thread_;
  bool removing_{false};
  std::shared_ptr<const ps::PlatformConfig> platform_;
  std::shared_ptr<const ns::TrustedCatalog> catalog_;
  std::string probe_;
  std::unique_ptr<wsl::Agent> agent_;
  std::shared_ptr<sb::Centre> centre_;
  std::unique_ptr<sb::Engine> engine_;
  std::unique_ptr<sb::GuestFiles> guest_files_;
  std::unique_ptr<sb::FilesWindows> files_windows_;
  std::vector<ps::NodeRef> nodes_;
  sb::Store store_;
  fs::path directory_;
  std::thread agent_thread_, sign_in_thread_, stop_thread_;
  bool closing_{false}, exiting_{false}, remembered_{false};
};

App* app = nullptr;

LRESULT CALLBACK window_procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam) noexcept {
  try {
    switch (message) {
      case WM_CREATE:
        app->create(window);
        return 0;
      case WM_SIZE:
        app->layout();
        return 0;
      case WM_DPICHANGED: {
        const auto* r = reinterpret_cast<const RECT*>(lparam);
        SetWindowPos(window, nullptr, r->left, r->top, r->right - r->left, r->bottom - r->top, SWP_NOZORDER | SWP_NOACTIVATE);
        app->dpi_changed(HIWORD(wparam));
        return 0;
      }
      case WM_GETMINMAXINFO: {
        auto* info = reinterpret_cast<MINMAXINFO*>(lparam);
        info->ptMinTrackSize = {app->px(820), app->px(480)};
        return 0;
      }
      case WM_COMMAND:
        if (HIWORD(wparam) == BN_CLICKED || HIWORD(wparam) == CBN_SELCHANGE) app->command(LOWORD(wparam));
        if (HIWORD(wparam) == CBN_SELCHANGE) app->selection_changed();
        return 0;
      case WM_NOTIFY: {
        const auto* hdr = reinterpret_cast<const NMHDR*>(lparam);
        if (hdr->idFrom == List && hdr->code == LVN_ITEMCHANGED) app->selection_changed();
        if (hdr->idFrom == List && hdr->code == NM_DBLCLK) app->command(Open);
        return 0;
      }
      case WM_TIMER:
        app->tick();
        return 0;
      case kAgentReady:
        app->agent_ready(reinterpret_cast<AgentResult*>(lparam));
        return 0;
      case kSignedIn:
        app->signed_in_result(reinterpret_cast<SignInResult*>(lparam));
        return 0;
      case kErased:
        app->erased(reinterpret_cast<std::string*>(lparam), wparam != 0);
        return 0;
      case kStopped:
        app->stopped();
        return 0;
      case kSetupProgress:
        app->setup_progress(reinterpret_cast<std::wstring*>(lparam));
        return 0;
      case kRemoved:
        app->removed(reinterpret_cast<std::wstring*>(lparam));
        return 0;
      case WM_CTLCOLORSTATIC:
        SetBkMode(reinterpret_cast<HDC>(wparam), TRANSPARENT);
        return reinterpret_cast<LRESULT>(GetSysColorBrush(COLOR_WINDOW));
      case WM_CLOSE:
        app->close_requested();
        return 0;
      case WM_DESTROY:
        app->destroyed();
        PostQuitMessage(0);
        return 0;
      default:
        break;
    }
  } catch (const std::exception&) {
    // Never let an exception cross the window procedure.
  }
  return DefWindowProcW(window, message, wparam, lparam);
}
}  // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show) {
  int argc = 0;
  wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  std::array<wchar_t, 32768> self{};
  GetModuleFileNameW(nullptr, self.data(), static_cast<DWORD>(self.size()));
  fs::path trust = fs::path(self.data()).parent_path() / L"trust";
  std::string username;
  bool password_stdin = false, remove_all = false;
  for (int i = 1; argv && i < argc; ++i) {
    const std::wstring_view arg = argv[i];
    if (arg == L"--remove-all-data") remove_all = true;
    else if (arg == L"--trust" && i + 1 < argc) trust = argv[++i];
    else if (arg == L"--username" && i + 1 < argc) username = narrow(argv[++i]);
    else if (arg == L"--password-stdin") password_stdin = true;
  }
  if (argv) LocalFree(argv);

  // One client per Windows session: two would fight over the distribution and
  // its agent. The installer and uninstaller look for these names
  // (AppMutex) to ask for the client to be closed first.
  HANDLE session_mutex = CreateMutexW(nullptr, FALSE, L"OrangeSpace.Client");
  const bool another = session_mutex && GetLastError() == ERROR_ALREADY_EXISTS;
  HANDLE global_mutex = CreateMutexW(nullptr, FALSE, L"Global\\OrangeSpace.Client");
  (void)global_mutex;  // held until exit; may fail when another user's client owns it
  if (another) {
    if (remove_all) return 3;
    if (HWND other = FindWindowW(L"OrangeSpaceWindow", nullptr)) {
      ShowWindow(other, IsIconic(other) ? SW_RESTORE : SW_SHOW);
      SetForegroundWindow(other);
    }
    return 0;
  }
  // The uninstaller's "delete all data" (for the Windows user running it).
  if (remove_all) {
    try {
      ss::remove_all_local_data();
      return 0;
    } catch (const std::exception&) {
      return 1;
    }
  }
  std::shared_ptr<std::string> password;
  if (password_stdin && !username.empty()) {
    password = std::make_shared<std::string>();
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    char c;
    DWORD n = 0;
    while (in && in != INVALID_HANDLE_VALUE && password->size() < 1024 && ReadFile(in, &c, 1, &n, nullptr) && n == 1 &&
           c != '\n')
      *password += c;
    if (!password->empty() && password->back() == '\r') password->pop_back();
  }

  INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES};
  InitCommonControlsEx(&controls);
  App instance_app(trust, username, std::move(password));
  app = &instance_app;
  WNDCLASSEXW type{sizeof(type)};
  type.lpfnWndProc = window_procedure;
  type.hInstance = instance;
  type.lpszClassName = L"OrangeSpaceWindow";
  type.hCursor = LoadCursorW(nullptr, IDC_ARROW);
  type.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(101));
  type.hbrBackground = GetSysColorBrush(COLOR_WINDOW);
  RegisterClassExW(&type);
  HWND window = CreateWindowExW(0, type.lpszClassName, L"橙域 OrangeSpace", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT,
                                CW_USEDEFAULT, 1000, 620, nullptr, nullptr, instance, nullptr);
  if (!window) return 1;
  ShowWindow(window, show);
  MSG message;
  while (GetMessageW(&message, nullptr, 0, 0) > 0) {
    if (!IsDialogMessageW(window, &message)) {
      TranslateMessage(&message);
      DispatchMessageW(&message);
    }
  }
  return 0;
}
