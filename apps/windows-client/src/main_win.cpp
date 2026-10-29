#include "orangespace/broker_win.hpp"
#include "orangespace/model.hpp"
#include "orangespace/node_session.hpp"
#include "orangespace/workspace_auth.hpp"

#include <commctrl.h>
#include <windowsx.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <thread>

namespace {
namespace ns = orangespace::node_session;
using Auth = orangespace::WorkspaceAuth<ns::NodeSession>;
std::int64_t now() {
  return std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
}
enum Control : int { TrustPath = 100, LoadTrust, Alias, Username, Password, Login, Logout,
  Refresh, SandboxList, Name, Create, Bind, Open, Close, Delete };
enum class Job { catalog, login, broker };
struct Completion {
  Job job{};
  std::uint64_t generation{};
  Auth::LoginTicket login{};
  Auth::Operation operation{};
  std::unique_ptr<ns::TrustedCatalog> catalog;
  std::unique_ptr<ns::NodeSession> session;
  orangespace::ProcessResult process;
  bool refresh{};
  bool failed{};
};
// No worker touches an HWND or Application. Destruction can return immediately;
// a late result is owned by the mailbox, never posted to a reused HWND.
struct Mailbox {
  std::mutex mutex;
  std::unique_ptr<Completion> result;
  std::atomic<bool> cancelled{false};
};
struct PasswordBuffer {
  std::vector<wchar_t> wide;
  std::vector<char> utf8;
  ~PasswordBuffer() {
    ns::detail::wipe(wide.data(), wide.size() * sizeof(wchar_t));
    ns::detail::wipe(utf8.data(), utf8.size());
  }
  PasswordBuffer(const PasswordBuffer&) = delete;
  PasswordBuffer() = default;
  std::string_view view() const { return {utf8.data(), utf8.size()}; }
};

class Application {
 public:
  HWND window{};
  LRESULT message(UINT message, WPARAM wparam, LPARAM lparam) {
    switch (message) {
      case WM_CREATE: create_controls(); SetTimer(window, 1, 100, nullptr); return 0;
      case WM_TIMER: poll(); return 0;
      case WM_SIZE: layout(); return 0;
      case WM_GETMINMAXINFO: {
        auto* info = reinterpret_cast<MINMAXINFO*>(lparam);
        info->ptMinTrackSize = {px(940), px(740)}; return 0;
      }
      case WM_COMMAND:
        if (LOWORD(wparam) == Alias && HIWORD(wparam) == CBN_SELCHANGE) {
          auth_.select(alias()); ++generation_; clear_rows(); sync_identity();
        } else if (HIWORD(wparam) == BN_CLICKED) {
          try { command(LOWORD(wparam)); }
          catch (...) { notice(L"操作未完成；请检查输入和本机组件。", true); }
        }
        return 0;
      case WM_NOTIFY:
        if (reinterpret_cast<NMHDR*>(lparam)->idFrom == SandboxList) update_detail();
        return 0;
      case WM_CLOSE:
        auth_.close(); if (mailbox_) mailbox_->cancelled = true;
        SetWindowTextW(password_, L""); SendMessageW(password_, EM_EMPTYUNDOBUFFER, 0, 0);
        DestroyWindow(window); return 0;
      case WM_DESTROY:
        KillTimer(window, 1);
        if (font_) DeleteObject(font_);
        if (title_font_) DeleteObject(title_font_);
        if (background_) DeleteObject(background_);
        PostQuitMessage(0); return 0;
      case WM_CTLCOLORSTATIC: {
        auto dc = reinterpret_cast<HDC>(wparam); SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, RGB(66, 47, 36)); return reinterpret_cast<LRESULT>(background_);
      }
      case WM_ERASEBKGND: {
        RECT rect{}; GetClientRect(window, &rect);
        FillRect(reinterpret_cast<HDC>(wparam), &rect, background_); return 1;
      }
      case WM_PAINT: paint(); return 0;
      case WM_DPICHANGED: {
        const auto* rect = reinterpret_cast<RECT*>(lparam);
        SetWindowPos(window, nullptr, rect->left, rect->top, rect->right - rect->left,
                     rect->bottom - rect->top, SWP_NOZORDER);
        layout(); return 0;
      }
    }
    return DefWindowProcW(window, message, wparam, lparam);
  }
 private:
  int px(int value) const { return MulDiv(value, static_cast<int>(GetDpiForWindow(window)), 96); }
  HWND control(const wchar_t* kind, const wchar_t* title, DWORD style, int id = 0) {
    auto handle = CreateWindowExW(std::wstring_view(kind) == L"EDIT" ? WS_EX_CLIENTEDGE : 0,
        kind, title, WS_CHILD | WS_VISIBLE | style, 0, 0, 0, 0, window,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), nullptr);
    SendMessageW(handle, WM_SETFONT, reinterpret_cast<WPARAM>(font_), TRUE); return handle;
  }
  HWND label(const wchar_t* title) { return control(L"STATIC", title, SS_LEFT); }
  HWND button(const wchar_t* title, int id) { return control(L"BUTTON", title, WS_TABSTOP | BS_PUSHBUTTON, id); }
  HWND edit(int id, int limit, DWORD extra = 0) {
    auto h = control(L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL | extra, id);
    SendMessageW(h, EM_SETLIMITTEXT, limit, 0); return h;
  }
  void create_controls() {
    background_ = CreateSolidBrush(RGB(255, 249, 243));
    font_ = CreateFontW(-px(14), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Microsoft YaHei UI");
    title_font_ = CreateFontW(-px(27), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Microsoft YaHei UI");
    trust_label_ = label(L"管理员保护的节点清单（显式绝对路径；不含凭据）");
    trust_ = edit(TrustPath, 240); load_ = button(L"验证并载入", LoadTrust);
    alias_label_ = label(L"可信节点别名");
    alias_ = control(WC_COMBOBOXW, L"", WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL, Alias);
    username_label_ = label(L"节点用户名"); username_ = edit(Username, 64);
    password_label_ = label(L"密码（仅内存）"); password_ = edit(Password, 1024, ES_PASSWORD);
    login_ = button(L"登录节点", Login); logout_ = button(L"退出全部登录", Logout);
    identity_ = label(L"未登录；不会使用手工 UUID 作为身份。");
    refresh_ = button(L"读取工作区", Refresh);
    list_ = control(WC_LISTVIEWW, L"", WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS, SandboxList);
    ListView_SetExtendedListViewStyle(list_, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
    ListView_SetBkColor(list_, RGB(255, 255, 255)); ListView_SetTextBkColor(list_, RGB(255, 255, 255));
    const wchar_t* columns[] = {L"沙盒", L"绑定节点", L"状态"};
    for (int i = 0; i < 3; ++i) {
      LVCOLUMNW column{}; column.mask = LVCF_TEXT | LVCF_WIDTH;
      column.pszText = const_cast<wchar_t*>(columns[i]); column.cx = px(i == 1 ? 290 : 120);
      ListView_InsertColumn(list_, i, &column);
    }
    name_label_ = label(L"新建沙盒"); name_ = edit(Name, 80); create_ = button(L"新建", Create);
    node_label_ = label(L"当前登录的节点（不可编辑）"); node_ = label(L"未登录");
    bind_ = button(L"绑定到当前登录节点", Bind); open_ = button(L"打开浏览器（已阻止）", Open);
    close_ = button(L"关闭沙盒", Close); delete_ = button(L"删除沙盒", Delete);
    detail_ = label(L"请选择工作区中的沙盒。");
    files_ = label(L"账号按节点独立；同名不代表同一用户。\r\n绑定要求服务端用户 UUID 完全相同。\r\n\r\n个人文件面板、持久登录及刷新尚未实现。");
    notice_ = label(L"Windows 网络防护尚未完成；浏览器始终禁止启动。");
    sync_identity(); layout();
  }
  void place(HWND h, int x, int y, int width, int height) { MoveWindow(h, px(x), px(y), px(width), px(height), TRUE); }
  void layout() {
    if (!list_) return;
    RECT rect{}; GetClientRect(window, &rect);
    const int width = MulDiv(rect.right, 96, static_cast<int>(GetDpiForWindow(window)));
    const int height = MulDiv(rect.bottom, 96, static_cast<int>(GetDpiForWindow(window)));
    const int body = std::max(880, width - 48), left = body - 275, right = left + 44;
    place(trust_label_, 24, 96, body, 22); place(trust_, 24, 120, body - 145, 30);
    place(load_, 24 + body - 135, 120, 135, 30);
    const int col = (body - 310) / 3;
    place(alias_label_, 24, 160, col, 22); place(alias_, 24, 184, col, 240);
    place(username_label_, 34 + col, 160, col, 22); place(username_, 34 + col, 184, col, 30);
    place(password_label_, 44 + col * 2, 160, col, 22); place(password_, 44 + col * 2, 184, col, 30);
    place(login_, body - 266, 184, 135, 30); place(logout_, body - 121, 184, 145, 30);
    place(identity_, 24, 226, body - 155, 58); place(refresh_, body - 121, 234, 145, 32);
    place(list_, 24, 300, left, std::max(180, height - 440));
    place(name_label_, right, 300, 255, 22); place(name_, right, 326, 170, 30); place(create_, right + 180, 326, 75, 30);
    place(node_label_, right, 370, 255, 22); place(node_, right, 397, 255, 44);
    place(bind_, right, 447, 255, 30); place(open_, right, 487, 255, 32);
    place(close_, right, 529, 122, 30); place(delete_, right + 132, 529, 123, 30);
    ShowWindow(files_, height >= 760 ? SW_SHOW : SW_HIDE);
    place(files_, right, 575, 255, std::max(100, height - 630));
    place(detail_, 24, height - 128, left, 66); place(notice_, 24, height - 50, body, 42);
  }
  std::wstring text(HWND handle) const {
    const int count = GetWindowTextLengthW(handle);
    std::wstring out(static_cast<std::size_t>(count) + 1, L'\0');
    GetWindowTextW(handle, out.data(), count + 1); out.resize(count); return out;
  }
  std::string alias() const { return orangespace::narrow(text(alias_)); }
  void notice(const std::wstring& value, bool error = false) {
    SetWindowTextW(notice_, value.c_str());
    if (error) MessageBoxW(window, value.c_str(), L"橙域 OrangeSpace", MB_OK | MB_ICONINFORMATION);
  }
  void clear_rows() {
    sandboxes_.clear(); ListView_DeleteAllItems(list_); SetWindowTextW(detail_, L"请选择工作区中的沙盒。");
  }
  std::optional<orangespace::Sandbox> selection() const {
    int index = ListView_GetNextItem(list_, -1, LVNI_SELECTED);
    if (index < 0 || static_cast<std::size_t>(index) >= sandboxes_.size()) return {};
    return sandboxes_[static_cast<std::size_t>(index)];
  }
  void update_detail() {
    auto s = selection(); if (!s) return;
    auto value = L"沙盒 ID：" + orangespace::widen(s->id) + L"\r\n本机 Profile：" + orangespace::widen(s->profile);
    SetWindowTextW(detail_, value.c_str());
  }
  void sync_identity() {
    const auto* s = auth_.active(now());
    const bool authorized = s && auth_.authorize(auth_.workspace_user(), "", s->identity().node_id, now());
    if (!s) {
      SetWindowTextW(identity_, L"未登录或登录已过期；请重新登录。退出不删除本机数据。");
      SetWindowTextW(node_, L"未登录");
      if (had_identity_) clear_rows();
    } else {
      auto value = L"用户：" + orangespace::widen(s->identity().username) + L"  UUID：" + orangespace::widen(s->identity().user_id);
      if (!authorized) value += L"\r\n不同节点返回不同用户 UUID，禁止混用；退出全部登录后可切换账号。";
      SetWindowTextW(identity_, value.c_str()); SetWindowTextW(node_, orangespace::widen(s->identity().node_id).c_str());
    }
    had_identity_ = s != nullptr;
    for (auto h : {trust_, load_, alias_, username_, password_}) EnableWindow(h, !busy_);
    EnableWindow(login_, !busy_ && catalog_ && !alias().empty());
    for (auto h : {refresh_, list_, name_, create_, bind_, close_, delete_}) EnableWindow(h, !busy_ && authorized);
    EnableWindow(open_, !busy_); // Always a local denial; never dispatches an open command.
    EnableWindow(logout_, TRUE);
  }
  template<class Work> void start(Work work) {
    auto box = std::make_shared<Mailbox>();
    const auto generation = generation_;
    // Thread creation failure leaves UI usable and captured secret owners wiped.
    std::thread worker([box, generation, work = std::move(work)]() mutable {
      auto result = std::make_unique<Completion>(); result->generation = generation;
      try { work(*result, *box); } catch (...) { result->failed = true; }
      std::lock_guard<std::mutex> lock(box->mutex); box->result = std::move(result);
    });
    worker.detach(); mailbox_ = std::move(box); busy_ = true; sync_identity();
  }
  void logout() {
    ++generation_; auth_.logout(); if (mailbox_) mailbox_->cancelled = true;
    SetWindowTextW(password_, L""); SendMessageW(password_, EM_EMPTYUNDOBUFFER, 0, 0);
    SetWindowTextW(username_, L""); clear_rows(); sync_identity();
    notice(L"全部本机登录已清除；不删除沙盒或远端数据。已提交的本机操作不作回滚；服务器令牌未撤销。");
  }
  void command(int id) {
    if (id == Logout) { logout(); return; }
    if (id == Open) { notice(orangespace::widen(orangespace::browser_launch_decision().reason), true); return; }
    if (busy_) return;
    if (id == LoadTrust) {
      auto path = text(trust_); logout(); catalog_.reset(); SendMessageW(alias_, CB_RESETCONTENT, 0, 0);
      start([path = std::move(path)](Completion& out, Mailbox&) {
        out.job = Job::catalog; out.catalog.reset(new ns::TrustedCatalog(ns::TrustedCatalog::load(path)));
      }); return;
    }
    if (id == Login) {
      auto secret = std::make_shared<PasswordBuffer>();
      const int length = GetWindowTextLengthW(password_);
      secret->wide.resize(static_cast<std::size_t>(length) + 1);
      GetWindowTextW(password_, secret->wide.data(), length + 1);
      SetWindowTextW(password_, L""); // Clear immediately, before validation/network dispatch.
      SendMessageW(password_, EM_EMPTYUNDOBUFFER, 0, 0);
      if (!catalog_ || alias().empty() || length == 0) { notice(L"请选择已验证节点并填写用户名和密码。", true); return; }
      const int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, secret->wide.data(), length, nullptr, 0, nullptr, nullptr);
      if (!bytes) throw std::runtime_error("invalid password encoding");
      secret->utf8.resize(static_cast<std::size_t>(bytes));
      if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, secret->wide.data(), length, secret->utf8.data(), bytes, nullptr, nullptr))
        throw std::runtime_error("invalid password encoding");
      ns::detail::wipe(secret->wide.data(), secret->wide.size() * sizeof(wchar_t));
      auto username = orangespace::narrow(text(username_));
      auto ticket = auth_.begin_login(alias()); auto catalog = catalog_;
      start([catalog, ticket, username = std::move(username), secret](Completion& out, Mailbox& box) {
        out.job = Job::login; out.login = ticket;
        if (!box.cancelled) out.session.reset(new ns::NodeSession(ns::NodeSession::login(*catalog, ticket.alias, username, secret->view())));
      }); notice(L"正在验证节点并登录……密码不会进入本机命令或日志。"); return;
    }
    const auto* s = auth_.active(now());
    if (!s || !auth_.authorize(auth_.workspace_user(), "", s->identity().node_id, now())) {
      notice(L"请先登录。不同节点的不同用户 UUID 不可混用，即使用户名相同。", true); return;
    }
    const auto user = auth_.workspace_user(); const auto user_wide = orangespace::widen(user);
    auto selected = selection();
    std::vector<std::wstring> args;
    if (id == Refresh) args = {L"list", L"--user", user_wide};
    else if (id == Create) {
      auto name = text(name_); if (name.empty()) { notice(L"请输入沙盒名称。", true); return; }
      args = {L"create", L"--user", user_wide, L"--name", name};
    } else {
      if (!selected || !auth_.authorize(selected->user_id, selected->node_id, s->identity().node_id, now()) ||
          (id != Bind && !auth_.manage(selected->user_id, selected->node_id, now()))) {
        notice(L"操作被拒绝：请选择同一认证用户的沙盒，并登录其绑定节点；换绑还需同时登录目标节点。", true); return;
      }
      if (id == Delete && MessageBoxW(window, L"删除此沙盒的本机数据和任务？Linux 个人文件保留。", L"删除沙盒",
          MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) != IDYES) return;
      if (id != Bind && id != Delete && id != Close) return;
      args = {id == Bind ? L"bind" : id == Delete ? L"delete" : L"close", L"--user", user_wide,
          L"--sandbox", orangespace::widen(selected->id)};
      if (id == Bind) { args.push_back(L"--node"); args.push_back(orangespace::widen(s->identity().node_id)); }
    }
    // Recheck after any confirmation dialog (expiry can occur in its message loop).
    auto op = auth_.operation(now(), (id == Refresh || id == Create || !selected) ? "" : selected->node_id);
    if (!auth_.current(op, now())) { sync_identity(); return; }
    const bool refresh = id != Refresh;
    start([args = std::move(args), op, refresh](Completion& out, Mailbox& box) {
      out.job = Job::broker; out.operation = op; out.refresh = refresh;
      if (box.cancelled || now() >= op.expiry) { out.failed = true; return; }
      out.process = orangespace::run_broker(args); // UUIDs only; no password/token IPC.
    }); notice(L"正在处理已认证工作区的本机元数据……");
  }
  void poll() {
    if (!busy_) { sync_identity(); return; }
    std::unique_ptr<Completion> out;
    { std::lock_guard<std::mutex> lock(mailbox_->mutex); out = std::move(mailbox_->result); }
    if (!out) { sync_identity(); return; }
    busy_ = false; mailbox_.reset();
    if (out->generation != generation_) { sync_identity(); return; }
    try {
      if (out->failed) { notice(L"操作失败：请检查节点、账号或受保护清单；不会自动重试。", true); sync_identity(); return; }
      if (out->job == Job::catalog) {
        catalog_ = std::shared_ptr<ns::TrustedCatalog>(std::move(out->catalog));
        for (const auto& name : catalog_->names()) {
          const auto wide = orangespace::widen(name); SendMessageW(alias_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(wide.c_str()));
        }
        SendMessageW(alias_, CB_SETCURSEL, 0, 0); auth_.select(alias()); notice(L"清单验证通过；请选择节点登录。");
      } else if (out->job == Job::login) {
        if (auth_.finish_login(out->login, std::move(out->session), now())) {
          clear_rows(); notice(L"节点登录已验证；会话只保存在内存，浏览器仍禁止启动。");
        }
      } else if (auth_.current(out->operation, now())) {
        if (!out->process.failure.empty()) throw std::runtime_error("local process failed");
        const auto response = orangespace::parse_response(out->process.output, out->operation.user);
        if (!response.ok || out->process.exit_code != 0) throw std::runtime_error("local operation failed");
        if (out->refresh) { command(Refresh); return; }
        sandboxes_ = response.sandboxes; ListView_DeleteAllItems(list_);
        for (std::size_t i = 0; i < sandboxes_.size(); ++i) {
          const auto& sandbox = sandboxes_[i]; auto name = orangespace::widen(sandbox.name);
          auto node = sandbox.node_id.empty() ? std::wstring(L"未绑定") : orangespace::widen(sandbox.node_id);
          auto state = sandbox.state == "closed" ? std::wstring(L"已关闭") : std::wstring(L"防护未就绪");
          LVITEMW item{}; item.mask = LVIF_TEXT; item.iItem = static_cast<int>(i); item.pszText = name.data();
          auto row = ListView_InsertItem(list_, &item);
          ListView_SetItemText(list_, row, 1, node.data()); ListView_SetItemText(list_, row, 2, state.data());
        }
        notice(L"工作区已读取。原有沙盒数据保持不变，浏览器仍禁止启动。");
      } else notice(L"登录已失效；已忽略迟到结果，请重新登录并读取工作区。");
    } catch (...) { notice(L"响应无效或本机操作失败；未采用此结果。", true); }
    sync_identity();
  }
  void paint() {
    PAINTSTRUCT paint{}; auto dc = BeginPaint(window, &paint); RECT client{}; GetClientRect(window, &client);
    RECT header{0, 0, client.right, px(84)}; auto orange = CreateSolidBrush(RGB(249, 117, 22));
    FillRect(dc, &header, orange); DeleteObject(orange); SetBkMode(dc, TRANSPARENT); SetTextColor(dc, RGB(255, 255, 255));
    SelectObject(dc, title_font_); const wchar_t* title = L"橙域 OrangeSpace";
    TextOutW(dc, px(24), px(14), title, static_cast<int>(wcslen(title)));
    SelectObject(dc, font_); const wchar_t* slogan = L"远方的网络，眼前的工作空间。";
    TextOutW(dc, px(26), px(54), slogan, static_cast<int>(wcslen(slogan))); EndPaint(window, &paint);
  }
  HWND trust_label_{}, trust_{}, load_{}, alias_label_{}, alias_{}, username_label_{}, username_{}, password_label_{}, password_{},
      login_{}, logout_{}, identity_{}, refresh_{}, list_{}, name_label_{}, name_{}, create_{}, node_label_{}, node_{},
      bind_{}, open_{}, close_{}, delete_{}, detail_{}, files_{}, notice_{};
  HFONT font_{}, title_font_{}; HBRUSH background_{};
  std::vector<orangespace::Sandbox> sandboxes_;
  std::shared_ptr<ns::TrustedCatalog> catalog_;
  std::shared_ptr<Mailbox> mailbox_;
  Auth auth_;
  std::uint64_t generation_{};
  bool busy_{}, had_identity_{};
};
LRESULT CALLBACK window_procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
  auto* app = reinterpret_cast<Application*>(GetWindowLongPtrW(window, GWLP_USERDATA));
  if (message == WM_NCCREATE) {
    app = static_cast<Application*>(reinterpret_cast<CREATESTRUCTW*>(lparam)->lpCreateParams);
    app->window = window; SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(app));
  }
  return app ? app->message(message, wparam, lparam) : DefWindowProcW(window, message, wparam, lparam);
}
} // namespace
int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show) {
  SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
  INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES}; InitCommonControlsEx(&controls);
  Application app;
  WNDCLASSEXW type{}; type.cbSize = sizeof(type); type.hInstance = instance; type.lpfnWndProc = window_procedure;
  type.lpszClassName = L"OrangeSpaceManager"; type.hCursor = LoadCursorW(nullptr, IDC_ARROW); type.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
  if (!RegisterClassExW(&type)) return 1;
  auto window = CreateWindowExW(0, type.lpszClassName, L"橙域 OrangeSpace · 开发版本", WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, CW_USEDEFAULT, 1120, 900, nullptr, nullptr, instance, &app);
  if (!window) return 1;
  ShowWindow(window, show); UpdateWindow(window); MSG message{};
  while (GetMessageW(&message, nullptr, 0, 0) > 0) {
    if (!IsDialogMessageW(window, &message)) { TranslateMessage(&message); DispatchMessageW(&message); }
  }
  return static_cast<int>(message.wParam);
}
