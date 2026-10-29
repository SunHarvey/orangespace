#include "orangespace/broker_win.hpp"
#include "orangespace/model.hpp"

#include <commctrl.h>
#include <windowsx.h>

#include <algorithm>
#include <memory>
#include <thread>

namespace {
constexpr UINT kCompleted = WM_APP + 1;
enum Control : int { User = 100, Refresh, SandboxList, Name, Create, Node, Bind, Open, Close, Delete, Detail, Notice };
struct Completion {
  orangespace::ProcessResult process;
  std::string user;
  bool refresh{};
  bool opening{};
};

class Application {
 public:
  ~Application() { if (worker_.joinable()) worker_.join(); }
  HWND window{};
  LRESULT message(UINT message, WPARAM wparam, LPARAM lparam) {
    switch (message) {
      case WM_CREATE: create_controls(); return 0;
      case WM_SIZE: layout(); return 0;
      case WM_GETMINMAXINFO: {
        auto* info = reinterpret_cast<MINMAXINFO*>(lparam);
        info->ptMinTrackSize = {900, 650}; return 0;
      }
      case WM_COMMAND:
        if (HIWORD(wparam) == BN_CLICKED) command(LOWORD(wparam));
        return 0;
      case WM_NOTIFY:
        if (reinterpret_cast<NMHDR*>(lparam)->idFrom == SandboxList) update_detail();
        return 0;
      case kCompleted: complete(std::unique_ptr<Completion>(reinterpret_cast<Completion*>(lparam))); return 0;
      case WM_CLOSE:
        if (busy_) {
          closing_ = true;
          SetWindowTextW(notice_, L"正在结束当前本机操作，随后关闭窗口……");
          return 0;
        }
        DestroyWindow(window); return 0;
      case WM_DESTROY:
        if (font_) DeleteObject(font_);
        if (title_font_) DeleteObject(title_font_);
        if (background_) DeleteObject(background_);
        PostQuitMessage(0); return 0;
      case WM_CTLCOLORSTATIC: {
        const auto dc = reinterpret_cast<HDC>(wparam);
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, RGB(66, 47, 36));
        return reinterpret_cast<LRESULT>(background_);
      }
      case WM_ERASEBKGND: {
        RECT rect{}; GetClientRect(window, &rect);
        FillRect(reinterpret_cast<HDC>(wparam), &rect, background_); return 1;
      }
      case WM_PAINT: paint(); return 0;
      case WM_DPICHANGED: {
        const auto* rect = reinterpret_cast<RECT*>(lparam);
        SetWindowPos(window, nullptr, rect->left, rect->top, rect->right - rect->left, rect->bottom - rect->top, SWP_NOZORDER);
        layout(); return 0;
      }
    }
    return DefWindowProcW(window, message, wparam, lparam);
  }

 private:
  int px(int value) const { return MulDiv(value, static_cast<int>(GetDpiForWindow(window)), 96); }
  HWND control(const wchar_t* kind, const wchar_t* text, DWORD style, int id) {
    const auto handle = CreateWindowExW(std::wstring_view(kind) == L"EDIT" ? WS_EX_CLIENTEDGE : 0,
                                       kind, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 0, 0,
                                       window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), nullptr);
    SendMessageW(handle, WM_SETFONT, reinterpret_cast<WPARAM>(font_), TRUE);
    return handle;
  }
  HWND label(const wchar_t* text) { return control(L"STATIC", text, SS_LEFT, 0); }
  void create_controls() {
    background_ = CreateSolidBrush(RGB(255, 249, 243));
    font_ = CreateFontW(-px(14), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                       OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Microsoft YaHei UI");
    title_font_ = CreateFontW(-px(27), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                             OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Microsoft YaHei UI");
    user_label_ = label(L"用户 ID（开发阶段，本机工作区标识；服务端登录待接入）");
    user_ = control(L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL, User);
    SendMessageW(user_, EM_SETLIMITTEXT, 36, 0);
    SendMessageW(user_, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"输入节点账号对应的用户 UUID"));
    refresh_ = control(L"BUTTON", L"读取工作区", WS_TABSTOP | BS_PUSHBUTTON, Refresh);
    list_ = control(WC_LISTVIEWW, L"", WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS, SandboxList);
    ListView_SetExtendedListViewStyle(list_, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
    ListView_SetBkColor(list_, RGB(255, 255, 255));
    ListView_SetTextBkColor(list_, RGB(255, 255, 255));
    const wchar_t* columns[] = {L"沙盒", L"绑定节点", L"状态"};
    for (int i = 0; i < 3; ++i) {
      LVCOLUMNW column{}; column.mask = LVCF_TEXT | LVCF_WIDTH;
      column.pszText = const_cast<wchar_t*>(columns[i]); column.cx = px(i == 1 ? 300 : 145);
      ListView_InsertColumn(list_, i, &column);
    }
    name_label_ = label(L"新建沙盒");
    name_ = control(L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL, Name);
    SendMessageW(name_, EM_SETLIMITTEXT, 80, 0);
    SendMessageW(name_, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"例如：深圳工作区"));
    create_ = control(L"BUTTON", L"新建", WS_TABSTOP | BS_PUSHBUTTON, Create);
    node_label_ = label(L"所选沙盒的节点 ID");
    node_ = control(L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL, Node);
    SendMessageW(node_, EM_SETLIMITTEXT, 36, 0);
    SendMessageW(node_, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"输入已配置节点的 UUID"));
    bind_ = control(L"BUTTON", L"绑定节点", WS_TABSTOP | BS_PUSHBUTTON, Bind);
    open_ = control(L"BUTTON", L"打开浏览器", WS_TABSTOP | BS_PUSHBUTTON, Open);
    close_ = control(L"BUTTON", L"关闭沙盒", WS_TABSTOP | BS_PUSHBUTTON, Close);
    delete_ = control(L"BUTTON", L"删除沙盒", WS_TABSTOP | BS_PUSHBUTTON, Delete);
    detail_ = control(L"STATIC", L"选择一个沙盒，查看本机数据和节点归属。", SS_LEFT, Detail);
    files_ = label(L"个人文件区\r\n\r\n同一用户在同一节点共享文件。节点文件 API 已独立提供，客户端文件面板和浏览器上传下载桥尚未接入。");
    notice_ = control(L"STATIC", L"开发版本 · Windows 网络防护尚未完成，所有沙盒浏览器均禁止启动。", SS_LEFT, Notice);
    layout();
  }
  void place(HWND handle, int x, int y, int width, int height) {
    MoveWindow(handle, px(x), px(y), px(width), px(height), TRUE);
  }
  void layout() {
    if (!list_) return;
    RECT rect{}; GetClientRect(window, &rect);
    const int width = MulDiv(rect.right, 96, static_cast<int>(GetDpiForWindow(window)));
    const int height = MulDiv(rect.bottom, 96, static_cast<int>(GetDpiForWindow(window)));
    const int body = std::max(790, width - 48);
    const int left = body - 265;
    place(user_label_, 24, 104, body - 150, 24);
    place(user_, 24, 132, body - 150, 32);
    place(refresh_, width - 158, 132, 134, 32);
    place(list_, 24, 184, left, std::max(180, height - 330));
    const int right_x = 24 + left + 20;
    place(name_label_, right_x, 184, 245, 24);
    place(name_, right_x, 213, 165, 32);
    place(create_, right_x + 175, 213, 70, 32);
    place(node_label_, right_x, 263, 245, 24);
    place(node_, right_x, 292, 245, 32);
    place(bind_, right_x, 334, 245, 32);
    place(open_, right_x, 386, 245, 34);
    place(close_, right_x, 430, 118, 32);
    place(delete_, right_x + 128, 430, 117, 32);
    place(files_, right_x, 484, 245, std::max(90, height - 555));
    place(detail_, 24, height - 130, left, 65);
    place(notice_, 24, height - 48, body, 38);
  }
  std::wstring text(HWND handle) const {
    const int count = GetWindowTextLengthW(handle);
    std::wstring output(static_cast<std::size_t>(count) + 1, L'\0');
    GetWindowTextW(handle, output.data(), count + 1); output.resize(count);
    return output;
  }
  void notice(const std::wstring& message, bool error = false) {
    SetWindowTextW(notice_, message.c_str());
    if (error) MessageBoxW(window, message.c_str(), L"橙域 OrangeSpace", MB_OK | MB_ICONINFORMATION);
  }
  std::optional<orangespace::Sandbox> selection() const {
    const int index = ListView_GetNextItem(list_, -1, LVNI_SELECTED);
    if (index < 0 || static_cast<std::size_t>(index) >= sandboxes_.size()) return std::nullopt;
    return sandboxes_[static_cast<std::size_t>(index)];
  }
  void update_detail() {
    const auto selected = selection();
    if (!selected) return;
    SetWindowTextW(node_, orangespace::widen(selected->node_id).c_str());
    const auto detail = L"沙盒 ID：" + orangespace::widen(selected->id) + L"\r\n本机 Profile：" + orangespace::widen(selected->profile);
    SetWindowTextW(detail_, detail.c_str());
  }
  void set_busy(bool busy) {
    busy_ = busy;
    for (auto handle : {user_, refresh_, list_, name_, create_, node_, bind_, open_, close_, delete_}) EnableWindow(handle, !busy);
  }
  void execute(std::vector<std::wstring> arguments, const std::string& user, bool refresh_after = false, bool opening = false) {
    if (busy_) return;
    if (worker_.joinable()) worker_.join();
    set_busy(true); notice(L"正在处理本机工作区……");
    const auto target = window;
    worker_ = std::thread([target, arguments = std::move(arguments), user, refresh_after, opening] {
      auto result = std::make_unique<Completion>();
      result->user = user; result->refresh = refresh_after; result->opening = opening;
      try { result->process = orangespace::run_broker(arguments); }
      catch (const std::exception&) { result->process.failure = L"无法执行本机组件，请检查安装与文件权限。"; }
      auto* message = result.release();
      if (!PostMessageW(target, kCompleted, 0, reinterpret_cast<LPARAM>(message))) delete message;
    });
  }
  void command(int id) {
    if (busy_) return;
    const auto user_wide = text(user_);
    auto user = orangespace::narrow(user_wide);
    if (!orangespace::valid_uuid(user)) { notice(L"请先输入有效的用户 UUID。", true); return; }
    user = orangespace::canonical_uuid(user);
    if (id == Refresh) { execute({L"list", L"--user", user_wide}, user); return; }
    if (id == Create) {
      const auto name = text(name_);
      if (name.empty()) { notice(L"请输入沙盒名称。", true); return; }
      execute({L"create", L"--user", user_wide, L"--name", name}, user, true); return;
    }
    const auto selected = selection();
    if (!selected || selected->user_id != user) {
      notice(L"请读取当前用户的工作区，并选择一个沙盒。", true); return;
    }
    std::vector<std::wstring> arguments;
    if (id == Bind) {
      const auto node = text(node_);
      if (!orangespace::valid_uuid(orangespace::narrow(node))) { notice(L"请输入有效的节点 UUID。", true); return; }
      arguments = {L"bind", L"--user", user_wide, L"--sandbox", orangespace::widen(selected->id), L"--node", node};
    } else if (id == Delete) {
      if (MessageBoxW(window, L"删除此沙盒的本机浏览器数据、临时文件和任务？\r\nLinux 上共享的个人文件将保留。", L"删除沙盒", MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) != IDYES) return;
      arguments = {L"delete", L"--user", user_wide, L"--sandbox", orangespace::widen(selected->id)};
    } else if (id == Close || id == Open) {
      arguments = {id == Open ? L"open" : L"close", L"--user", user_wide, L"--sandbox", orangespace::widen(selected->id)};
    } else return;
    execute(std::move(arguments), user, id != Open, id == Open);
  }
  void complete(std::unique_ptr<Completion> completion) {
    if (worker_.joinable()) worker_.join();
    set_busy(false);
    if (closing_) { DestroyWindow(window); return; }
    try {
      if (!completion->process.failure.empty()) { notice(completion->process.failure, true); return; }
      const auto response = orangespace::parse_response(completion->process.output, completion->user);
      if (completion->opening) {
        // A local broker claiming success cannot unlock the future host.
        notice(orangespace::widen(orangespace::browser_launch_decision().reason), true); return;
      }
      if (!response.ok || completion->process.exit_code != 0) {
        notice(response.message.empty() ? L"本机操作失败。" : orangespace::widen(response.message), true); return;
      }
      if (completion->refresh) {
        execute({L"list", L"--user", orangespace::widen(completion->user)}, completion->user); return;
      }
      sandboxes_ = response.sandboxes;
      ListView_DeleteAllItems(list_);
      for (std::size_t i = 0; i < sandboxes_.size(); ++i) {
        const auto& sandbox = sandboxes_[i];
        auto name = orangespace::widen(sandbox.name);
        auto node = sandbox.node_id.empty() ? std::wstring(L"未绑定") : orangespace::widen(sandbox.node_id);
        auto state = sandbox.state == "closed" ? std::wstring(L"已关闭") : std::wstring(L"防护未就绪");
        LVITEMW item{}; item.mask = LVIF_TEXT; item.iItem = static_cast<int>(i); item.pszText = name.data();
        const auto row = ListView_InsertItem(list_, &item);
        ListView_SetItemText(list_, row, 1, node.data()); ListView_SetItemText(list_, row, 2, state.data());
      }
      SetWindowTextW(detail_, L"选择一个沙盒，查看本机数据和节点归属。");
      notice(L"工作区已读取。网络防护尚未完成，浏览器保持禁止启动。");
    } catch (const std::exception&) {
      notice(L"本机组件响应无效，已停止此次操作。", true);
    }
  }
  void paint() {
    PAINTSTRUCT paint{}; const auto dc = BeginPaint(window, &paint);
    RECT client{}; GetClientRect(window, &client);
    RECT header{0, 0, client.right, px(84)};
    const auto orange = CreateSolidBrush(RGB(249, 117, 22)); FillRect(dc, &header, orange); DeleteObject(orange);
    SetBkMode(dc, TRANSPARENT); SetTextColor(dc, RGB(255, 255, 255));
    SelectObject(dc, title_font_); const wchar_t* title = L"橙域 OrangeSpace";
    TextOutW(dc, px(24), px(14), title, static_cast<int>(wcslen(title)));
    SelectObject(dc, font_); const wchar_t* slogan = L"远方的网络，眼前的工作空间。";
    TextOutW(dc, px(26), px(54), slogan, static_cast<int>(wcslen(slogan)));
    EndPaint(window, &paint);
  }
  HWND user_label_{}, user_{}, refresh_{}, list_{}, name_label_{}, name_{}, create_{}, node_label_{}, node_{}, bind_{}, open_{}, close_{}, delete_{}, detail_{}, files_{}, notice_{};
  HFONT font_{}, title_font_{};
  HBRUSH background_{};
  std::vector<orangespace::Sandbox> sandboxes_;
  std::thread worker_;
  bool busy_{}, closing_{};
};

LRESULT CALLBACK window_procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
  Application* app = reinterpret_cast<Application*>(GetWindowLongPtrW(window, GWLP_USERDATA));
  if (message == WM_NCCREATE) {
    app = static_cast<Application*>(reinterpret_cast<CREATESTRUCTW*>(lparam)->lpCreateParams);
    app->window = window; SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(app));
  }
  return app ? app->message(message, wparam, lparam) : DefWindowProcW(window, message, wparam, lparam);
}
}  // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show) {
  SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
  INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES}; InitCommonControlsEx(&controls);
  Application app;
  WNDCLASSEXW type{}; type.cbSize = sizeof(type); type.hInstance = instance;
  type.lpfnWndProc = window_procedure; type.lpszClassName = L"OrangeSpaceManager";
  type.hCursor = LoadCursorW(nullptr, IDC_ARROW); type.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
  if (!RegisterClassExW(&type)) return 1;
  const auto window = CreateWindowExW(0, type.lpszClassName, L"橙域 OrangeSpace · 开发版本", WS_OVERLAPPEDWINDOW,
                                     CW_USEDEFAULT, CW_USEDEFAULT, 1120, 790, nullptr, nullptr, instance, &app);
  if (!window) return 1;
  ShowWindow(window, show); UpdateWindow(window);
  MSG message{};
  while (GetMessageW(&message, nullptr, 0, 0) > 0) {
    if (!IsDialogMessageW(window, &message)) { TranslateMessage(&message); DispatchMessageW(&message); }
  }
  return static_cast<int>(message.wParam);
}
