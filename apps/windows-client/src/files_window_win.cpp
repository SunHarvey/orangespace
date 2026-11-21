#include "orangespace/files_window.hpp"

#include <bcrypt.h>
#include <commctrl.h>

#include <algorithm>
#include <atomic>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

namespace orangespace::sandbox {
namespace fs = std::filesystem;

namespace {
constexpr UINT kDone = WM_APP + 40;
constexpr UINT_PTR kProgress = 7;
constexpr wchar_t kClass[] = L"OrangeSpaceFilesWindow";
enum Id : int { NodeUp = 200, NodeRefresh, NodeList, GuestRefresh, GuestList, ToSandbox, ToNode, Cancel };

std::wstring widen(std::string_view s) {
  const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
  std::wstring out(n > 0 ? n : 0, L'\0');
  if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
  return out;
}

std::wstring size_text(std::uint64_t bytes) {
  wchar_t b[32];
  if (bytes < 1024) swprintf(b, 32, L"%llu B", static_cast<unsigned long long>(bytes));
  else if (bytes < 1024ull * 1024) swprintf(b, 32, L"%.1f KB", bytes / 1024.0);
  else if (bytes < 1024ull * 1024 * 1024) swprintf(b, 32, L"%.1f MB", bytes / 1048576.0);
  else swprintf(b, 32, L"%.2f GB", bytes / 1073741824.0);
  return b;
}

std::wstring time_text(std::int64_t seconds) {
  if (seconds <= 0) return L"—";
  const auto ticks = static_cast<ULONGLONG>(seconds) * 10000000ULL + 116444736000000000ULL;
  FILETIME utc{static_cast<DWORD>(ticks), static_cast<DWORD>(ticks >> 32)}, local{};
  SYSTEMTIME t{};
  if (!FileTimeToLocalFileTime(&utc, &local) || !FileTimeToSystemTime(&local, &t)) return L"—";
  wchar_t b[32];
  swprintf(b, 32, L"%04u-%02u-%02u %02u:%02u", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute);
  return b;
}

std::wstring random_leaf() {
  unsigned char r[16];
  if (BCryptGenRandom(nullptr, r, sizeof r, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) throw std::runtime_error("no randomness");
  static constexpr wchar_t hex[] = L"0123456789abcdef";
  std::wstring out = L"copy-";
  for (auto b : r) {
    out += hex[b >> 4];
    out += hex[b & 15];
  }
  return out;
}

std::string parent_of(const std::string& dir) {
  const auto at = dir.rfind('/');
  return at == std::string::npos ? std::string() : dir.substr(0, at);
}

std::string joined(const std::string& dir, const std::string& name) { return dir.empty() ? name : dir + "/" + name; }

bool cancelled(const std::exception& e) {
  return dynamic_cast<const files::Cancelled*>(&e) || std::string_view(e.what()) == "cancelled";
}

// Plain words; the raw reason goes to the log.
std::wstring reason(const std::exception& e) {
  const std::string what = e.what();
  if (cancelled(e)) return L"已取消。";
  if (what.find("no desktop data") != std::string::npos) return L"这个沙盒还没有桌面数据，请先打开一次。";
  if (what.find("invalid file name") != std::string::npos) return L"沙盒不接受这个文件名（不能以点开头，不能含斜杠）。";
  if (what.find("Downloads folder is not a directory") != std::string::npos) return L"沙盒里的“下载”不是文件夹。";
  if (what.find("Centre HTTP 401") != std::string::npos) return L"中心登录已失效，请退出后重新登录。";
  if (what.find("WSL agent") != std::string::npos) return L"WSL 已停止，请重新打开橙域。";
  return L"没有完成：" + widen(what.substr(0, 160));
}

void set_text(HWND list, int row, int column, const std::wstring& text) {
  ListView_SetItemText(list, row, column, const_cast<wchar_t*>(text.c_str()));
}

int selected_row(HWND list) { return ListView_GetNextItem(list, -1, LVNI_SELECTED); }
}  // namespace

class FilesWindow {
 public:
  FilesWindow(FilesWindows& owner, FilesTarget target) : owner_(owner), target_(std::move(target)) {
    static const bool registered = [] {
      WNDCLASSEXW type{sizeof(type)};
      type.lpfnWndProc = &FilesWindow::procedure;
      type.hInstance = GetModuleHandleW(nullptr);
      type.lpszClassName = kClass;
      type.hCursor = LoadCursorW(nullptr, IDC_ARROW);
      type.hIcon = LoadIconW(type.hInstance, MAKEINTRESOURCEW(101));
      type.hbrBackground = GetSysColorBrush(COLOR_WINDOW);
      return RegisterClassExW(&type) != 0;
    }();
    (void)registered;
    const auto title = widen(target_.sandbox_name) + L" · 文件";
    hwnd_ = CreateWindowExW(0, kClass, title.c_str(), WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 980, 600,
                            owner_.owner_, nullptr, GetModuleHandleW(nullptr), this);
    if (!hwnd_) throw std::runtime_error("cannot create the files window");
  }

  ~FilesWindow() {
    stop_worker();
    if (hwnd_) {
      HWND h = hwnd_;
      hwnd_ = nullptr;
      SetWindowLongPtrW(h, GWLP_USERDATA, 0);
      DestroyWindow(h);
    }
    if (font_) DeleteObject(font_);
  }

  void show() {
    if (IsIconic(hwnd_)) ShowWindow(hwnd_, SW_RESTORE);
    ShowWindow(hwnd_, SW_SHOW);
    SetForegroundWindow(hwnd_);
  }

  // From the owner: cancel, wait, close (the owner then drops this object).
  void stop_worker() noexcept {
    cancel_ = true;
    if (worker_.joinable()) worker_.join();
  }

 private:
  enum class Kind { Refresh, ToSandbox, ToNode };
  struct Job {
    Kind kind{Kind::Refresh};
    bool node{true}, guest{true};
    std::string node_dir;
    files::Entry entry;  // ToSandbox
    GuestFile file;      // ToNode
  };
  struct Result {
    std::wstring message;
    std::optional<std::vector<files::Entry>> node;
    std::string node_dir;
    std::optional<std::vector<GuestFile>> guest;
  };

  static LRESULT CALLBACK procedure(HWND h, UINT message, WPARAM wparam, LPARAM lparam) noexcept {
    if (message == WM_NCCREATE) {
      auto* create = reinterpret_cast<CREATESTRUCTW*>(lparam);
      SetWindowLongPtrW(h, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(create->lpCreateParams));
      reinterpret_cast<FilesWindow*>(create->lpCreateParams)->hwnd_ = h;
    }
    auto* self = reinterpret_cast<FilesWindow*>(GetWindowLongPtrW(h, GWLP_USERDATA));
    if (!self) return DefWindowProcW(h, message, wparam, lparam);
    try {
      switch (message) {
        case WM_CREATE: self->create(); return 0;
        case WM_SIZE: self->layout(); return 0;
        case WM_DPICHANGED: {
          const auto* r = reinterpret_cast<const RECT*>(lparam);
          SetWindowPos(h, nullptr, r->left, r->top, r->right - r->left, r->bottom - r->top, SWP_NOZORDER | SWP_NOACTIVATE);
          self->dpi_ = HIWORD(wparam);
          self->layout();
          return 0;
        }
        case WM_GETMINMAXINFO:
          reinterpret_cast<MINMAXINFO*>(lparam)->ptMinTrackSize = {self->px(760), self->px(420)};
          return 0;
        case WM_COMMAND:
          if (HIWORD(wparam) == BN_CLICKED) self->command(LOWORD(wparam));
          return 0;
        case WM_NOTIFY: {
          const auto* hdr = reinterpret_cast<const NMHDR*>(lparam);
          if (hdr->code == LVN_ITEMCHANGED) self->update_buttons();
          if (hdr->idFrom == NodeList && hdr->code == NM_DBLCLK) self->enter_selected();
          return 0;
        }
        case WM_TIMER: self->progress(); return 0;
        case kDone: self->finished(); return 0;
        case WM_CTLCOLORSTATIC:
          SetBkMode(reinterpret_cast<HDC>(wparam), TRANSPARENT);
          return reinterpret_cast<LRESULT>(GetSysColorBrush(COLOR_WINDOW));
        case WM_CLOSE:
          if (self->busy_ && MessageBoxW(h, L"正在复制文件。要取消并关闭吗？", L"橙域", MB_OKCANCEL | MB_ICONQUESTION) != IDOK)
            return 0;
          self->owner_.close(self->target_.sandbox_id);  // destroys self
          return 0;
        default: break;
      }
    } catch (const std::exception&) {
      // Never let an exception cross the window procedure.
    }
    return DefWindowProcW(h, message, wparam, lparam);
  }

  int px(int v) const { return MulDiv(v, static_cast<int>(dpi_), 96); }

  HWND control(const wchar_t* kind, const wchar_t* text, DWORD style, int id = 0, DWORD ex = 0) {
    HWND c = CreateWindowExW(ex, kind, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 10, 10, hwnd_,
                             reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), nullptr);
    SendMessageW(c, WM_SETFONT, reinterpret_cast<WPARAM>(font_), TRUE);
    return c;
  }

  HWND list(int id, std::initializer_list<std::pair<const wchar_t*, int>> columns) {
    HWND l = control(WC_LISTVIEWW, L"", WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS, id, WS_EX_CLIENTEDGE);
    ListView_SetExtendedListViewStyle(l, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
    int i = 0;
    for (const auto& [title, width] : columns) {
      LVCOLUMNW c{LVCF_TEXT | LVCF_WIDTH};
      c.pszText = const_cast<wchar_t*>(title);
      c.cx = px(width);
      ListView_InsertColumn(l, i++, &c);
    }
    return l;
  }

  void create() {
    dpi_ = GetDpiForWindow(hwnd_);
    font_ = CreateFontW(-px(15), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Microsoft YaHei UI");
    node_title_ = control(L"STATIC", (L"节点上的个人文件（" + widen(target_.node_name) + L"）").c_str(), SS_LEFT | SS_NOPREFIX);
    guest_title_ = control(L"STATIC", L"沙盒的“下载”文件夹", SS_LEFT);
    up_ = control(L"BUTTON", L"上一级", WS_TABSTOP, NodeUp);
    path_ = control(L"STATIC", L"/", SS_LEFT | SS_NOPREFIX | SS_PATHELLIPSIS);
    node_refresh_ = control(L"BUTTON", L"刷新", WS_TABSTOP, NodeRefresh);
    guest_refresh_ = control(L"BUTTON", L"刷新", WS_TABSTOP, GuestRefresh);
    node_list_ = list(NodeList, {{L"名称", 220}, {L"大小", 80}, {L"修改时间", 130}});
    guest_list_ = list(GuestList, {{L"名称", 220}, {L"大小", 80}, {L"修改时间", 130}});
    to_sandbox_ = control(L"BUTTON", L"放入下载 →", WS_TABSTOP, ToSandbox);
    to_node_ = control(L"BUTTON", L"← 存到节点", WS_TABSTOP, ToNode);
    status_ = control(L"STATIC", L"", SS_LEFT | SS_NOPREFIX);
    cancel_button_ = control(L"BUTTON", L"取消", WS_TABSTOP, Cancel);
    layout();
    start(Job{});
  }

  void layout() {
    if (!status_) return;
    RECT rc;
    GetClientRect(hwnd_, &rc);
    const int w = rc.right, h = rc.bottom, m = px(16), row = px(30), mid = px(130);
    const int side = (w - 2 * m - mid) / 2, right = m + side + mid;
    MoveWindow(node_title_, m, m, side, px(24), TRUE);
    MoveWindow(guest_title_, right, m, side, px(24), TRUE);
    MoveWindow(up_, m, m + px(30), px(70), row, TRUE);
    MoveWindow(path_, m + px(78), m + px(36), side - px(78) - px(70), px(22), TRUE);
    MoveWindow(node_refresh_, m + side - px(64), m + px(30), px(64), row, TRUE);
    MoveWindow(guest_refresh_, right + side - px(64), m + px(30), px(64), row, TRUE);
    const int top = m + px(68), bottom = h - m - px(40);
    MoveWindow(node_list_, m, top, side, (std::max)(px(80), bottom - top), TRUE);
    MoveWindow(guest_list_, right, top, side, (std::max)(px(80), bottom - top), TRUE);
    const int centre = top + (bottom - top) / 2;
    MoveWindow(to_sandbox_, m + side + px(10), centre - px(40), mid - px(20), row, TRUE);
    MoveWindow(to_node_, m + side + px(10), centre + px(10), mid - px(20), row, TRUE);
    MoveWindow(status_, m, h - m - px(26), w - 2 * m - px(90), px(22), TRUE);
    MoveWindow(cancel_button_, w - m - px(80), h - m - px(32), px(80), row, TRUE);
  }

  void update_buttons() {
    const int n = selected_row(node_list_), g = selected_row(guest_list_);
    const bool file = n >= 0 && n < static_cast<int>(node_entries_.size()) && !node_entries_[n].is_directory;
    EnableWindow(to_sandbox_, !busy_ && file);
    EnableWindow(to_node_, !busy_ && g >= 0 && g < static_cast<int>(guest_files_.size()) && node_loaded_);
    EnableWindow(up_, !busy_ && !node_dir_.empty());
    EnableWindow(node_refresh_, !busy_);
    EnableWindow(guest_refresh_, !busy_);
    EnableWindow(cancel_button_, busy_);
  }

  void command(int id) {
    if (busy_ && id != Cancel) return;
    switch (id) {
      case NodeUp: {
        Job j;
        j.guest = false;
        j.node_dir = parent_of(node_dir_);
        start(std::move(j));
        break;
      }
      case NodeRefresh: {
        Job j;
        j.guest = false;
        j.node_dir = node_dir_;
        start(std::move(j));
        break;
      }
      case GuestRefresh: {
        Job j;
        j.node = false;
        start(std::move(j));
        break;
      }
      case ToSandbox: {
        const int n = selected_row(node_list_);
        if (n < 0 || n >= static_cast<int>(node_entries_.size()) || node_entries_[n].is_directory) return;
        Job j;
        j.kind = Kind::ToSandbox;
        j.entry = node_entries_[n];
        j.node_dir = node_dir_;
        start(std::move(j));
        break;
      }
      case ToNode: {
        const int g = selected_row(guest_list_);
        if (g < 0 || g >= static_cast<int>(guest_files_.size())) return;
        const auto& file = guest_files_[g];
        // The node refuses to replace a file; say so before copying anything.
        if (std::any_of(node_entries_.begin(), node_entries_.end(), [&](const auto& e) { return e.name == file.name; })) {
          status(L"节点当前文件夹里已有「" + widen(file.name) + L"」。请先在沙盒里改名，或换一个节点文件夹。");
          return;
        }
        Job j;
        j.kind = Kind::ToNode;
        j.file = file;
        j.node_dir = node_dir_;
        start(std::move(j));
        break;
      }
      case Cancel:
        cancel_ = true;
        status(L"正在取消……");
        break;
      default: break;
    }
  }

  void enter_selected() {
    const int n = selected_row(node_list_);
    if (busy_ || n < 0 || n >= static_cast<int>(node_entries_.size()) || !node_entries_[n].is_directory) return;
    Job j;
    j.guest = false;
    j.node_dir = node_entries_[n].path;
    start(std::move(j));
  }

  void status(const std::wstring& text) { SetWindowTextW(status_, text.c_str()); }

  void start(Job job) {
    if (worker_.joinable()) worker_.join();
    busy_ = true;
    cancel_ = false;
    phase_ = 0;
    done_ = total_ = 0;
    label_ = job.kind == Kind::ToSandbox ? widen(job.entry.name) : job.kind == Kind::ToNode ? widen(job.file.name) : L"";
    status(job.kind == Kind::Refresh ? L"正在读取……" : L"正在准备……");
    update_buttons();
    SetTimer(hwnd_, kProgress, 250, nullptr);
    worker_ = std::thread([this, job = std::move(job)]() mutable { run(std::move(job)); });
  }

  void progress() {
    static const wchar_t* const phases[] = {L"", L"正在从节点取回", L"正在放入沙盒", L"正在从沙盒取出", L"正在存到节点"};
    const int p = phase_.load();
    if (!busy_ || p <= 0 || p > 4 || cancel_) return;
    const auto total = total_.load();
    status(std::wstring(phases[p]) + L"「" + label_ + L"」：" + size_text(done_.load()) +
           (total ? L" / " + size_text(total) : L""));
  }

  files::FileClient& client() {
    if (!client_) client_ = std::make_shared<files::FileClient>(target_.context);
    return *client_;
  }

  std::vector<files::Entry> list_node(const std::string& dir) {
    auto entries = client().list(dir, cancel_);
    std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) {
      return a.is_directory != b.is_directory ? a.is_directory : a.name < b.name;
    });
    return entries;
  }

  // Worker thread: one job at a time; never touches controls.
  void run(Job job) noexcept {
    Result r;
    fs::path staging;
    try {
      auto progress = [this](std::uint64_t done, std::uint64_t total) {
        done_ = done;
        total_ = total;
      };
      if (job.kind == Kind::ToSandbox || job.kind == Kind::ToNode) {
        fs::create_directories(target_.staging);
        staging = target_.staging / random_leaf();
      }
      if (job.kind == Kind::ToSandbox) {
        phase_ = 1;
        client().download(job.entry.path, staging, cancel_, progress);
        phase_ = 2;
        done_ = total_ = 0;
        const auto name = owner_.guest_.push(target_.sandbox_id, staging, job.entry.name, cancel_, progress);
        r.message = L"已放入沙盒的“下载”文件夹：" + widen(name);
        owner_.log_("files: node file copied into the Downloads of sandbox " + target_.sandbox_id);
        job.node = false;
      } else if (job.kind == Kind::ToNode) {
        phase_ = 3;
        owner_.guest_.pull(target_.sandbox_id, job.file.name, staging, cancel_, progress);
        phase_ = 4;
        done_ = total_ = 0;
        client().upload(staging, joined(job.node_dir, job.file.name), cancel_, progress);
        r.message = L"已存到节点：" + widen(joined(job.node_dir, job.file.name));
        owner_.log_("files: Downloads file of sandbox " + target_.sandbox_id + " copied to its node");
        job.guest = false;
      }
      phase_ = 0;
      if (job.node) {
        r.node = list_node(job.node_dir);
        r.node_dir = job.node_dir;
      }
      if (job.guest) r.guest = owner_.guest_.list(target_.sandbox_id);
    } catch (const std::exception& e) {
      r.message = reason(e);
      if (!cancelled(e)) owner_.log_("files: sandbox " + target_.sandbox_id + ": " + std::string(e.what()).substr(0, 240));
      if (!dynamic_cast<const files::Cancelled*>(&e)) client_.reset();  // a fresh Centre/node exchange next time
    } catch (...) {
      r.message = L"没有完成。";
    }
    if (!staging.empty()) {
      std::error_code ec;
      fs::remove(staging, ec);
    }
    {
      std::lock_guard lock(mutex_);
      result_ = std::move(r);
    }
    if (hwnd_) PostMessageW(hwnd_, kDone, 0, 0);
  }

  void finished() {
    if (worker_.joinable()) worker_.join();
    KillTimer(hwnd_, kProgress);
    Result r;
    {
      std::lock_guard lock(mutex_);
      r = std::move(result_);
    }
    busy_ = false;
    if (r.node) {
      node_entries_ = std::move(*r.node);
      node_dir_ = r.node_dir;
      node_loaded_ = true;
      SetWindowTextW(path_, (L"/" + widen(node_dir_)).c_str());
      ListView_DeleteAllItems(node_list_);
      for (int i = 0; i < static_cast<int>(node_entries_.size()); ++i) {
        const auto& e = node_entries_[i];
        auto name = widen(e.name) + (e.is_directory ? L"/" : L"");
        LVITEMW item{LVIF_TEXT};
        item.iItem = i;
        item.pszText = name.data();
        ListView_InsertItem(node_list_, &item);
        set_text(node_list_, i, 1, e.is_directory ? L"" : size_text(e.size));
        set_text(node_list_, i, 2, time_text(e.modified_s.value_or(0)));
      }
    }
    if (r.guest) {
      guest_files_ = std::move(*r.guest);
      ListView_DeleteAllItems(guest_list_);
      for (int i = 0; i < static_cast<int>(guest_files_.size()); ++i) {
        const auto& f = guest_files_[i];
        auto name = widen(f.name);
        LVITEMW item{LVIF_TEXT};
        item.iItem = i;
        item.pszText = name.data();
        ListView_InsertItem(guest_list_, &item);
        set_text(guest_list_, i, 1, size_text(f.size));
        set_text(guest_list_, i, 2, time_text(f.modified_s));
      }
    }
    status(r.message);
    update_buttons();
  }

  friend class FilesWindows;
  FilesWindows& owner_;
  const FilesTarget target_;
  HWND hwnd_{};
  UINT dpi_{96};
  HFONT font_{};
  HWND node_title_{}, guest_title_{}, up_{}, path_{}, node_refresh_{}, guest_refresh_{}, node_list_{}, guest_list_{},
      to_sandbox_{}, to_node_{}, status_{}, cancel_button_{};
  std::shared_ptr<files::FileClient> client_;  // used by the worker only
  std::thread worker_;
  std::atomic<bool> cancel_{false};
  std::atomic<int> phase_{0};
  std::atomic<std::uint64_t> done_{0}, total_{0};
  std::wstring label_;
  bool busy_{false}, node_loaded_{false};
  std::mutex mutex_;
  Result result_;
  std::vector<files::Entry> node_entries_;
  std::string node_dir_;
  std::vector<GuestFile> guest_files_;
};

FilesWindows::FilesWindows(HWND owner, GuestFiles& guest, std::function<void(const std::string&)> log)
    : owner_(owner), guest_(guest), log_(std::move(log)) {
  if (!log_) log_ = [](const std::string&) {};
}

FilesWindows::~FilesWindows() { close_all(); }

void FilesWindows::open(const FilesTarget& target) {
  auto it = windows_.find(target.sandbox_id);
  if (it == windows_.end()) it = windows_.emplace(target.sandbox_id, std::make_unique<FilesWindow>(*this, target)).first;
  it->second->show();
}

void FilesWindows::close(const std::string& sandbox_id) {
  const auto it = windows_.find(sandbox_id);
  if (it == windows_.end()) return;
  auto window = std::move(it->second);
  windows_.erase(it);
  window.reset();  // cancels, waits for the copy to stop, destroys the window
}

void FilesWindows::close_all() {
  while (!windows_.empty()) close(windows_.begin()->first);
}

}  // namespace orangespace::sandbox
