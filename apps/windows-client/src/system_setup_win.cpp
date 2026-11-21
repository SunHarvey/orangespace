#include "orangespace/system_setup.hpp"

#include "orangespace/wsl_runtime.hpp"

#include <bcrypt.h>
#include <shlobj.h>
#include <windows.h>

#include <array>
#include <fstream>
#include <sstream>
#include <vector>

namespace orangespace::system_setup {
namespace fs = std::filesystem;
namespace {

constexpr wchar_t kSystemTool[] = L"/opt/orangespace/wsl/system";
constexpr DWORD kMinutes = 60 * 1000;

// Messages are UTF-8 (the window widens them); a user's folder name may be non-ASCII.
std::string utf8(const fs::path& path) {
  const auto u = path.u8string();
  return std::string(u.begin(), u.end());
}

struct File {
  HANDLE h{INVALID_HANDLE_VALUE};
  File() = default;
  explicit File(HANDLE handle) : h(handle) {}
  File(const File&) = delete;
  File& operator=(const File&) = delete;
  File(File&& other) noexcept : h(other.h) { other.h = INVALID_HANDLE_VALUE; }
  File& operator=(File&&) = delete;
  ~File() { close(); }
  void close() {
    if (h != INVALID_HANDLE_VALUE && h) CloseHandle(h);
    h = INVALID_HANDLE_VALUE;
  }
  bool ok() const { return h != INVALID_HANDLE_VALUE && h; }
};

File open_read(const fs::path& path) {
  File f(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN,
                     nullptr));
  if (!f.ok()) throw SetupError("无法读取 " + utf8(path.filename()));
  return f;
}

File create_write(const fs::path& path) {
  File f(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
  if (!f.ok()) throw SetupError("无法写入 " + utf8(path.filename()));
  return f;
}

fs::path local_root() {
  PWSTR base = nullptr;
  if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_CREATE, nullptr, &base)))
    throw SetupError("找不到本机应用数据文件夹");
  fs::path dir(base);
  CoTaskMemFree(base);
  return dir;
}

fs::path client_root() { return local_root() / L"OrangeSpace"; }
fs::path distro_dir() { return client_root() / L"wsl"; }
fs::path upgrade_dir() { return client_root() / L"upgrade"; }

std::string sha256_file(const fs::path& path) {
  auto file = open_read(path);
  BCRYPT_ALG_HANDLE alg{};
  BCRYPT_HASH_HANDLE hash{};
  if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) throw SetupError("无法计算校验值");
  struct Close {
    BCRYPT_ALG_HANDLE& a;
    BCRYPT_HASH_HANDLE& h;
    ~Close() {
      if (h) BCryptDestroyHash(h);
      if (a) BCryptCloseAlgorithmProvider(a, 0);
    }
  } close{alg, hash};
  if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) != 0) throw SetupError("无法计算校验值");
  std::vector<unsigned char> buffer(1 << 20);
  for (;;) {
    DWORD n = 0;
    if (!ReadFile(file.h, buffer.data(), static_cast<DWORD>(buffer.size()), &n, nullptr))
      throw SetupError("读取 " + utf8(path.filename()) + " 时出错");
    if (n == 0) break;
    if (BCryptHashData(hash, buffer.data(), n, 0) != 0) throw SetupError("无法计算校验值");
  }
  std::array<unsigned char, 32> digest{};
  if (BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) != 0) throw SetupError("无法计算校验值");
  static constexpr char hex[] = "0123456789abcdef";
  std::string out;
  for (auto b : digest) {
    out += hex[b >> 4];
    out += hex[b & 15];
  }
  return out;
}

// stderr of every command goes to setup.log in the client folder (no
// credentials pass through these commands).
File open_log() {
  std::error_code ec;
  fs::create_directories(client_root(), ec);
  File f(CreateFileW((client_root() / L"setup.log").c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                     nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
  return f;
}

void log_line(const std::string& line) {
  auto log = open_log();
  if (!log.ok()) return;
  SYSTEMTIME t;
  GetLocalTime(&t);
  char stamp[32];
  std::snprintf(stamp, sizeof(stamp), "%04u-%02u-%02u %02u:%02u:%02u ", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute,
                t.wSecond);
  const auto text = stamp + line + "\n";
  DWORD n = 0;
  WriteFile(log.h, text.data(), static_cast<DWORD>(text.size()), &n, nullptr);
}

DWORD system_tool(std::vector<std::wstring> args, HANDLE in, HANDLE out, DWORD timeout_ms) {
  args.insert(args.begin(), {L"/usr/bin/python3", kSystemTool});
  auto log = open_log();
  return wsl::run_as_root(args, in, out, log.ok() ? log.h : nullptr, timeout_ms);
}

Installed query_info() {
  SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, FALSE};
  File read, write;
  if (!CreatePipe(&read.h, &write.h, &sa, 1 << 16)) throw SetupError("无法读取系统信息");
  const DWORD code = system_tool({L"info"}, nullptr, write.h, 5 * kMinutes);
  write.close();
  std::string output;
  char buffer[4096];
  DWORD n = 0;
  while (output.size() < 65536 && ReadFile(read.h, buffer, sizeof(buffer), &n, nullptr) && n) output.append(buffer, n);
  if (code != 0) throw SetupError("无法读取已安装的橙域系统信息");
  return parse_info(output);
}

std::string read_text(const fs::path& path, std::size_t limit) {
  std::ifstream in(path, std::ios::binary);
  if (!in) throw SetupError("无法读取 " + utf8(path.filename()));
  std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  if (text.size() > limit) throw SetupError(utf8(path.filename()) + " 太大");
  return text;
}

void write_text_atomically(const fs::path& path, const std::string& text) {
  const auto temp = path.wstring() + L".new";
  {
    auto f = create_write(temp);
    DWORD n = 0;
    if (!WriteFile(f.h, text.data(), static_cast<DWORD>(text.size()), &n, nullptr) || n != text.size() ||
        !FlushFileBuffers(f.h))
      throw SetupError("无法写入升级记录");
  }
  if (!MoveFileExW(temp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    throw SetupError("无法写入升级记录");
}

struct Saved {
  std::string sha256;
  int sandboxes{};
};

Saved read_saved() {
  const auto doc = json::parse(read_text(upgrade_dir() / L"state.json", 4096));
  const auto* sha = doc.find("sha256");
  const auto* count = doc.find("sandboxes");
  const auto* s = sha ? std::get_if<std::string>(&sha->data) : nullptr;
  const auto* c = count ? std::get_if<double>(&count->data) : nullptr;
  if (!s || !detail::sha256_hex(*s) || !c || *c < 0) throw SetupError("升级记录已损坏");
  return {*s, static_cast<int>(*c)};
}

}  // namespace

std::optional<SystemSetup> SystemSetup::for_this_install() {
  std::array<wchar_t, 32768> self{};
  const DWORD n = GetModuleFileNameW(nullptr, self.data(), static_cast<DWORD>(self.size()));
  if (!n || n >= self.size()) throw SetupError("找不到程序所在位置");
  const auto folder = fs::path(std::wstring(self.data(), n)).parent_path() / L"system";
  const auto manifest = folder / L"release.json";
  if (!fs::exists(manifest)) return std::nullopt;
  return SystemSetup(folder, parse_release(read_text(manifest, 4096)));
}

void SystemSetup::run(const std::function<void(const std::wstring&)>& progress) {
  if (wsl::wsl_executable().empty()) throw SetupError("本机还没有启用 WSL，请重新运行橙域安装程序");
  const auto rootfs = folder_ / release_.rootfs;
  const auto image = folder_ / release_.image;
  const auto saved_tar = upgrade_dir() / L"userdata.tar";
  const auto saved_state = upgrade_dir() / L"state.json";
  std::error_code ec;
  fs::remove(upgrade_dir() / L"userdata.tar.part", ec);  // an export that never finished

  auto check_rootfs = [&] {
    if (sha256_file(rootfs) != release_.rootfs_sha256) throw SetupError("安装文件已损坏（系统镜像校验不符），请重新安装橙域");
  };
  auto load_image = [&] {
    progress(L"正在载入桌面环境……");
    auto file = open_read(image);
    if (system_tool({L"load-image", std::wstring(release_.image_sha256.begin(), release_.image_sha256.end())}, file.h,
                    nullptr, 30 * kMinutes) != 0)
      throw SetupError("载入桌面环境失败（详情见 setup.log）");
  };
  auto import = [&] {
    check_rootfs();
    try {
      wsl::import_distribution(rootfs.wstring(), distro_dir().wstring());
    } catch (const wsl::RuntimeError& e) {
      throw SetupError(std::string("导入橙域系统失败：") + e.what());
    }
  };
  auto resume = [&] {
    const auto saved = read_saved();
    progress(L"正在升级橙域系统：核对已保存的沙盒数据……");
    if (sha256_file(saved_tar) != saved.sha256)
      throw SetupError("升级时保存的沙盒数据校验不符，已停止升级；数据仍在 " + utf8(upgrade_dir()));
    progress(L"正在升级橙域系统：替换系统……");
    log_line("upgrade: replacing the distribution with " + release_.revision);
    wsl::terminate_distribution();
    if (wsl::distribution_registered()) {
      try {
        wsl::unregister_distribution();
      } catch (const wsl::RuntimeError& e) {
        throw SetupError(std::string("无法移除旧系统：") + e.what());
      }
    }
    import();
    progress(L"正在升级橙域系统：恢复沙盒数据……");
    {
      auto file = open_read(saved_tar);
      if (system_tool({L"import-data"}, file.h, nullptr, 60 * kMinutes) != 0)
        throw SetupError("恢复沙盒数据失败（详情见 setup.log）；数据仍在 " + utf8(upgrade_dir()));
    }
    load_image();
    const auto now = query_info();
    if (now.revision != release_.revision || !now.has_image || now.sandboxes != saved.sandboxes)
      throw SetupError("升级后的系统与预期不符；数据仍在 " + utf8(upgrade_dir()));
    fs::remove_all(upgrade_dir(), ec);
    log_line("upgrade: done, " + std::to_string(saved.sandboxes) + " sandboxes restored");
  };

  const bool saved = fs::exists(saved_state) && fs::exists(saved_tar);
  std::optional<Installed> installed;
  if (!saved && wsl::distribution_registered()) installed = query_info();
  switch (plan(release_, installed ? &*installed : nullptr, saved)) {
    case Step::none:
      return;
    case Step::install:
      progress(L"正在安装橙域系统（首次运行，需要几分钟）……");
      log_line("install: " + release_.revision);
      import();
      load_image();
      if (const auto now = query_info(); now.revision != release_.revision || !now.has_image)
        throw SetupError("安装后的系统与预期不符（详情见 setup.log）");
      log_line("install: done");
      return;
    case Step::load_image:
      load_image();
      return;
    case Step::upgrade: {
      progress(L"正在升级橙域系统：保存沙盒数据……");
      log_line("upgrade: " + installed->revision + " -> " + release_.revision + ", saving data");
      wsl::terminate_distribution();
      fs::create_directories(upgrade_dir());
      const auto part = upgrade_dir() / L"userdata.tar.part";
      DWORD code;
      {
        auto out = create_write(part);
        code = system_tool({L"export-data"}, nullptr, out.h, 60 * kMinutes);
        if (code == 0 && !FlushFileBuffers(out.h)) code = 1;
      }
      if (code != 0) {
        fs::remove(part, ec);
        throw SetupError("保存沙盒数据失败，系统没有改动（详情见 setup.log）");
      }
      const auto sha = sha256_file(part);
      fs::rename(part, saved_tar);
      write_text_atomically(saved_state, "{\"schema\":1,\"sha256\":\"" + sha + "\",\"sandboxes\":" +
                                             std::to_string(installed->sandboxes) + "}");
      resume();
      return;
    }
    case Step::resume_upgrade:
      resume();
      return;
  }
}

void remove_all_local_data() {
  std::string failed;
  if (!wsl::wsl_executable().empty() && wsl::distribution_registered()) {
    wsl::terminate_distribution();
    try {
      wsl::unregister_distribution();
    } catch (const wsl::RuntimeError&) {
      failed += " WSL 发行版";
    }
  }
  // The client folder, and the DPAPI credential folders of credential_store_win.cpp.
  const auto base = local_root();
  for (const wchar_t* name : {L"OrangeSpace", L"OrangeSpace-Credentials-v1", L"OrangeSpace-Platform-Credentials-v1"}) {
    std::error_code ec;
    fs::remove_all(base / name, ec);
    if (ec || fs::exists(base / name)) failed += " " + utf8(base / name);
  }
  if (!failed.empty()) throw SetupError("以下内容没有删除：" + failed);
}

}  // namespace orangespace::system_setup
