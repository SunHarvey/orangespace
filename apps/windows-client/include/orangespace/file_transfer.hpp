#pragma once
#include "orangespace/platform_session.hpp"
#include <atomic>
#include <filesystem>
#include <optional>

namespace orangespace::files {
namespace ps = platform_session;
struct FileContext {
  std::string central_user_id, sandbox_id, node_id, username, node_name;
  std::shared_ptr<const ps::PlatformConfig> platform;
  std::shared_ptr<ps::Session> session; // Compatibility only; never read by FileClient.
  std::shared_ptr<const ps::SerializedSecret> central_envelope;
};
struct Entry {
  std::string name, path;
  bool is_directory{};
  std::uint64_t size{};
  std::optional<std::int64_t> modified_at_ns;
};
using Progress = std::function<void(std::uint64_t, std::uint64_t)>;
class Cancelled final : public std::runtime_error {
 public: Cancelled() : std::runtime_error("file operation cancelled") {}
};
// The caller snapshots central_envelope under its existing Session owner gate
// before spawning work. FileClient NEVER reads the compatibility session field.
// It restores a private central Session and never logs out the shared token.
// Catalog is the administrator-protected nodes.json beside the executable.
// App-private roots use the streaming Rust ABI, never the capped JSON ABI or
// WinHTTP trust-ignore flags. Ordinary OS-trusted HTTPS uses strict WinHTTP.
class FileClient {
 public:
  explicit FileClient(const FileContext&);
  ~FileClient();
  FileClient(const FileClient&) = delete;
  FileClient& operator=(const FileClient&) = delete;
  std::vector<Entry> list(std::string_view path, std::atomic<bool>& cancel);
  void mkdir(std::string_view path, std::atomic<bool>& cancel);
  void upload(const std::filesystem::path& local_absolute, std::string_view remote_relative,
              std::atomic<bool>& cancel, Progress progress = {});
  void download(std::string_view remote_relative, const std::filesystem::path& local_absolute,
                std::atomic<bool>& cancel, Progress progress = {});
 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};
namespace detail {
// Portable ownership/path policy exercised by file_transfer tests.
std::string checked_path(std::string_view path, bool allow_root = false);
std::string encode_path(std::string_view path);
struct TaskScope {
  const std::string central_user_id, sandbox_id, node_id, path;
  TaskScope(const FileContext&, std::string_view, bool allow_root = false);
};
void cancellation_point(const std::atomic<bool>&);
std::vector<Entry> parse_listing(std::string_view body, const TaskScope&);
class DownloadOwnership {
 public:
  bool owns_part() const noexcept { return owned_; }
  void publish(const std::atomic<bool>& cancel, const std::function<void()>& atomic_publish);
 private: bool owned_{true};
};
}
} // namespace orangespace::files
