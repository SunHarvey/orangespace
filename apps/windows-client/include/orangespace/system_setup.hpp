#pragma once
// Bringing this Windows user's OrangeSpace distribution to the release that
// was installed with OrangeSpace.exe.
//
// The installer (administrator) puts the release next to the executable:
//   system\release.json         {"schema":1,"revision","rootfs","rootfs_sha256","image","image_sha256"}
//   system\<rootfs>.tar.gz      the distribution's root filesystem
//   system\<image>.tar          the desktop image (OCI archive)
// WSL distributions belong to one Windows user, so the client does the rest on
// its first start for each user, and again after an upgrade:
//   install      wsl --import, then load the desktop image
//   upgrade      save the sandbox data to a private folder, replace the
//                distribution, restore the data, load the new image
// The saved data is deleted only after it is back; an upgrade interrupted at
// any point resumes on the next start. A development build has no system
// folder and leaves the distribution alone.
#include "orangespace/json.hpp"

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

namespace orangespace::system_setup {

class SetupError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

struct Release {
  std::string revision;
  std::string rootfs, rootfs_sha256;
  std::string image, image_sha256;
};

// What `wsl/system info` reports about the registered distribution.
struct Installed {
  std::string revision;
  bool has_image{false};
  int sandboxes{0};
};

enum class Step { none, install, load_image, upgrade, resume_upgrade };

namespace detail {
inline bool sha256_hex(std::string_view s) {
  if (s.size() != 64) return false;
  for (char c : s)
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
  return true;
}
// A plain file name in the system folder: no path, nothing hidden, ASCII.
inline bool file_name(std::string_view s, std::string_view suffix) {
  if (s.empty() || s.size() > 100 || s.front() == '.' || !s.ends_with(suffix) || s.size() == suffix.size()) return false;
  for (char c : s)
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' ||
          c == '_'))
      return false;
  return true;
}
inline bool revision_text(std::string_view s) {
  if (s.empty() || s.size() > 64) return false;
  for (char c : s)
    if (c <= ' ' || c > '~') return false;
  return true;
}
inline const std::string& text(const json::Value& v, std::string_view key) {
  const auto* f = v.find(key);
  const auto* s = f ? std::get_if<std::string>(&f->data) : nullptr;
  if (!s) throw SetupError("release.json: missing " + std::string(key));
  return *s;
}
}  // namespace detail

inline Release parse_release(std::string_view input) {
  json::Value doc;
  try {
    doc = json::parse(input);
  } catch (const std::exception&) {
    throw SetupError("release.json is not valid JSON");
  }
  const auto* object = std::get_if<json::Value::Object>(&doc.data);
  if (!object || object->size() != 6) throw SetupError("release.json has unexpected fields");
  const auto* schema = doc.find("schema");
  const auto* n = schema ? std::get_if<double>(&schema->data) : nullptr;
  if (!n || *n != 1) throw SetupError("release.json: unsupported schema");
  Release r{detail::text(doc, "revision"), detail::text(doc, "rootfs"), detail::text(doc, "rootfs_sha256"),
            detail::text(doc, "image"), detail::text(doc, "image_sha256")};
  if (!detail::revision_text(r.revision) || !detail::file_name(r.rootfs, ".tar.gz") ||
      !detail::file_name(r.image, ".tar") || !detail::sha256_hex(r.rootfs_sha256) ||
      !detail::sha256_hex(r.image_sha256))
    throw SetupError("release.json has an invalid value");
  return r;
}

// `wsl/system info` output: {"revision": "...", "image": "<id>"|null, "sandboxes": N}.
inline Installed parse_info(std::string_view input) {
  json::Value doc;
  try {
    doc = json::parse(input);
  } catch (const std::exception&) {
    throw SetupError("the distribution's system info is not valid JSON");
  }
  Installed result;
  const auto* revision = doc.find("revision");
  const auto* image = doc.find("image");
  const auto* count = doc.find("sandboxes");
  const auto* r = revision ? std::get_if<std::string>(&revision->data) : nullptr;
  const auto* c = count ? std::get_if<double>(&count->data) : nullptr;
  if (!r || !image || !c || *c < 0 || *c > 100000 || *c != static_cast<double>(static_cast<int>(*c)))
    throw SetupError("the distribution's system info is incomplete");
  result.revision = *r;
  result.has_image = std::get_if<std::string>(&image->data) != nullptr;
  result.sandboxes = static_cast<int>(*c);
  return result;
}

// installed: nullptr when no OrangeSpace distribution is registered.
// upgrade_saved: the sandbox data of an earlier upgrade is waiting to go back.
inline Step plan(const Release& release, const Installed* installed, bool upgrade_saved) {
  if (upgrade_saved) return Step::resume_upgrade;
  if (!installed) return Step::install;
  if (installed->revision != release.revision) return Step::upgrade;
  if (!installed->has_image) return Step::load_image;
  return Step::none;
}

}  // namespace orangespace::system_setup

#ifdef _WIN32
#include <filesystem>
#include <functional>
#include <optional>

namespace orangespace::system_setup {

class SystemSetup {
 public:
  // The release installed next to this executable, or nullopt for a
  // development build (no system\release.json). Throws if it is present but bad.
  static std::optional<SystemSetup> for_this_install();
  // Does whatever plan() says. progress gets one short line per stage (UI
  // thread must not call this: it takes minutes). Throws SetupError.
  void run(const std::function<void(const std::wstring&)>& progress);

  const Release& release() const { return release_; }

 private:
  SystemSetup(std::filesystem::path folder, Release release) : folder_(std::move(folder)), release_(std::move(release)) {}
  std::filesystem::path folder_;
  Release release_;
};

// This Windows user's local OrangeSpace data: the distribution (every sandbox
// desktop, HOME and download in it), the client's folder (sandbox list,
// logs) and saved credentials. Files on nodes are not touched. The caller makes
// sure no client runs. Throws SetupError if something could not be removed.
void remove_all_local_data();

}  // namespace orangespace::system_setup
#endif
