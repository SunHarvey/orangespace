// What the client decides to do with this user's distribution, given the
// release installed next to it (portable part of system_setup).
#include "orangespace/system_setup.hpp"

#include <cassert>
#include <cstdio>
#include <functional>
#include <string>
#include <vector>

namespace ss = orangespace::system_setup;

namespace {
const std::string H1(64, 'a');
const std::string H2 = std::string(63, '0') + "f";

std::string release_json(const std::string& revision = "0.1.0+e526852", const std::string& rootfs = "orangespace-rootfs.tar.gz",
                         const std::string& rootfs_sha = H1, const std::string& image = "desktop-image.tar",
                         const std::string& image_sha = H2) {
  return "{\"schema\":1,\"revision\":\"" + revision + "\",\"rootfs\":\"" + rootfs + "\",\"rootfs_sha256\":\"" +
         rootfs_sha + "\",\"image\":\"" + image + "\",\"image_sha256\":\"" + image_sha + "\"}";
}

bool rejected(const std::function<void()>& f) {
  try {
    f();
  } catch (const ss::SetupError&) {
    return true;
  }
  return false;
}

void a_release_names_plain_files_with_their_digests() {
  const auto r = ss::parse_release(release_json());
  assert(r.revision == "0.1.0+e526852" && r.rootfs == "orangespace-rootfs.tar.gz" && r.rootfs_sha256 == H1 &&
         r.image == "desktop-image.tar" && r.image_sha256 == H2);
  // Anything that could point outside the system folder, or be ambiguous, is refused.
  for (const std::string bad : {"../rootfs.tar.gz", "sub\\\\rootfs.tar.gz", "sub/rootfs.tar.gz", ".tar.gz", ".hidden.tar.gz",
                                "rootfs.tar", "C:rootfs.tar.gz", "rootfs .tar.gz"})
    assert(rejected([&] { ss::parse_release(release_json("r", bad)); }));
  for (const std::string bad : {"../image.tar", "image.tar.gz.exe", "image"})
    assert(rejected([&] { ss::parse_release(release_json("r", "a.tar.gz", H1, bad)); }));
  for (const std::string bad : {std::string(64, 'A'), std::string(63, 'a'), std::string(65, 'a'), std::string(64, 'g')})
    assert(rejected([&] { ss::parse_release(release_json("r", "a.tar.gz", bad)); }));
  for (const std::string& bad : std::vector<std::string>{"", "has space", std::string(65, 'r')})
    assert(rejected([&] { ss::parse_release(release_json(bad)); }));
  assert(rejected([] { ss::parse_release("{\"schema\":2" + release_json().substr(10)); }));
  assert(rejected([] { ss::parse_release(release_json().substr(0, release_json().size() - 1) + ",\"extra\":1}"); }));
  assert(rejected([] { ss::parse_release("not json"); }));
}

void system_info_is_read_strictly() {
  auto i = ss::parse_info("{\"revision\": \"0.1.0+e526852\", \"image\": \"sha256:ab\", \"sandboxes\": 3}");
  assert(i.revision == "0.1.0+e526852" && i.has_image && i.sandboxes == 3);
  i = ss::parse_info("{\"revision\": \"\", \"image\": null, \"sandboxes\": 0}");
  assert(i.revision.empty() && !i.has_image && i.sandboxes == 0);
  for (const char* bad : {"{\"revision\":\"r\",\"sandboxes\":1}", "{\"revision\":\"r\",\"image\":null,\"sandboxes\":-1}",
                          "{\"revision\":\"r\",\"image\":null,\"sandboxes\":1.5}", "{\"revision\":1,\"image\":null,\"sandboxes\":1}",
                          ""})
    assert(rejected([&] { ss::parse_info(bad); }));
}

void the_plan_follows_the_distribution_and_any_saved_upgrade() {
  const auto release = ss::parse_release(release_json("0.2.0"));
  ss::Installed same{"0.2.0", true, 2}, older{"0.1.0", true, 2}, unknown{"", false, 0}, no_image{"0.2.0", false, 0};
  assert(ss::plan(release, nullptr, false) == ss::Step::install);
  assert(ss::plan(release, &same, false) == ss::Step::none);
  assert(ss::plan(release, &older, false) == ss::Step::upgrade);
  assert(ss::plan(release, &unknown, false) == ss::Step::upgrade);  // a distribution from before releases
  assert(ss::plan(release, &no_image, false) == ss::Step::load_image);  // an install interrupted after import
  // Saved data of an interrupted upgrade always goes back first, whatever is registered now.
  for (const ss::Installed* now : std::vector<const ss::Installed*>{nullptr, &same, &older})
    assert(ss::plan(release, now, true) == ss::Step::resume_upgrade);
}
}  // namespace

int main() {
  a_release_names_plain_files_with_their_digests();
  system_info_is_read_strictly();
  the_plan_follows_the_distribution_and_any_saved_upgrade();
  std::puts("system setup tests passed");
  return 0;
}
