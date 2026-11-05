#include "orangespace/credential_store.hpp"
#include <cassert>
#include <iostream>
#include <mutex>
#include <thread>
#include <stdexcept>
namespace cd = orangespace::node_session::credential_detail;
// Fault model exercises the production transaction ordering, not Windows I/O.
struct Disk {
  bool marker{}, blob{true};
  bool fail_commit{}, fail_delete{}, fail_absence{}, fail_clear{};
  void commit() { if(fail_commit) throw std::runtime_error("commit"); marker=true; }
  void remove_blob() { assert(marker); if(fail_delete) throw std::runtime_error("delete"); blob=false; }
  void verify_absent() { if(fail_absence || blob) throw std::runtime_error("absence"); }
  void clear() { assert(!blob); if(fail_clear) throw std::runtime_error("clear"); marker=false; }
};
int main() {
  Disk disk; disk.fail_delete=true;
  try { cd::pending_erase(disk); assert(false); } catch(const std::runtime_error&) {}
  assert(disk.marker && disk.blob); // crash/reopen sees the committed disk marker
  auto reopened=disk;
  assert(reopened.marker);
  reopened.fail_delete=false;
  cd::pending_erase(reopened);
  assert(!reopened.marker && !reopened.blob);
  bool denied=false;
  try {cd::require_no_pending(true);} catch(const std::runtime_error&) {denied=true;}
  assert(denied);
  cd::require_no_pending(false);
  // All failure boundaries: never reset committed intent on uncertain cleanup.
  for(int fault=0;fault<4;++fault) {
    Disk broken;
    broken.fail_commit=fault==0; broken.fail_delete=fault==1;
    broken.fail_absence=fault==2; broken.fail_clear=fault==3;
    bool threw=false;
    try {cd::pending_erase(broken);} catch(const std::runtime_error&) {threw=true;}
    assert(threw);
    if(fault==0) assert(!broken.marker && broken.blob); // NOT COMMITTED
    else assert(broken.marker);
    broken.fail_commit=broken.fail_delete=broken.fail_absence=broken.fail_clear=false;
    cd::pending_erase(broken);
    assert(!broken.marker && !broken.blob);
  }
  // Per-node held-lock interleaving: committed failed logout fences queued old
  // saves and loads; a different node remains usable. This models file faults,
  // not DPAPI/NTFS, and calls the actual production ordering and access policy.
  Disk a,b; a.fail_delete=true;
  std::mutex mutex; std::unique_lock owner(mutex);
  bool save_denied=false,load_denied=false;
  std::thread late_save([&]{
    std::lock_guard guard(mutex);
    try {cd::require_no_pending(a.marker);a.blob=true;} catch(...) {save_denied=true;}
  });
  std::thread late_load([&]{
    std::lock_guard guard(mutex);
    try {cd::require_no_pending(a.marker);} catch(...) {load_denied=true;}
  });
  try {cd::pending_erase(a);} catch(...) {}
  owner.unlock();late_save.join();late_load.join();
  assert(save_denied && load_denied && a.marker && a.blob);
  cd::require_no_pending(b.marker); assert(b.blob); // A is not B
  // Ordinary window-close performs no store transaction at all.
  auto before=b; cd::require_no_pending(b.marker);
  assert(b.blob==before.blob && b.marker==before.marker);
  std::cout << "pending logout write-ahead/fault/recovery/concurrency policy: passed\n";
}
