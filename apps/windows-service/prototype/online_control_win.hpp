#pragma once
#include "orangespace/windows_service.hpp"
#include "orangespace/prototype_local_channel.hpp"
#include <memory>
#include "../../windows-client/prototype/private_channel.hpp"
namespace orangespace::service::win {
// Construct only after actual active/unlocked WTS selection and Offline install.
// This owner grants neither BrowserPermit nor any WFP/loopback permission.
class PrototypeControl final {
 public:
  PrototypeControl(Peer actualSelectedWTS, HANDLE serviceStop, std::string_view expectedSGNodeUUID);
  ~PrototypeControl();
  PrototypeControl(const PrototypeControl&)=delete;
  PrototypeControl& operator=(const PrototypeControl&)=delete;
  void start();
  std::shared_ptr<const LocalChannel> wait_channel(DWORD timeout_ms);
  // Uses current Engine authority, never the channel's initial grant as renewal.
  void verify_live(const LocalChannel&);
  // Real forwarding probe; returns its conservative monotonic start, not a new grant.
  std::int64_t fresh_forwarding_proof(const LocalChannel&);
  void publish_root(const LocalChannel&,std::string package,std::string profile,DWORD pid,std::uint64_t birth);
  bool desktop_configured();
  bool closing();
  prototype::BrowserFrame next_command();
  void observe(const prototype::BrowserFrame&);
  void finish_run(const LocalChannel&);
  void stopAndJoin() noexcept;
 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};
}
