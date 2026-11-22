#pragma once
// Runs sandboxes whose network is authorized by node leases (Windows only).
// Shared by the OrangeSpace window and the orangespace-sandbox acceptance tool.
//
// Every sandbox has a worker thread of its own, with its own node session and
// tunnel; nothing is shared between sandboxes except the Centre session (calls
// serialized) and the agent channel (concurrent). A worker exchanges a node
// session, creates a tunnel lease, hands it to the guest (credentials over the
// agent's stdin, never a command line), starts the desktop and renews the lease
// every 10 s, extending the guest's kernel permit to each renewed lease. A
// failed renewal gets a new tunnel with a higher generation; repeated failures
// get a new node session. If the client stops for any reason the renewals stop
// and every permit lapses within the lease (at most 30 s). Stopping a sandbox
// revokes its tunnel and stops its desktop.
#include "orangespace/node_session.hpp"
#include "orangespace/platform_session.hpp"
#include "orangespace/sandbox_status.hpp"
#include "orangespace/wsl_runtime.hpp"

#include <chrono>
#include <condition_variable>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace orangespace::sandbox {

// The signed-in Centre session. platform_session::Session is single-threaded;
// every call goes through this lock. A background thread refreshes the
// session while it is renewable, so its credentials rotate in place and the
// holders keep working past the access lifetime; it stops at logout, at
// destruction, or once the Centre refuses the refresh (session ended).
class Centre final : public platform_session::SharedCentre {
 public:
  // log: optional, one secret-free line per refresh event, from the refresher.
  // refreshed: optional, called with the lock held right after each refresh
  // (to save the new renewal when the sign-in is remembered).
  // check_every: how often the refresher looks at the session's clock. Windows
  // timeouts do not count time asleep, so one long wait could end long after
  // the access credential expired; short waits renew soon after a resume.
  explicit Centre(platform_session::Session session, std::function<void(const std::string&)> log = {},
                  std::function<void(const platform_session::Session&)> refreshed = {},
                  std::chrono::milliseconds check_every = std::chrono::seconds(15));
  ~Centre() override;
  Centre(const Centre&) = delete;
  Centre& operator=(const Centre&) = delete;
  platform_session::CentralIdentity identity() const override;
  std::vector<platform_session::NodeRef> nodes() override;
  platform_session::ExchangeTicket issue(std::string_view node_id) override;
  void logout();

 private:
  void keep_fresh() noexcept;
  void renew_locked();  // refresh, log, and save the new renewal; mutex_ held
  template <class F>
  auto with_renewal(F f) -> decltype(f());  // mutex_ held
  mutable std::mutex mutex_;
  std::condition_variable wake_;
  bool closing_{false};
  platform_session::Session session_;
  std::function<void(const std::string&)> log_;
  std::function<void(const platform_session::Session&)> refreshed_;
  std::chrono::milliseconds check_every_;
  std::thread refresher_;
};

struct Spec {
  std::string id;       // sandbox UUID
  std::string node_id;  // bound node UUID
  std::string title;    // desktop window title (at most 64 characters)
};

class Engine {
 public:
  // probe_json: optional HTTPS probe object for the guest ({"ipv4":..,"port":..,"tls_name":..,"path":..}), or empty.
  // log: optional, receives one line per event (no secrets); called from worker threads.
  Engine(const node_session::TrustedCatalog& catalog, Centre& centre, wsl::Agent& agent, std::string probe_json,
         std::function<void(const std::string&)> log = {});
  ~Engine();
  Engine(const Engine&) = delete;
  Engine& operator=(const Engine&) = delete;

  // Starts the sandbox (new lease, then its desktop), or brings back its window
  // if it is already running. Never blocks on the network.
  void open(const Spec& spec);
  // Revokes the tunnel and stops the desktop, in the background.
  void stop(const std::string& id);
  // Stops the sandbox, then deletes its desktop data in the distribution (HOME,
  // browser data, downloads). Files on nodes are never touched. done() runs on
  // a worker thread.
  void erase(const std::string& id, std::function<void(bool ok, std::string error)> done);
  Status status(const std::string& id) const;
  bool any_active() const;
  // Stops every sandbox and waits for it. Blocking; call off the UI thread.
  void shutdown() noexcept;

 private:
  struct Worker;
  void run(Worker& w) noexcept;
  void connect(Worker& w);
  void renew(Worker& w);
  void exchange(Worker& w);
  void refresh(Worker& w);
  void finish(Worker& w) noexcept;
  void start_desktop(Worker& w) noexcept;
  void note(const Worker& w, const std::string& line) const;
  std::string agent_call(std::string_view request, DWORD timeout_ms);
  void set(Worker& w, const std::function<void(Status&)>& change);
  Worker& prepare(const Spec& spec);  // caller holds mutex_

  const node_session::TrustedCatalog& catalog_;
  Centre& centre_;
  wsl::Agent& agent_;
  std::string probe_;
  std::function<void(const std::string&)> log_;
  std::string user_id_;
  mutable std::mutex mutex_;
  std::condition_variable wake_;
  std::map<std::string, std::unique_ptr<Worker>> workers_;
  std::vector<std::thread> erasers_;
  bool closing_{false};
};

}  // namespace orangespace::sandbox
