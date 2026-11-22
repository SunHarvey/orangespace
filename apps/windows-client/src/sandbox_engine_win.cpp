#include "orangespace/sandbox_engine.hpp"

#include "orangespace/json.hpp"
#include "orangespace/node_federation.hpp"

#include <bcrypt.h>

#include <algorithm>
#include <chrono>
#include <stdexcept>
#include <utility>

namespace orangespace::sandbox {
namespace ps = orangespace::platform_session;
namespace ns = orangespace::node_session;
namespace nd = orangespace::node_session::detail;
namespace pp = orangespace::node_federation;

namespace {
constexpr std::int64_t kRenewEveryMs = 10000;
constexpr std::int64_t kRetryMs = 3000;

struct Secret {
  std::string value;
  Secret() = default;
  Secret(const Secret&) = delete;
  Secret& operator=(const Secret&) = delete;
  ~Secret() { nd::wipe(value.data(), value.size()); }
};

std::string json_string(std::string_view text) {
  std::string out = "\"";
  static constexpr char hex[] = "0123456789abcdef";
  for (const unsigned char c : text) {
    if (c == '"' || c == '\\') {
      out += '\\';
      out += static_cast<char>(c);
    } else if (c < 0x20) {
      out += "\\u00";
      out += hex[c >> 4];
      out += hex[c & 15];
    } else {
      out += static_cast<char>(c);
    }
  }
  return out + "\"";
}

std::int64_t unix_seconds() {
  return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}
std::int64_t unix_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
      .count();
}

std::string uuid4() {
  unsigned char b[16];
  if (BCryptGenRandom(nullptr, b, sizeof b, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) throw std::runtime_error("no randomness");
  b[6] = static_cast<unsigned char>((b[6] & 0x0f) | 0x40);
  b[8] = static_cast<unsigned char>((b[8] & 0x3f) | 0x80);
  static constexpr char hex[] = "0123456789abcdef";
  std::string out;
  for (int i = 0; i < 16; ++i) {
    if (i == 4 || i == 6 || i == 8 || i == 10) out += '-';
    out += hex[b[i] >> 4];
    out += hex[b[i] & 15];
  }
  return out;
}

// Short, secret-free reason for the status line and the log.
std::string reason(const std::exception& e) {
  if (const auto* s = dynamic_cast<const ns::HttpStatusError*>(&e)) return "node HTTP " + std::to_string(s->status_code());
  if (const auto* s = dynamic_cast<const ps::HttpStatusError*>(&e)) return "Centre HTTP " + std::to_string(s->status_code());
  std::string text = e.what();
  return text.size() > 200 ? text.substr(0, 200) : text;
}

bool status_is(const std::exception& e, unsigned code) {
  const auto* s = dynamic_cast<const ns::HttpStatusError*>(&e);
  return s && s->status_code() == code;
}

std::string text_or_empty(const json::Value& v, std::string_view key) {
  const auto* f = v.find(key);
  return f && std::get_if<std::string>(&f->data) ? std::get<std::string>(f->data) : std::string();
}
}  // namespace

Centre::Centre(ps::Session session, std::function<void(const std::string&)> log)
    : session_(std::move(session)), log_(std::move(log)) {
  refresher_ = std::thread([this] { keep_fresh(); });
}

Centre::~Centre() {
  {
    std::lock_guard lock(mutex_);
    closing_ = true;
  }
  wake_.notify_all();
  if (refresher_.joinable()) refresher_.join();
}

void Centre::keep_fresh() noexcept {
  // Retries stay well inside the Centre's lost-response window.
  constexpr auto kRetry = std::chrono::seconds(20);
  std::unique_lock lock(mutex_);
  while (!closing_ && session_.renewable()) {
    const auto wait = std::chrono::seconds((std::max<std::int64_t>)(0, session_.renew_at() - unix_seconds()));
    if (wake_.wait_for(lock, wait, [&] { return closing_; })) break;
    try {
      session_.refresh();
      if (log_) log_("Centre session refreshed");
    } catch (const std::exception& e) {
      if (log_) log_("Centre session refresh failed: " + reason(e));
      if (!session_.renewable()) break;  // the Centre refused: the session has ended
      if (wake_.wait_for(lock, kRetry, [&] { return closing_; })) break;
    }
  }
}

ps::CentralIdentity Centre::identity() const {
  std::lock_guard lock(mutex_);
  return session_.identity();
}

std::vector<ps::NodeRef> Centre::nodes() {
  std::lock_guard lock(mutex_);
  return session_.nodes();
}

ps::ExchangeTicket Centre::issue(std::string_view node_id) {
  std::lock_guard lock(mutex_);
  session_.revalidate();
  return session_.issue(node_id);
}

void Centre::logout() {
  std::lock_guard lock(mutex_);
  closing_ = true;
  wake_.notify_all();
  session_.logout();
}

// One sandbox's own node session (never shared with another sandbox). The
// session is neither copyable nor movable, so it is built in place.
struct Bound {
  ns::NodeSession session;
  Bound(const ns::TrustedCatalog& catalog, const std::string& name, std::string_view token)
      : session(ns::NodeSession::restore(catalog, name, token)) {}
};

// One sandbox. Fields under "shared" are guarded by Engine::mutex_; the rest
// belong to the worker thread alone.
struct Engine::Worker {
  Spec spec;
  std::thread thread;
  // shared
  Status status;
  std::int64_t deadline_ms{0};  // monotonic; the current lease's end
  bool quit{false}, reopen{false}, done{true}, erasing{false};
  enum class Start { none, running, ok, failed } start{Start::none};
  std::string start_error;
  // worker only
  std::thread starter;
  std::unique_ptr<Bound> node;
  ps::NodeRef ref;
  const nd::NodeEntry* pin{};
  std::string tunnel;
  std::int64_t generation{0};
  int failures{0};
  OfflineWatch offline;
};

Engine::Engine(const ns::TrustedCatalog& catalog, Centre& centre, wsl::Agent& agent, std::string probe_json,
               std::function<void(const std::string&)> log)
    : catalog_(catalog),
      centre_(centre),
      agent_(agent),
      probe_(std::move(probe_json)),
      log_(std::move(log)),
      user_id_(centre.identity().central_user_id) {}

Engine::~Engine() { shutdown(); }

void Engine::note(const Worker& w, const std::string& line) const {
  if (log_) log_("[" + w.spec.id + "] " + line);
}

void Engine::set(Worker& w, const std::function<void(Status&)>& change) {
  std::lock_guard lock(mutex_);
  change(w.status);
}

Engine::Worker& Engine::prepare(const Spec& spec) {
  auto& slot = workers_[spec.id];
  if (!slot) slot = std::make_unique<Worker>();
  auto& w = *slot;
  if (w.thread.joinable()) w.thread.join();  // finished: done is set as its last step
  w.spec = spec;
  w.status = Status{};
  w.status.phase = Phase::starting;
  w.status.node_id = spec.node_id;
  w.deadline_ms = 0;
  w.quit = w.reopen = false;
  w.done = false;
  w.start = Worker::Start::none;
  w.start_error.clear();
  w.node.reset();
  w.tunnel.clear();
  w.failures = 0;
  return w;
}

void Engine::open(const Spec& spec) {
  nd::require(nd::uuid(spec.id) && nd::uuid(spec.node_id));
  std::lock_guard lock(mutex_);
  if (closing_) throw std::runtime_error("the client is closing");
  const auto it = workers_.find(spec.id);
  if (it != workers_.end()) {
    auto& w = *it->second;
    if (w.erasing) throw std::runtime_error("the sandbox is being deleted");
    if (!w.done) {
      if (w.quit) throw std::runtime_error("the sandbox is stopping");
      if (w.spec.node_id != spec.node_id) throw std::runtime_error("stop the sandbox before changing its node");
      w.reopen = true;
      wake_.notify_all();
      return;
    }
  }
  auto& w = prepare(spec);
  w.thread = std::thread([this, &w] { run(w); });
}

void Engine::stop(const std::string& id) {
  std::lock_guard lock(mutex_);
  const auto it = workers_.find(id);
  if (it == workers_.end() || it->second->done) return;
  it->second->quit = true;
  it->second->status.phase = Phase::stopping;
  wake_.notify_all();
}

void Engine::erase(const std::string& id, std::function<void(bool, std::string)> done) {
  nd::require(nd::uuid(id));
  std::lock_guard lock(mutex_);
  if (closing_) throw std::runtime_error("the client is closing");
  auto& slot = workers_[id];
  if (!slot) {
    slot = std::make_unique<Worker>();
    slot->spec.id = id;
  }
  auto& w = *slot;
  if (w.erasing) throw std::runtime_error("the sandbox is being deleted");
  w.erasing = true;
  if (!w.done) {
    w.quit = true;
    w.status.phase = Phase::stopping;
    wake_.notify_all();
  }
  erasers_.emplace_back([this, &w, id, done = std::move(done)] {
    {
      std::unique_lock lock(mutex_);
      wake_.wait(lock, [&] { return w.done; });
      w.status = Status{};
      w.status.phase = Phase::deleting;
    }
    bool ok = true;
    std::string error;
    try {
      agent_call("{\"op\":\"desktop.delete\",\"user\":" + json_string(user_id_) + ",\"sandbox\":" + json_string(id) + "}",
                 300000);
      note(w, "desktop data deleted");
    } catch (const std::exception& e) {
      ok = false;
      error = reason(e);
      note(w, "delete failed: " + error);
    }
    {
      std::lock_guard lock(mutex_);
      w.status = Status{};
      if (!ok) w.status.error = error;
      w.erasing = false;
    }
    if (done) done(ok, error);
  });
}

Status Engine::status(const std::string& id) const {
  std::lock_guard lock(mutex_);
  const auto it = workers_.find(id);
  if (it == workers_.end()) return Status{};
  auto s = it->second->status;
  s.lease_ms_left = active(s.phase) ? (std::max<std::int64_t>)(0, it->second->deadline_ms - nd::monotonic_ms()) : 0;
  return s;
}

bool Engine::any_active() const {
  std::lock_guard lock(mutex_);
  return std::any_of(workers_.begin(), workers_.end(), [](const auto& p) { return !p.second->done || p.second->erasing; });
}

void Engine::shutdown() noexcept {
  std::vector<std::thread> threads;
  {
    std::lock_guard lock(mutex_);
    closing_ = true;
    for (auto& [id, w] : workers_) {
      if (!w->done) {
        w->quit = true;
        w->status.phase = Phase::stopping;
      }
      if (w->thread.joinable()) threads.push_back(std::move(w->thread));
    }
    for (auto& t : erasers_) threads.push_back(std::move(t));
    erasers_.clear();
    wake_.notify_all();
  }
  for (auto& t : threads) t.join();  // workers stop in parallel
}

std::string Engine::agent_call(std::string_view request, DWORD timeout_ms) {
  auto reply = agent_.request(request, timeout_ms);
  if (reply.find("\"error\"") != std::string::npos) {
    std::string detail = "guest refused";
    try {
      detail = "guest: " + text_or_empty(json::parse(reply), "error");
    } catch (const std::exception&) {
    }
    throw std::runtime_error(detail.substr(0, 240));
  }
  return reply;
}

void Engine::run(Worker& w) noexcept {
  std::int64_t next = 0;
  note(w, "opening on node " + w.spec.node_id);
  for (;;) {
    bool reopen = false, running = false;
    Worker::Start start;
    std::string start_error;
    {
      std::unique_lock lock(mutex_);
      wake_.wait_for(lock, std::chrono::milliseconds((std::max<std::int64_t>)(0, next - nd::monotonic_ms())), [&] {
        return w.quit || w.reopen || nd::monotonic_ms() >= next || w.start == Worker::Start::ok ||
               w.start == Worker::Start::failed;
      });
      if (w.quit) break;
      reopen = std::exchange(w.reopen, false);
      start = w.start;
      start_error = w.start_error;
      if (start == Worker::Start::ok) {
        w.start = Worker::Start::none;  // seen; the desktop is up
        w.status.phase = Phase::running;
      }
      running = w.status.phase == Phase::running;
    }
    if (start == Worker::Start::failed) {
      note(w, "desktop did not start: " + start_error);
      set(w, [&](Status& s) {
        s.phase = Phase::failed;
        s.error = start_error;
      });
      break;
    }
    if (start == Worker::Start::ok) {
      note(w, "desktop running");
      next = 0;  // refresh its status now
    }
    if (reopen && running) {
      start_desktop(w);  // brings the window back; the guest does not restart a running desktop
      refresh(w);
    }
    if (nd::monotonic_ms() < next) continue;
    try {
      if (w.tunnel.empty()) connect(w);
      else renew(w);
      w.failures = 0;
      next = nd::monotonic_ms() + kRenewEveryMs;
      set(w, [](Status& s) { s.error.clear(); });
    } catch (const std::exception& e) {
      // A renewal the node refuses (or that cannot be checked) is never retried
      // on the same tunnel: the next attempt creates a new one with a higher
      // generation, which the Centre makes the only valid one. The old permit
      // lapses in the guest on its own. Repeated failures to set up a tunnel
      // start over with a new node session.
      const auto why = reason(e);
      if (!w.tunnel.empty()) {
        note(w, "renewal failed (" + why + "); new tunnel next");
        try {
          w.node->session.revoke_tunnel(w.tunnel);  // best effort; it lapses on its own anyway
        } catch (const std::exception&) {
        }
        w.tunnel.clear();
      } else {
        note(w, "tunnel setup failed (" + why + "); retrying");
        if (status_is(e, 401) || ++w.failures >= 2) {
          w.node.reset();
          w.failures = 0;
        }
      }
      {
        std::lock_guard lock(mutex_);
        w.deadline_ms = 0;  // no claim of a valid lease once the node refused it
        w.status.error = why;
      }
      next = nd::monotonic_ms() + kRetryMs;
      continue;
    }
    {
      std::lock_guard lock(mutex_);
      running = w.status.phase == Phase::running;
    }
    if (!running) continue;
    refresh(w);
    Network network;
    {
      std::lock_guard lock(mutex_);
      network = w.status.phase == Phase::running ? w.status.network : Network::unknown;
    }
    if (w.offline.observe(network)) {
      note(w, "no network through a valid lease; new tunnel");
      try {
        w.node->session.revoke_tunnel(w.tunnel);
      } catch (const std::exception&) {
      }
      w.tunnel.clear();
      {
        std::lock_guard lock(mutex_);
        w.deadline_ms = 0;
      }
      next = 0;
    }
  }
  finish(w);
}

void Engine::exchange(Worker& w) {
  w.node.reset();
  const auto refs = centre_.nodes();
  const auto found = std::find_if(refs.begin(), refs.end(), [&](const auto& r) { return r.node_id == w.spec.node_id; });
  if (found == refs.end()) throw std::runtime_error("the Centre grants no access to this node");
  if (std::find(found->scopes.begin(), found->scopes.end(), "tunnel") == found->scopes.end())
    throw std::runtime_error("no tunnel grant on this node");
  w.ref = *found;
  w.pin = &catalog_.federation_node(w.spec.node_id);
  pp::match_catalog(w.ref, *w.pin);
  const auto identity = centre_.identity();
  auto ticket = centre_.issue(w.spec.node_id);
  Secret body;
  body.value = "{\"schema\":1,\"exchange_id\":\"" + ticket.exchange_id + "\",\"exchange_token\":\"";
  body.value.append(ticket.exchange_token.view());
  body.value += "\"}";
  catalog_.federation_exchange(w.spec.node_id, body.value, false, [&](std::string_view bytes) {
    nd::exact_wire_integers(bytes);
    nd::JsonGuard doc(bytes);
    const auto expiry = pp::validate_exchange(doc.value, identity, w.ref, unix_seconds());
    const auto& token = nd::text(nd::field(nd::field(doc.value, "node_credential"), "access_token"));
    auto node = std::make_unique<Bound>(catalog_, w.pin->name, token);
    nd::require(node->session.identity().user_id == w.ref.remote_legacy_user_id &&
                node->session.identity().node_id == w.spec.node_id && node->session.expires_at() == expiry);
    w.node = std::move(node);
  });
  nd::require(w.node != nullptr);
  note(w, "node session exchanged");
}

void Engine::connect(Worker& w) {
  if (!w.node || w.node->session.expires_at() <= unix_seconds() + 60) exchange(w);
  // Generations only rise, also across runs: the Centre refuses any other.
  w.generation = (std::max)(w.generation + 1, unix_ms());
  const auto tunnel = uuid4();
  const auto request = "{\"sandbox_id\":\"" + w.spec.id + "\",\"generation\":" + std::to_string(w.generation) +
                       ",\"tunnel_id\":\"" + tunnel + "\"}";
  auto lease = w.node->session.create_tunnel(request);
  std::int64_t deadline = 0;
  Secret message;
  {
    nd::JsonGuard reply(lease.payload);
    const auto& r = reply.value;
    nd::require(nd::text(nd::field(r, "tunnel_id")) == tunnel && nd::text(nd::field(r, "sandbox_id")) == w.spec.id);
    deadline = lease.budget.deadline_ms;
    const auto remaining = deadline - nd::monotonic_ms();
    nd::require(remaining > 1000);
    Secret record;
    record.value = "{\"node_id\":" + json_string(w.spec.node_id) + ",\"tunnel_id\":" + json_string(tunnel) +
                   ",\"endpoint_ip\":" + json_string(nd::text(nd::field(r, "endpoint_ip"))) +
                   ",\"endpoint_port\":" + std::to_string(nd::integer(nd::field(r, "endpoint_port"))) +
                   ",\"tls_server_name\":" + json_string(nd::text(nd::field(r, "tls_server_name"))) +
                   ",\"certificate_pem\":" + json_string(*w.pin->ca_pem) +
                   ",\"uuid\":" + json_string(nd::text(nd::field(r, "tuic_uuid"))) +
                   ",\"password\":" + json_string(nd::text(nd::field(r, "tuic_password"))) +
                   ",\"remaining_ms\":" + std::to_string(remaining) +
                   (probe_.empty() ? std::string() : ",\"probe\":" + probe_) + "}";
    message.value = "{\"op\":\"desktop.lease\",\"user\":" + json_string(user_id_) + ",\"sandbox\":" +
                    json_string(w.spec.id) + ",\"node\":" + json_string(w.spec.node_id) +
                    ",\"lease\":" + json_string(record.value) + "}";
  }
  w.tunnel = tunnel;  // revoked in finish() even if the guest refuses it
  agent_call(message.value, 60000);
  bool start = false;
  {
    std::lock_guard lock(mutex_);
    w.deadline_ms = deadline;
    if (w.status.phase == Phase::starting && w.start == Worker::Start::none) {
      w.start = Worker::Start::running;
      start = true;
    }
  }
  note(w, "tunnel " + tunnel + " generation " + std::to_string(w.generation) + " on " + w.pin->name);
  if (start) {
    // The desktop starts in the background so this worker keeps renewing the
    // lease while it does (the first start can take longer than a lease).
    w.starter = std::thread([this, &w] { start_desktop(w); });
  }
}

void Engine::start_desktop(Worker& w) noexcept {
  bool first;
  {
    std::lock_guard lock(mutex_);
    first = w.start == Worker::Start::running;
  }
  try {
    agent_call("{\"op\":\"desktop.start\",\"user\":" + json_string(user_id_) + ",\"sandbox\":" + json_string(w.spec.id) +
                   ",\"node\":" + json_string(w.spec.node_id) + ",\"title\":" + json_string(w.spec.title) + "}",
               300000);
    if (first) {
      std::lock_guard lock(mutex_);
      w.start = Worker::Start::ok;
      wake_.notify_all();
    } else {
      note(w, "window reopened");
    }
  } catch (const std::exception& e) {
    if (first) {
      std::lock_guard lock(mutex_);
      w.start = Worker::Start::failed;
      w.start_error = reason(e);
      wake_.notify_all();
    } else {
      set(w, [&](Status& s) { s.error = reason(e); });
    }
  }
}

void Engine::renew(Worker& w) {
  const auto result = w.node->session.renew_tunnel(w.tunnel);
  const auto remaining = result.budget.deadline_ms - nd::monotonic_ms();
  nd::require(remaining > 1000);
  agent_call("{\"op\":\"desktop.renew\",\"user\":" + json_string(user_id_) + ",\"sandbox\":" + json_string(w.spec.id) +
                 ",\"tunnel\":" + json_string(w.tunnel) + ",\"remaining_ms\":" + std::to_string(remaining) + "}",
             15000);
  std::lock_guard lock(mutex_);
  w.deadline_ms = result.budget.deadline_ms;
}

void Engine::refresh(Worker& w) {
  try {
    const auto reply = json::parse(agent_call(
        "{\"op\":\"desktop.status\",\"user\":" + json_string(user_id_) + ",\"sandbox\":" + json_string(w.spec.id) + "}",
        20000));
    const auto desktop = text_or_empty(reply, "desktop");
    std::lock_guard lock(mutex_);
    w.status.network = network_from_guest(text_or_empty(reply, "network"));
    w.status.window_open = text_or_empty(reply, "window") == "open";
    if (desktop == "stopped" && !w.quit) {
      // Gone from under us (for example the distribution was shut down).
      w.status.phase = Phase::failed;
      w.status.error = "the desktop stopped";
      w.quit = true;
    }
  } catch (const std::exception& e) {
    set(w, [&](Status& s) {
      s.network = Network::unknown;
      s.error = reason(e);
    });
  }
}

void Engine::finish(Worker& w) noexcept {
  if (!w.tunnel.empty() && w.node) {
    try {
      w.node->session.revoke_tunnel(w.tunnel);
      note(w, "tunnel revoked");
    } catch (const std::exception& e) {
      note(w, "revoke failed (" + reason(e) + "); the lease lapses on its own");
    }
  }
  bool started;
  {
    std::lock_guard lock(mutex_);
    w.deadline_ms = 0;  // renewals have stopped
    started = w.start != Worker::Start::none || w.status.phase == Phase::running || w.status.phase == Phase::failed ||
              w.starter.joinable();
  }
  if (started) {
    // The guest serializes this behind a start still in progress.
    try {
      agent_call("{\"op\":\"desktop.stop\",\"user\":" + json_string(user_id_) + ",\"sandbox\":" + json_string(w.spec.id) +
                     "}",
                 180000);
      note(w, "desktop stopped");
    } catch (const std::exception& e) {
      note(w, "stop failed: " + reason(e));
    }
  }
  if (w.starter.joinable()) w.starter.join();
  w.node.reset();
  w.tunnel.clear();
  std::lock_guard lock(mutex_);
  if (w.status.phase != Phase::failed) w.status.phase = Phase::stopped;
  w.status.network = Network::unknown;
  w.status.window_open = false;
  w.done = true;
  wake_.notify_all();
}

}  // namespace orangespace::sandbox
