#pragma once
// What the client shows for each sandbox. Portable; the engine fills Status,
// the window turns it into text. Nothing here claims more than was observed:
// the network column is what the guest's gateway reported last, and a lapsed
// lease means no network (there is no direct path to fall back to).
#include <cstdint>
#include <string>

namespace orangespace::sandbox {

enum class Phase { stopped, starting, running, stopping, failed, deleting };
enum class Network { unknown, offline, gateway_ready, online };

struct Status {
  Phase phase{Phase::stopped};
  Network network{Network::unknown};
  bool window_open{false};
  std::int64_t lease_ms_left{0};  // > 0 only while the current tunnel's lease is valid
  std::string node_id;            // the node the running desktop is bound to
  std::string error;              // last failure, short and free of secrets
};

inline Network network_from_guest(const std::string& value) {
  if (value == "online") return Network::online;
  if (value == "gateway-ready") return Network::gateway_ready;
  if (value == "offline") return Network::offline;
  return Network::unknown;
}

inline bool active(Phase p) { return p == Phase::starting || p == Phase::running; }

inline std::string desktop_label(const Status& s) {
  switch (s.phase) {
    case Phase::stopped: return "已停止";
    case Phase::starting: return "正在启动";
    case Phase::running: return s.window_open ? "运行中" : "运行中（窗口已关闭）";
    case Phase::stopping: return "正在停止";
    case Phase::failed: return "启动失败";
    case Phase::deleting: return "正在删除";
  }
  return "未知";
}

inline std::string network_label(const Status& s) {
  if (!active(s.phase)) return "—";
  if (s.lease_ms_left <= 0) return "网络离线";
  switch (s.network) {
    case Network::online: return "节点在线";
    case Network::gateway_ready: return "网关就绪";
    case Network::offline: return "网络离线";
    case Network::unknown: return "检查中";
  }
  return "检查中";
}

inline std::string lease_label(const Status& s) {
  if (!active(s.phase)) return "—";
  if (s.lease_ms_left <= 0) return s.phase == Phase::starting ? "正在建立" : "已失效，正在重建";
  return "有效 · 剩余 " + std::to_string((s.lease_ms_left + 999) / 1000) + " 秒";
}

}  // namespace orangespace::sandbox
