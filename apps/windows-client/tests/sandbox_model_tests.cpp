// Portable behaviour of the sandbox list on this computer and of what the
// window shows for each sandbox.
#include "orangespace/sandbox_status.hpp"
#include "orangespace/sandbox_store.hpp"

#include <cassert>
#include <cstdio>
#include <functional>
#include <string>

namespace sb = orangespace::sandbox;

namespace {
const std::string A = "aaaaaaaa-0000-4000-8000-00000000000a";
const std::string B = "bbbbbbbb-0000-4000-8000-00000000000b";
const std::string N1 = "11111111-1111-4111-8111-111111111111";
const std::string N2 = "22222222-2222-4222-8222-222222222222";

bool throws(const std::function<void()>& f) {
  try {
    f();
  } catch (const sb::StoreError&) {
    return true;
  }
  return false;
}

void round_trip_keeps_order_names_and_bindings() {
  sb::Store s;
  s.add({A, "工作 \"A\"", N1});
  s.add({B, "  个人  ", N2});
  const auto back = sb::Store::parse(s.serialize());
  assert(back.records().size() == 2);
  assert(back.records()[0].id == A && back.records()[0].name == "工作 \"A\"" && back.records()[0].node_id == N1);
  assert(back.records()[1].name == "个人");  // trimmed when added
  assert(back.serialize() == s.serialize());
}

void parse_rejects_anything_unexpected() {
  assert(throws([] { sb::Store::parse("not json"); }));
  assert(throws([] { sb::Store::parse(R"({"schema":2,"sandboxes":[]})"); }));
  assert(throws([] { sb::Store::parse(R"({"schema":1,"sandboxes":[],"extra":1})"); }));
  assert(throws([&] {
    sb::Store::parse(R"({"schema":1,"sandboxes":[{"id":")" + A + R"(","name":"x","node_id":")" + N1 +
                     R"(","owner":"y"}]})");
  }));
  assert(throws([&] {  // the same sandbox twice
    const auto one = R"({"id":")" + A + R"(","name":"x","node_id":")" + N1 + R"("})";
    sb::Store::parse(R"({"schema":1,"sandboxes":[)" + one + "," + one + "]}");
  }));
  assert(throws([&] {  // upper-case UUIDs are not canonical
    sb::Store::parse(R"({"schema":1,"sandboxes":[{"id":"AAAAAAAA-0000-4000-8000-00000000000A","name":"x","node_id":")" +
                     N1 + R"("}]})");
  }));
  assert(sb::Store::parse(R"({"schema":1,"sandboxes":[]})").records().empty());
}

void names_are_bounded_printable_text() {
  assert(sb::valid_name("  橙域 1 ") == "橙域 1");
  assert(throws([] { sb::valid_name("   "); }));
  assert(throws([] { sb::valid_name("a\nb"); }));
  assert(throws([] { sb::valid_name("\xff\xfe"); }));
  std::string forty, forty_one;
  for (int i = 0; i < 40; ++i) forty += "沙";
  forty_one = forty + "x";
  assert(sb::valid_name(forty) == forty);  // 40 characters, 120 bytes
  assert(throws([&] { sb::valid_name(forty_one); }));
}

void a_sandbox_keeps_one_node_until_rebound() {
  sb::Store s;
  s.add({A, "a", N1});
  s.rebind(A, N2);
  assert(s.find(A)->node_id == N2);
  assert(throws([&] { s.rebind(A, "not-a-node"); }));
  assert(throws([&] { s.rebind(B, N1); }));
  s.remove(A);
  assert(!s.find(A) && s.records().empty());
  assert(throws([&] { s.remove(A); }));
}

void the_list_is_bounded() {
  sb::Store s;
  for (std::size_t i = 0; i < sb::kMaxSandboxes; ++i) {
    char id[37];
    std::snprintf(id, sizeof id, "aaaaaaaa-0000-4000-8000-%012zu", i);
    s.add({id, "s", N1});
  }
  assert(throws([&] { s.add({B, "one too many", N1}); }));
}

void status_never_claims_more_than_observed() {
  sb::Status s;
  assert(sb::desktop_label(s) == "已停止" && sb::network_label(s) == "—" && sb::lease_label(s) == "—");

  s.phase = sb::Phase::starting;
  assert(sb::lease_label(s) == "正在建立" && sb::network_label(s) == "网络离线");

  s.phase = sb::Phase::running;
  s.window_open = true;
  s.lease_ms_left = 12001;
  s.network = sb::network_from_guest("online");
  assert(sb::desktop_label(s) == "运行中" && sb::network_label(s) == "节点在线" && sb::lease_label(s) == "有效 · 剩余 13 秒");
  s.network = sb::network_from_guest("gateway-ready");
  assert(sb::network_label(s) == "网关就绪");
  s.network = sb::network_from_guest("something else");
  assert(sb::network_label(s) == "检查中");

  // A lapsed lease is no network, whatever the guest said last.
  s.network = sb::Network::online;
  s.lease_ms_left = 0;
  assert(sb::network_label(s) == "网络离线" && sb::lease_label(s) == "已失效，正在重建");

  s.window_open = false;
  assert(sb::desktop_label(s) == "运行中（窗口已关闭）");
  s.phase = sb::Phase::failed;
  assert(sb::desktop_label(s) == "启动失败" && sb::network_label(s) == "—");
}
}  // namespace

int main() {
  round_trip_keeps_order_names_and_bindings();
  parse_rejects_anything_unexpected();
  names_are_bounded_printable_text();
  a_sandbox_keeps_one_node_until_rebound();
  the_list_is_bounded();
  status_never_claims_more_than_observed();
  std::puts("sandbox model tests passed");
  return 0;
}
