// Standalone: g++ -std=c++20 -O2 -Iapps/windows-client/include
// apps/windows-client/tests/json_zeroization_tests.cpp -o json-zeroization
// Run each named case or all. Never combine allocation hooks with ASan:
// compile with -DORANGESPACE_JSON_NO_ALLOC_HOOKS for sanitizer semantic tests.
#include "orangespace/node_session.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <string_view>

namespace audit {
struct Allocation { void* pointer; std::size_t size; };
static Allocation live[65536]{};
static bool active = false;
static std::size_t dirty = 0, freed = 0, allocations = 0, fail_at = 0;
static bool marker(const void* p, std::size_t n) {
  const auto* bytes = static_cast<const unsigned char*>(p);
  unsigned run = 0;
  for (std::size_t i = 0; i < n; ++i) {
    run = bytes[i] == 'Q' ? run + 1 : 0;
    if (run == 8) return true;
  }
  return false;
}
#ifndef ORANGESPACE_JSON_NO_ALLOC_HOOKS
static void* allocate(std::size_t n) {
  if (active && ++allocations == fail_at) throw std::bad_alloc();
  void* p = std::malloc(n ? n : 1);
  if (!p) throw std::bad_alloc();
  if (active) {
    // Exclude pre-existing bytes from fixture construction / allocator reuse.
    // Only bytes written during this audited allocation belong to this test.
    std::memset(p, 0, n);
    for (auto& slot : live) if (!slot.pointer) { slot = {p, n}; return p; }
    std::abort();
  }
  return p;
}
static void release(void* p) noexcept {
  if (!p) return;
  for (auto& slot : live) if (slot.pointer == p) {
    ++freed;
    if (marker(p, slot.size)) ++dirty;
    slot = {};
    break;
  }
  std::free(p);
}
#endif
static void begin(std::size_t failure = 0) {
  dirty = freed = allocations = 0; fail_at = failure; active = true;
}
static bool end() {
  active = false;
  bool empty = true;
  for (const auto& slot : live) if (slot.pointer) empty = false;
  return dirty == 0 && empty;
}
}
#ifndef ORANGESPACE_JSON_NO_ALLOC_HOOKS
void* operator new(std::size_t n) { return audit::allocate(n); }
void* operator new[](std::size_t n) { return audit::allocate(n); }
void operator delete(void* p) noexcept { audit::release(p); }
void operator delete[](void* p) noexcept { audit::release(p); }
void operator delete(void* p, std::size_t) noexcept { audit::release(p); }
void operator delete[](void* p, std::size_t) noexcept { audit::release(p); }
#endif

namespace ns = orangespace::node_session;
static bool exercise(std::string_view input, bool valid, bool envelope, std::size_t failure = 0) {
  // The caller-owned fixture/input is constructed BEFORE auditing; its storage
  // is deliberately not scanned or counted as parser-owned memory.
  audit::begin(failure);
  bool accepted = false, oom = false;
  try {
    if (envelope) {
      const ns::detail::NodeEntry node{"office", "11111111-1111-4111-8111-111111111111", "node.example", 443};
      auto reply = ns::detail::validate_envelope(node, input, 1900000000);
      accepted = reply.token.size() == 43 && audit::marker(reply.token.data(), reply.token.size());
    } else {
      ns::detail::JsonGuard document(input);
      accepted = true;
    }
  } catch (const std::bad_alloc&) { oom = true; }
    catch (const std::runtime_error&) {}
  const bool clean = audit::end();
  // An injected site must actually be reached and propagate bad_alloc; a
  // swallowed failure or a changed path is not allocation-failure coverage.
  return clean && (failure ? oom : (!oom && accepted == valid));
}
#ifndef ORANGESPACE_JSON_NO_ALLOC_HOOKS
static bool allocation_coverage(bool valid, std::size_t freed, std::size_t allocations) {
  // Invalid input can be rejected by the structural prescan before DOM storage
  // is allocated. Exception storage need not use our replaceable operator new.
  // Valid cases must still exercise real allocations and their clean release.
  return (!valid && allocations == 0 && freed == 0) ||
         (freed > 0 && allocations > 0);
}
// Predicate regression, not a simulation of MSVC exception storage. Rejection
// and audit::end() cleanliness are independently required by exercise().
static bool allocation_coverage_regression() {
  return allocation_coverage(false, 0, 0) &&
         !allocation_coverage(true, 0, 0) &&
         !allocation_coverage(true, 0, 1) &&
         !allocation_coverage(false, 0, 1) &&
         !allocation_coverage(false, 1, 0) &&
         allocation_coverage(true, 1, 1) &&
         allocation_coverage(false, 1, 1);
}
#endif
int main(int argc, char** argv) {
  const std::string token(43, 'Q'); // Known non-production marker; never printed.
  const std::string envelope = std::string(R"({"schema":1,"node_id":"11111111-1111-4111-8111-111111111111","api_origin":"https://node.example:443","access_token":")") + token + R"(","expires_at":2000000000})";
  const std::string long_value(8192, 'Q');
  struct Case { const char* name; std::string input; bool valid; bool envelope; };
  const Case cases[] = {
    {"trailing-envelope", envelope + "{}", false, true},
    {"malformed-tree", "{\"outer\":[{\"token\":\"" + token + "\"},", false, false},
    {"malformed-string", "[\"" + token + "\\uD800x", false, false},
    {"duplicate-key", "{\"token\":\"" + token + "\",\"token\":\"" + token + "\"}", false, false},
    {"long-growth", "[\"" + long_value + "\"]", true, false},
    {"key-lifetime", "{\"" + token + "\": [\"short\",\"" + token + "\"]}", true, false},
    {"short-key-lifetime", "{\"QQQQQQQQ\":\"QQQQQQQQ\"}", true, false},
    {"valid-envelope", envelope, true, true},
    {"escaped-growth", "[\"" + token + "\\u0041\\uD83D\\uDE00" + long_value + "\"]", true, false},
    {"array-growth", "[\"" + token + "\",\"short\",null,true,{},[],0,\"" + token + "\"]", true, false},
    {"duplicate-secret-key", "{\"" + token + "\":1,\"" + token + "\":2}", false, false},
    {"top-string-decode-failure", "\"" + token + "\\uD800x", false, false},
    {"secret-key-decode-failure", "{\"" + token + "\\uD800x", false, false},
    {"prior-secret-scan-failure", "{\"secret\":\"" + token + "\",\"later\":[1,", false, false},
    {"nested-object-secret-key", "{\"" + token + "\":{\"nested\":{\"secret\":\"" + token + "\"}}}", true, false},
    {"top-level-object-return", "{\"" + token + "\":\"" + token + "\"}", true, false},
    {"array-object-growth", "[{\"" + token + "\":{\"secret\":\"" + token + "\"}},null,{},[],true,false,0,1,2,3,4,5,6,7]", true, false},
    {"prescan-escaped-delimiters", R"(["QQQQQQQQ\"],}[",{"key":["QQQQQQQQ",0]},false])", true, false},
    {"prescan-mismatched-braces", R"(["QQQQQQQQ",{]},0])", false, false},
    {"prescan-trailing-comma", R"(["QQQQQQQQ",])", false, false},
    {"prescan-unclosed-quote", R"(["QQQQQQQQ)", false, false},
    {"prescan-nested-truncation", R"(["QQQQQQQQ",{"key":[1,2])", false, false},
    {"depth-failure", "[\"" + token + "\"," + std::string(34, '[') + "0" + std::string(34, ']') + "]", false, false},
  };
  unsigned failed = 0, ran = 0;
  std::size_t failure_points = 0;
#ifndef ORANGESPACE_JSON_NO_ALLOC_HOOKS
  // Prove the actual pre-free observer sees unzeroed memory (no production code).
  audit::begin();
  void* control = ::operator new(64);
  std::memset(control, 'Q', 64);
  ::operator delete(control);
  const bool observed = audit::dirty == 1 && audit::freed == 1;
  audit::end();
  if (!observed) return 2;
  const bool coverage_ok = allocation_coverage_regression();
  std::printf("allocation-coverage-predicate: %s\n", coverage_ok ? "PASS" : "FAIL");
  if (!coverage_ok) return 2;
#endif
  for (const auto& test : cases) {
    if (argc > 1 && std::string_view(argv[1]) != test.name) continue;
    ++ran;
    bool ok = exercise(test.input, test.valid, test.envelope);
#ifndef ORANGESPACE_JSON_NO_ALLOC_HOOKS
    const auto dirty_count = audit::dirty;
    const auto allocation_count = audit::allocations;
    ok = ok && allocation_coverage(test.valid, audit::freed, allocation_count);
    // Every ordinary allocation point, including container insertion, is failed
    // once; successfully allocated parser storage must still be clean at free.
    if (ok) for (std::size_t i = 1; i <= allocation_count; ++i) {
      ++failure_points;
      if (!exercise(test.input, test.valid, test.envelope, i)) ok = false;
    }
    std::printf("%s: %s (dirty frees=%zu; allocation points=%zu)\n", test.name, ok ? "PASS" : "FAIL", dirty_count, allocation_count);
#else
    std::printf("%s: %s (semantic only; allocation hooks disabled)\n", test.name, ok ? "PASS" : "FAIL");
#endif
    if (!ok) ++failed;
  }
  std::printf("cases=%u failed=%u injected allocation points=%zu\n", ran, failed, failure_points);
  return ran && !failed ? 0 : 1;
}
