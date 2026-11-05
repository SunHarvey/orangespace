// GNU structural runtime proof (not a Microsoft STL simulation):
// g++ -std=c++20 -O0 -fno-inline -fno-elide-constructors -finstrument-functions
// -rdynamic -Iapps/windows-client/include json_transfer_tests.cpp -ldl -o transfers
// Build WITHOUT instrumentation on Windows for traits and semantic cases.
#include "orangespace/json.hpp"
#include <cstdio>
#include <cstring>
#include <type_traits>
#if defined(__GNUC__) && !defined(_WIN32)
#include <dlfcn.h>
static bool watching;
static unsigned transfers;
extern "C" __attribute__((no_instrument_function))
void __cyg_profile_func_enter(void* fn, void*) {
  if (!watching) return;
  Dl_info info{};
  if (dladdr(fn, &info) && info.dli_sname &&
      std::strstr(info.dli_sname, "4json5ValueC") &&
      (std::strstr(info.dli_sname, "EOS") || std::strstr(info.dli_sname, "ERKS")))
    ++transfers;
}
extern "C" __attribute__((no_instrument_function))
void __cyg_profile_func_exit(void*, void*) {}
#endif
int main() {
  using namespace orangespace::json;
  std::printf("nothrow move: Object=%d Value=%d; copyable Value=%d\n",
      int(std::is_nothrow_move_constructible_v<Value::Object>),
      int(std::is_nothrow_move_constructible_v<Value>),
      int(std::is_copy_constructible_v<Value>));
#if defined(__GNUC__) && !defined(_WIN32)
  // Positive control: prove the instrumentation observes actual Value moves.
  Value source{Value::Object{}};
  watching = true;
  Value moved{std::move(source)};
  watching = false;
  if (!transfers) { std::puts("move observer positive control FAILED"); return 2; }
  wipe(moved);
#endif
  const char* cases[] = {
    R"(["QQQQQQQQ",{},null,[],true,1,{"QQQQQQQQ":{"nested":"QQQQQQQQ"}},false,"QQQQQQQQ"])",
    R"({"QQQQQQQQ":{"nested":{"secret":"QQQQQQQQ"}}})",
    R"({"QQQQQQQQ":"QQQQQQQQ"})"
  };
  unsigned failed = 0;
  for (const auto input : cases) {
#if defined(__GNUC__) && !defined(_WIN32)
    transfers = 0; watching = true;
#endif
    auto result = parse(input);
#if defined(__GNUC__) && !defined(_WIN32)
    watching = false;
    std::printf("parser Value copies/moves=%u\n", transfers);
    if (transfers) ++failed;
#else
    std::puts("semantic case only; transfer observer unavailable");
#endif
    wipe(result);
  }
  return failed ? 1 : 0;
}
