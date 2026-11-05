// Standalone semantic/public-DOM regression cases. No allocation hooks.
#include "orangespace/json.hpp"
#include <cstdio>
#include <stdexcept>
#include <type_traits>
namespace j = orangespace::json;
static unsigned checks;
static void need(bool ok) { ++checks; if (!ok) throw std::runtime_error("semantic check failed"); }
static bool accepts(std::string_view input) {
  try { auto v = j::parse(input); j::wipe(v); return true; }
  catch (const std::runtime_error&) { return false; }
}
int main() {
  static_assert(std::is_copy_constructible_v<j::Value>);
  static_assert(std::is_copy_assignable_v<j::Value>);
  static_assert(std::is_nothrow_default_constructible_v<j::Value>);
  static_assert(std::is_same_v<j::Value::Array, std::vector<j::Value>>);
  static_assert(std::is_same_v<j::Value::Object, std::map<std::string,j::Value,std::less<>>>);
  auto root = j::parse(R"({"unknown":{"secret":"QQQQQQQQ"},"values":[null,true,false,-1.25e2,"\u0041\uD83D\uDE00",[],{}]})");
  need(root.find("missing") == nullptr);
  need(root.find("unknown")->find("secret")->text() == "QQQQQQQQ");
  const auto& array = std::get<j::Value::Array>(root.find("values")->data);
  need(array.size() == 7);
  need(std::holds_alternative<std::nullptr_t>(array[0].data));
  need(array[1].is_true() && !array[2].is_true());
  need(std::get<double>(array[3].data) == -125.0);
  need(array[4].text() == "A\xF0\x9F\x98\x80");
  j::Value copied = root;
  need(copied.find("unknown")->find("secret")->text() == "QQQQQQQQ");
  j::wipe(copied); j::wipe(root);
  j::Value constructed[] = {nullptr, true, std::string("text"), j::Value::Array{}, j::Value::Object{}, 2.0};
  for (std::size_t i = 0; i != 6; ++i) need(constructed[i].data.index() == i);
  for (const char* invalid : {"", "[1,]", "[,1]", "[1 2]", "[}", "[{]}", "[[]", "[\"\\\"]", "[null]x", "01", "-01", "1.", "1e", "1e+", "1e9999", "NaN", "Infinity", "{\"x\":1,\"\\u0078\":2}", "\"\\uD800\"", "\"\\uDC00\"", "\"\\uD800\\u0041\"", "\"\\x41\"", "\"\n\""}) need(!accepts(invalid));
  need(accepts(std::string(32, '[') + "0" + std::string(32, ']')));
  need(!accepts(std::string(33, '[') + "0" + std::string(33, ']')));
  need(accepts(std::string(33, '[') + std::string(33, ']'))); // empty container at depth 32
  need(!accepts(std::string(34, '[') + std::string(34, ']')));
  need(accepts("null" + std::string(1024 * 1024 - 4, ' ')));
  need(!accepts("null" + std::string(1024 * 1024 - 3, ' ')));
  // Maximize direct array separators: capacity must be reserved before children.
  std::string wide = "[null";
  for (unsigned i = 0; i != 4096; ++i) wide += ",null";
  wide += "]";
  auto many = j::parse(wide);
  need(std::get<j::Value::Array>(many.data).size() == 4097);
  j::wipe(many);
  std::printf("in-place semantic/public DOM: %u checks PASS\n", checks);
}
