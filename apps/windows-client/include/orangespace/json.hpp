#pragma once

#include <charconv>
#include <cmath>
#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>
#include <type_traits>
#include <utility>
#include <vector>

namespace orangespace::json {

class Parser;
namespace detail { struct ParseTag {}; }

// A bounded, strict JSON reader for small broker and credential responses.
// Value keeps its ordinary public DOM types; callers owning a successful tree
// containing credentials must call wipe() before destroying it.
struct Value {
  using Array = std::vector<Value>;
  using Object = std::map<std::string, Value, std::less<>>;
  std::variant<std::nullptr_t, bool, std::string, Array, Object, double> data;

  Value() = default;
  // Preserve the ordinary variant-alternative brace construction and implicit
  // Value copy/move operations. The parser itself uses neither copy nor move.
  template<class T, std::enable_if_t<std::is_constructible_v<decltype(data), T&&>, int> = 0>
  Value(T&& initial) : data(std::forward<T>(initial)) {}
  Value(detail::ParseTag, Parser& parser);

  const Value* find(std::string_view key) const {
    const auto* object = std::get_if<Object>(&data);
    if (!object) return nullptr;
    const auto it = object->find(key);
    return it == object->end() ? nullptr : &it->second;
  }
  std::string text(std::string fallback = {}) const {
    const auto* s = std::get_if<std::string>(&data);
    return s ? *s : fallback;
  }
  bool is_true() const {
    const auto* b = std::get_if<bool>(&data);
    return b && *b;
  }
};

// No allocation in cleanup, including object keys (which cannot be modified
// while resident in a map). This covers owned character buffers, not copies in
// caller input, allocator internals, registers, or arbitrary copies of Value.
inline void wipe(std::string& text) noexcept {
  auto* p = static_cast<volatile char*>(text.data());
  for (std::size_t i = 0; i < text.size(); ++i) p[i] = 0;
}
inline void wipe(Value& value) noexcept;
inline void wipe(Value::Array& array) noexcept {
  for (auto& value : array) wipe(value);
}
inline void wipe(Value::Object& object) noexcept {
  while (!object.empty()) {
    auto node = object.extract(object.begin());
    wipe(node.key());
    wipe(node.mapped());
  }
}
inline void wipe(Value& value) noexcept {
  if (auto* s = std::get_if<std::string>(&value.data)) wipe(*s);
  else if (auto* a = std::get_if<Value::Array>(&value.data)) wipe(*a);
  else if (auto* o = std::get_if<Value::Object>(&value.data)) wipe(*o);
}
namespace detail {
template<class T> struct WipeGuard {
  T& value;
  bool active = true;
  ~WipeGuard() noexcept { if (active) wipe(value); }
  void release() noexcept { active = false; }
};
} // namespace detail

class Parser {
 public:
  explicit Parser(std::string_view input) : input_(input) {
    if (input.size() > 1024 * 1024) fail("broker response is too large");
  }
  // C++17 guaranteed prvalue elision, including with -fno-elide-constructors.
  Value parse() { return Value(detail::ParseTag{}, *this); }

 private:
  friend struct Value;
  void parse_into(Value& result) {
    value(result, 0);
    whitespace();
    if (position_ != input_.size()) fail("trailing JSON content");
  }
  [[noreturn]] static void fail(const char* message) { throw std::runtime_error(message); }
  void whitespace() {
    while (position_ < input_.size() && (input_[position_] == ' ' || input_[position_] == '\n' ||
           input_[position_] == '\r' || input_[position_] == '\t')) ++position_;
  }
  char take() {
    if (position_ == input_.size()) fail("unexpected end of JSON");
    return input_[position_++];
  }
  void expect(char c) { if (take() != c) fail("invalid JSON delimiter"); }
  bool consume(char c) {
    whitespace();
    if (position_ < input_.size() && input_[position_] == c) { ++position_; return true; }
    return false;
  }
  void literal(std::string_view word) {
    if (input_.substr(position_, word.size()) != word) fail("invalid JSON literal");
    position_ += word.size();
  }
  std::uint32_t hex4() {
    std::uint32_t result = 0;
    for (int i = 0; i < 4; ++i) {
      const char c = take();
      result <<= 4;
      if (c >= '0' && c <= '9') result |= c - '0';
      else if (c >= 'a' && c <= 'f') result |= c - 'a' + 10;
      else if (c >= 'A' && c <= 'F') result |= c - 'A' + 10;
      else fail("invalid Unicode escape");
    }
    return result;
  }
  static void utf8(std::string& output, std::uint32_t cp) {
    if (cp <= 0x7f) output.push_back(static_cast<char>(cp));
    else if (cp <= 0x7ff) {
      output.push_back(static_cast<char>(0xc0 | (cp >> 6)));
      output.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    } else if (cp <= 0xffff) {
      output.push_back(static_cast<char>(0xe0 | (cp >> 12)));
      output.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
      output.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    } else {
      output.push_back(static_cast<char>(0xf0 | (cp >> 18)));
      output.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
      output.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
      output.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    }
  }
  std::string string() {
    expect('"');
    std::string result;
    detail::WipeGuard guard{result};
    // Scan only this raw lexeme, skipping escaped characters. Decoding cannot
    // exceed its raw byte length, so no secret-bearing buffer is ever grown.
    // Reserve beyond the string object's own size even for short values: this
    // keeps parsed characters off SSO storage that moves could leave behind.
    auto end = position_;
    while (end < input_.size() && input_[end] != '"') {
      if (input_[end++] == '\\' && end < input_.size()) ++end;
    }
    const auto raw_size = end - position_;
    result.reserve(raw_size > sizeof(std::string) ? raw_size : sizeof(std::string) + 1);
    while (true) {
      const auto c = static_cast<unsigned char>(take());
      if (c == '"') { guard.release(); return result; }
      if (c < 0x20) fail("unescaped control character");
      if (c != '\\') { result.push_back(static_cast<char>(c)); continue; }
      switch (take()) {
        case '"': result += '"'; break;
        case '\\': result += '\\'; break;
        case '/': result += '/'; break;
        case 'b': result += '\b'; break;
        case 'f': result += '\f'; break;
        case 'n': result += '\n'; break;
        case 'r': result += '\r'; break;
        case 't': result += '\t'; break;
        case 'u': {
          auto cp = hex4();
          if (cp >= 0xd800 && cp <= 0xdbff) {
            expect('\\'); expect('u');
            const auto low = hex4();
            if (low < 0xdc00 || low > 0xdfff) fail("invalid Unicode surrogate pair");
            cp = 0x10000 + ((cp - 0xd800) << 10) + low - 0xdc00;
          } else if (cp >= 0xdc00 && cp <= 0xdfff) fail("unpaired Unicode surrogate");
          utf8(result, cp);
          break;
        }
        default: fail("invalid JSON escape");
      }
    }
  }
  double number() {
    const auto start = position_;
    if (position_ < input_.size() && input_[position_] == '-') ++position_;
    if (position_ == input_.size()) fail("invalid JSON number");
    if (input_[position_] == '0') ++position_;
    else {
      if (input_[position_] < '1' || input_[position_] > '9') fail("invalid JSON number");
      while (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9') ++position_;
    }
    if (position_ < input_.size() && input_[position_] == '.') {
      ++position_;
      const auto digits = position_;
      while (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9') ++position_;
      if (digits == position_) fail("invalid JSON fraction");
    }
    if (position_ < input_.size() && (input_[position_] == 'e' || input_[position_] == 'E')) {
      ++position_;
      if (position_ < input_.size() && (input_[position_] == '+' || input_[position_] == '-')) ++position_;
      const auto digits = position_;
      while (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9') ++position_;
      if (digits == position_) fail("invalid JSON exponent");
    }
    double result{};
    const auto parsed = std::from_chars(input_.data() + start, input_.data() + position_, result);
    if (parsed.ec != std::errc{} || !std::isfinite(result)) fail("number out of range");
    return result;
  }
  // Structural prescan only: count direct array separators without decoding or
  // allocating secret storage. It does not accept JSON; value() remains the sole
  // grammar validator. The scan is input-bounded, iterative, and nesting-bounded.
  std::size_t array_capacity(unsigned depth) const {
    std::size_t count = 1;
    unsigned nested = 0;
    bool quoted = false;
    for (auto i = position_; i < input_.size(); ++i) {
      const char c = input_[i];
      if (quoted) {
        if (c == '\\') { if (++i == input_.size()) break; }
        else if (c == '"') quoted = false;
        continue;
      }
      if (c == '"') quoted = true;
      else if (c == '[' || c == '{') {
        if (depth + ++nested > 32) fail("JSON nesting limit exceeded");
      } else if (c == ']' || c == '}') {
        if (!nested) {
          if (c == ']') return count;
          fail("invalid JSON delimiter");
        }
        --nested;
      } else if (c == ',' && !nested) ++count;
    }
    fail("unexpected end of JSON");
  }
  void value(Value& result, unsigned depth) {
    if (depth > 32) fail("JSON nesting limit exceeded");
    whitespace();
    if (position_ == input_.size()) fail("missing JSON value");
    switch (input_[position_]) {
      case 'n': literal("null"); return;
      case 't': literal("true"); result.data.emplace<bool>(true); return;
      case 'f': literal("false"); result.data.emplace<bool>(false); return;
      case '"': result.data.emplace<std::string>(string()); return;
      case '[': {
        ++position_;
        auto& array = result.data.emplace<Value::Array>();
        if (consume(']')) return;
        // Reserve before parsing children. Even on STLs with throwing Object /
        // Value moves, no secret-bearing Value is ever relocated or copied.
        array.reserve(array_capacity(depth));
        do {
          // Defense in depth: malformed prescan input must never cause growth.
          if (array.size() == array.capacity()) fail("invalid JSON array");
          array.emplace_back();
          value(array.back(), depth + 1);
        } while (consume(','));
        whitespace(); expect(']');
        return;
      }
      case '{': {
        ++position_;
        auto& object = result.data.emplace<Value::Object>();
        if (consume('}')) return;
        do {
          whitespace();
          auto key = string();
          detail::WipeGuard key_guard{key};
          whitespace(); expect(':');
          if (object.find(key) != object.end()) fail("duplicate JSON key");
          // Insert only a default null Value. Its construction cannot throw
          // after the (standard-allocator, nonthrowing) string move. A throwing
          // map default construction or child parse occurs only once the node
          // belongs to the guarded root; no mapped Value is transferred.
          static_assert(std::is_nothrow_move_constructible_v<std::string>);
          static_assert(std::is_nothrow_default_constructible_v<Value>);
          auto [it, inserted] = object.try_emplace(std::move(key));
          if (!inserted) fail("duplicate JSON key");
          value(it->second, depth + 1);
        } while (consume(','));
        whitespace(); expect('}');
        return;
      }
      default: result.data.emplace<double>(number()); return;
    }
  }
  std::string_view input_;
  std::size_t position_{};
};

inline Value::Value(detail::ParseTag, Parser& parser) : data(nullptr) {
  // This guard runs before data's destruction even if construction throws.
  // get_if-based wipe also tolerates a valueless variant after failed emplace.
  detail::WipeGuard guard{*this};
  parser.parse_into(*this);
  guard.release();
}

inline Value parse(std::string_view input) { return Parser(input).parse(); }
}  // namespace orangespace::json
