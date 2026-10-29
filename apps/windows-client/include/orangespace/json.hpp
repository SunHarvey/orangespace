#pragma once

#include <charconv>
#include <cmath>
#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace orangespace::json {

// A bounded, strict JSON reader for the broker's small local responses. This is
// not a general web JSON library and never handles tokens or tunnel credentials.
struct Value {
  using Array = std::vector<Value>;
  using Object = std::map<std::string, Value, std::less<>>;
  std::variant<std::nullptr_t, bool, std::string, Array, Object, double> data;

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

class Parser {
 public:
  explicit Parser(std::string_view input) : input_(input) {
    if (input.size() > 1024 * 1024) fail("broker response is too large");
  }
  Value parse() {
    auto result = value(0);
    whitespace();
    if (position_ != input_.size()) fail("trailing JSON content");
    return result;
  }

 private:
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
    while (true) {
      const auto c = static_cast<unsigned char>(take());
      if (c == '"') return result;
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
  Value number() {
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
    return Value{result};
  }
  Value value(unsigned depth) {
    if (depth > 32) fail("JSON nesting limit exceeded");
    whitespace();
    if (position_ == input_.size()) fail("missing JSON value");
    switch (input_[position_]) {
      case 'n': literal("null"); return Value{nullptr};
      case 't': literal("true"); return Value{true};
      case 'f': literal("false"); return Value{false};
      case '"': return Value{string()};
      case '[': {
        ++position_;
        Value::Array array;
        if (consume(']')) return Value{std::move(array)};
        do { array.push_back(value(depth + 1)); } while (consume(','));
        whitespace(); expect(']');
        return Value{std::move(array)};
      }
      case '{': {
        ++position_;
        Value::Object object;
        if (consume('}')) return Value{std::move(object)};
        do {
          whitespace();
          auto key = string();
          whitespace(); expect(':');
          if (!object.emplace(std::move(key), value(depth + 1)).second) fail("duplicate JSON key");
        } while (consume(','));
        whitespace(); expect('}');
        return Value{std::move(object)};
      }
      default: return number();
    }
  }
  std::string_view input_;
  std::size_t position_{};
};

inline Value parse(std::string_view input) { return Parser(input).parse(); }
}  // namespace orangespace::json
