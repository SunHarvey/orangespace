#include "orangespace/wsl_channel.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace orangespace::wsl;

namespace {
void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    std::exit(1);
  }
}
template <class F>
bool rejects(F f) {
  try {
    f();
  } catch (const ProtocolError&) {
    return true;
  }
  return false;
}
std::string reply_frame(std::uint32_t number, const std::string& payload, std::uint8_t kind = kReply) {
  std::string out(kHeader, '\0');
  out[0] = static_cast<char>(kind);
  for (int i = 0; i < 4; ++i) out[1 + i] = static_cast<char>(number >> (24 - 8 * i));
  for (int i = 0; i < 4; ++i) out[5 + i] = static_cast<char>(payload.size() >> (24 - 8 * i));
  return out + payload;
}
}  // namespace

int main() {
  // Request frames match the agent's struct "!BII" layout.
  const auto frame = request_frame(0x01020304, "{\"op\":\"ping\"}");
  check(frame.size() == kHeader + 13 && frame[0] == kRequest && frame[1] == 1 && frame[4] == 4 && frame[8] == 13,
        "request frame layout");
  check(rejects([] { request_frame(0, "{}"); }), "request number zero rejected");
  check(rejects([] { request_frame(1, std::string(kMaxPayload + 1, 'x')); }), "oversized request rejected");

  // Banner noise before the marker is skipped; frames split across reads reassemble.
  {
    ReplyReader reader;
    const std::string stream = std::string("wsl: some localhost proxy warning\r\n") + std::string(kMarker) +
                               reply_frame(7, "{\"ready\":true}") + reply_frame(8, "{}");
    for (char c : stream) reader.feed(&c, 1);
    check(reader.synced(), "marker found after banner");
    auto first = reader.next();
    check(first && first->number == 7 && first->payload == "{\"ready\":true}", "first reply");
    auto second = reader.next();
    check(second && second->number == 8 && second->payload == "{}", "second reply");
    check(!reader.next(), "no further replies");
  }
  {
    ReplyReader reader;
    const std::string partial = std::string(kMarker) + reply_frame(3, "abcdef").substr(0, 11);
    reader.feed(partial.data(), partial.size());
    check(!reader.next(), "incomplete frame waits for more bytes");
    const std::string rest = "cdef";
    reader.feed(rest.data(), rest.size());
    auto r = reader.next();
    check(r && r->payload == "abcdef", "completed after more bytes");
  }

  // Anything that is not marker + well-formed REPLY frames is a protocol error.
  check(rejects([] {
          ReplyReader reader;
          const std::string junk(kMaxPreamble + kMarker.size() + 1, 'x');
          reader.feed(junk.data(), junk.size());
        }),
        "missing marker within budget rejected");
  for (const std::string& bad : {reply_frame(1, "{}", kRequest), reply_frame(0, "{}"),
                                std::string("\x02\x00\x00\x00\x01\x00\x01\x00\x01", 9)}) {
    check(rejects([&] {
            ReplyReader reader;
            const std::string stream = std::string(kMarker) + bad;
            reader.feed(stream.data(), stream.size());
            (void)reader.next();
          }),
          "wrong kind, number zero or oversized reply rejected");
  }
  std::printf("wsl channel: request framing, marker sync, reassembly and rejection passed\n");
  return 0;
}
