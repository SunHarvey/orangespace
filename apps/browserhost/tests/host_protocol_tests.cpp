#include "../host_protocol.hpp"

#include <cassert>
#include <iostream>

using namespace orangespace::browserhost;

namespace {
const char* kGood =
    R"({"v":1,"sandbox_id":"0b4c2a8e-1f7d-4c6e-9a51-6d2f0e8b7c13","parent_window":131234,)"
    R"("proxy_port":41234,"proxy_username":"os-a","proxy_password":"0123456789abcdef0123",)"
    R"("profile_dir":"C:\\Users\\u\\AppData\\Local\\OrangeSpace\\profile","start_url":"https://example.com/"})";

void config_cases() {
  std::string error;
  const auto c = parse_config(kGood, error);
  assert(c && error.empty());
  assert(c->proxy_port == 41234 && c->parent_window == 131234);
  assert(c->profile_dir == "C:\\Users\\u\\AppData\\Local\\OrangeSpace\\profile");

  const auto bad = [](std::string text) {
    std::string e;
    const auto r = parse_config(text, e);
    assert(!r && !e.empty());
    // Errors never echo the input (it contains the proxy password).
    assert(e.find("0123456789abcdef") == std::string::npos);
  };
  std::string s = kGood;
  bad(s.substr(0, s.size() - 1));                                            // truncated JSON
  bad(std::string(s).replace(s.find("\"v\":1"), 5, "\"v\":2"));               // version
  bad(std::string(s).replace(s.find("0b4c2a8e"), 8, "0B4C2A8E"));             // non-canonical uuid
  bad(std::string(s).replace(s.find("41234"), 5, "80"));                      // privileged port
  bad(std::string(s).replace(s.find("0123456789abcdef0123"), 20, "short"));   // weak password
  bad(std::string(s).replace(s.find("C:\\\\Users"), 9, "..\\\\Users"));       // relative profile
  bad(std::string(s).replace(s.find("https://example.com/"), 20, "file:///C:/x"));
  bad(std::string(s).insert(1, "\"extra\":1,"));                               // unknown field
  bad(std::string(s).replace(s.find("\\\\profile"), 10, "\\\\..\\\\x"));       // dot-dot component

  // What the Service writes is exactly what BrowserHost accepts, including
  // characters that need escaping in credentials and paths.
  Config made = *c;
  made.proxy_password = "p\"q\\r\x01-0123456789abcdef";
  made.profile_dir = "C:\\Users\\\u00e9l\u00e8ve\\AppData\\Local\\OrangeSpace\\p";
  const auto line = config_line(made);
  assert(!line.empty() && line.back() == '\n');
  const auto back = parse_config(std::string_view(line).substr(0, line.size() - 1), error);
  assert(back && back->sandbox_id == made.sandbox_id && back->parent_window == made.parent_window &&
         back->proxy_port == made.proxy_port && back->proxy_username == made.proxy_username &&
         back->proxy_password == made.proxy_password && back->profile_dir == made.profile_dir &&
         back->start_url == made.start_url);
}

void url_cases() {
  assert(allowed_url("https://example.com"));
  assert(allowed_url("HTTP://example.com/a?b=c"));
  assert(allowed_url("about:blank"));
  for (const char* u : {"", "file:///C:/Windows", "javascript:alert(1)", "data:text/html,x", "chrome://settings",
                        "devtools://x", "https://", "https://exa mple.com", "ftp://x", "about:config"})
    assert(!allowed_url(u));
  assert(!allowed_url("https://" + std::string(kMaxUrl, 'a')));
}

void command_cases() {
  std::string e;
  auto c = parse_command(R"({"op":"navigate","tab":3,"url":"https://a.test/"})", e);
  assert(c && c->op == Op::navigate && c->tab == 3 && c->url == "https://a.test/");
  c = parse_command(R"({"op":"back"})", e);
  assert(c && c->op == Op::back && c->tab == 0);
  c = parse_command(R"({"op":"new_tab","url":"about:blank"})", e);
  assert(c && c->op == Op::new_tab);
  assert(!parse_command(R"({"op":"navigate","url":"file:///C:/"})", e));
  assert(!parse_command(R"({"op":"close_tab"})", e));
  assert(!parse_command(R"({"op":"select_tab","tab":-1})", e));
  assert(!parse_command(R"({"op":"select_tab","tab":1.5})", e));
  assert(!parse_command(R"({"op":"reload","url":"https://a.test/"})", e));
  assert(!parse_command(R"({"op":"exec","tab":1})", e));
  assert(!parse_command(R"({"op":"back","x":1})", e));
  assert(!parse_command("not json", e));
}

void event_cases() {
  TabState t{7, "https://a.test/\"x", "Ti\ntle\x01", true, false, true, true};
  const auto ev = tab_event(t);
  const std::string expected =
      "{\"ev\":\"tab\",\"tab\":7,\"url\":\"https://a.test/\\\"x\",\"title\":\"Ti\\ntle\\u0001\","
      "\"loading\":true,\"back\":false,\"forward\":true,\"active\":true}";
  assert(ev == expected);
  // Every event must be parseable back as one JSON line.
  for (const auto& line : {ev, tab_closed_event(7), simple_event("ready"), error_event("bad\"x")}) {
    assert(line.find('\n') == std::string::npos);
    (void)orangespace::json::Parser(line).parse();
  }
}
}  // namespace

int main() {
  config_cases();
  url_cases();
  command_cases();
  event_cases();
  std::cout << "browserhost protocol: config, url policy, commands and events passed\n";
}
