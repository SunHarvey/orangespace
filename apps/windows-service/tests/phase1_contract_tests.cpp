#include "phase1_contract.hpp"
#include <iostream>
#include <stdexcept>
using namespace phase1;
void check(bool x) { if (!x) throw std::runtime_error("assertion failed"); }
int main() {
 try {
  // One bounded, exact, secret-bearing JSON object; no permissive aliases.
  const std::string good=R"({"schema":1,"alias_a":"a","alias_b":"b","username_a":"test-a","password_a":"secret-a","username_b":"test-b","password_b":"secret-b","expiry_budget_seconds":180,"renew_seconds":35})";
  auto b=parse_bootstrap(good); check(b.alias_a=="a" && b.renew_seconds==35);
  for (auto bad : {std::string("{}"),good+"x",std::string(32769,'x')}) {
   bool rejected=false; try { (void)parse_bootstrap(bad); } catch (...) { rejected=true; } check(rejected);
  }
  auto changed=good; changed.replace(changed.find("\"renew_seconds\":35"),18,"\"renew_seconds\":30");
  bool rejected=false; try {(void)parse_bootstrap(changed);} catch (...) {rejected=true;} check(rejected);
  auto huge=good;huge.replace(huge.find("\"expiry_budget_seconds\":180"),27,"\"expiry_budget_seconds\":4294967476");
  rejected=false;try{(void)parse_bootstrap(huge);}catch(...){rejected=true;}check(rejected);
  std::cout << "phase1 bootstrap contract: passed\n"; return 0;
 } catch (...) {std::cerr<<"phase1 bootstrap contract: FAILED\n";return 1;}
}
