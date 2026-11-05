#include "orangespace/ui_lifecycle.hpp"
#include <cassert>
#include <iostream>
#include <string>
#include <thread>
#include <barrier>
#include <atomic>
int main() {
  using orangespace::ui_lifecycle::Drain;
  Drain<int> d;
  auto ticket=d.begin(); assert(ticket);
  d.close(); assert(!d.begin()); assert(!d.ready());
  d.finish(*ticket, 7); // authorization completed after close
  assert(!d.ready());
  int calls=0;
  d.retry([&](int value){assert(value==7);++calls;return false;});
  assert(!d.ready() && calls==1);
  d.retry([&](int){++calls;return true;});
  assert(d.ready() && calls==2);
  {
    orangespace::ui_lifecycle::LogoutState logout;
    int erases=0, cleanup=0;
    logout.begin({"a","b"});
    logout.retry_erasure([&](const std::string& name){++erases;return name=="b";});
    ++cleanup; // service-down does not suppress erasure attempts
    assert(erases==2 && cleanup==1 && logout.restore_blocked());
    assert(!logout.erased());
    logout.retry_erasure([](const std::string&){return true;});
    assert(logout.erased() && !logout.restore_blocked());
  }
  std::cout << "S2-AUTH-LATE S2-RETIRE-RETRY L3-ERASE-SERVICE-DOWN L3-IN-PROCESS-RESTORE-GATE passed\n";
  {
    orangespace::ui_lifecycle::Retirement policy;
    int remote=0,local=0;
    assert(!policy.run("grant-a",true,[&]{++remote;throw 1;},[&]{++local;throw 2;}));
    assert(remote==1 && local==1 && policy.remote_failed());
    assert(policy.run("grant-a",true,[&]{++remote;},[&]{++local;}));
    assert(remote==1 && local==2 && policy.remote_failed());
    assert(policy.run("grant-b",false,[&]{++remote;},[&]{++local;}));
    assert(remote==1 && local==3); // close never calls remote logout
    std::cout << "S2-LOCAL-ONLY L3-REMOTE-BEST-EFFORT passed\n";
  }
  {
    Drain<int> sources;
    const auto auth=*sources.begin(),start=*sources.begin();
    std::barrier release_auth(2),release_start(2);
    std::thread auth_worker([&]{release_auth.arrive_and_wait();sources.finish(auth,11);});
    std::thread start_worker([&]{release_start.arrive_and_wait();sources.finish(start);});
    sources.close();sources.close();
    assert(!sources.begin());
    int retirements=0;
    sources.retry([&](int){++retirements;return true;});
    assert(retirements==0 && !sources.ready());
    release_auth.arrive_and_wait();auth_worker.join();
    sources.retry([&](int){++retirements;return true;});
    assert(retirements==0 && !sources.ready()); // start response still outstanding
    release_start.arrive_and_wait();start_worker.join();
    std::barrier cleanup_enter(2),cleanup_exit(2);
    std::thread owner([&]{sources.retry([&](int value){
      assert(value==11 && !sources.ready() && !sources.begin());
      ++retirements;cleanup_enter.arrive_and_wait();cleanup_exit.arrive_and_wait();return true;
    });});
    cleanup_enter.arrive_and_wait();
    sources.retry([](int){assert(false && "second cleanup owner");return false;});
    assert(!sources.ready());cleanup_exit.arrive_and_wait();owner.join();
    assert(sources.ready() && retirements==1);
    sources.finish(auth,12); // duplicate completion cannot introduce a new owner
    assert(sources.ready());
    std::cout << "S2-PENDING-START S2-MULTISOURCE S2-REPEAT-CLOSE S2-ONE-OWNER S2-UNLOCKED-CALLBACK passed\n";
  }
  {
    Drain<int> live;
    auto a=*live.begin(),b=*live.begin();
    live.finish(a,1);live.finish(b,2);live.close();
    orangespace::ui_lifecycle::LogoutState logout;
    orangespace::ui_lifecycle::Retirement retirement;
    logout.begin({"node-a","node-b"});
    int erases=0,local_attempts=0,remote_attempts=0;
    logout.retry_erasure([&](const std::string& name){++erases;if(name=="node-a")throw 1;return true;});
    live.retry([&](int id){return retirement.run(std::to_string(id),true,
      [&]{++remote_attempts;throw 2;},[&]{++local_attempts;throw 3;});});
    assert(erases==2 && remote_attempts==2 && local_attempts==2);
    assert(logout.restore_blocked() && !logout.erased() && !live.ready() && retirement.remote_failed());
    logout.retry_erasure([&](const std::string& name){assert(name=="node-a");++erases;return true;});
    live.retry([&](int id){return retirement.run(std::to_string(id),true,
      [&]{assert(false);},[&]{++local_attempts;});});
    assert(erases==3 && local_attempts==4 && logout.erased() && live.ready());
    assert(retirement.remote_failed()); // local retry never invents remote success
    std::cout << "L3-ALL-ERASES L3-BLOB-FAIL-SERVICE-DOWN L3-LOCAL-REMOTE-SEPARATE L3-RETRY passed\n";
  }
}
