// Deterministic reentrant completion seams in actual Engine, not Windows timing.
#define main supplied_chain_main
#include "chain_tests.cpp"
#undef main
int main(){
  orangespace::service::Peer p{"S-1-5-21-100",1,99};
  for(int operation=0;operation<3;++operation)for(bool negative:{false,true}) {
    std::int64_t mono=100000;FakeBackend b;
    Engine e(p,b,[]{return 100;},std::make_shared<Namespace>(),[&]{return mono;});
    auto id=e.authorize(p,"metadata","{}");b.last->clock=[&]{return mono;};b.last->expiry=131;
    auto live=e.start(p,id);int polls=0;bool fired=false;
    b.on_alive=[&](const Binding&){
      ++polls;
      if(!fired && polls==(operation==2?2:1)) {
        fired=true;mono=101000;b.last->expiry=132;
        e.tick(); // current tuple now has D=131000, old snapshot D=130000
        mono=130000;return !negative;
      }
      return true;
    };
    bool denied=false;std::string result;
    try{if(operation==0)result=e.status(p,id);else if(operation==1)e.poll();else e.tick();}catch(...){denied=true;}
    check(fired && !denied && b.closed==0,"stale same-tuple expiry/negative must not detach renewed authority");
    check(e.status(p,id).find(live.tunnel)!=std::string::npos,"current authority is re-polled, not old proof reused");
    mono=131000;denied=false;try{(void)e.status(p,id);}catch(...){denied=true;}
    check(denied && b.closed>0,"new current deadline still fails closed");
  }
  // A current negative must not be ignored just because a renewal happened.
  {
    std::int64_t mono=100000;FakeBackend b;Engine e(p,b,[]{return 100;},std::make_shared<Namespace>(),[&]{return mono;});
    auto id=e.authorize(p,"negative","{}");b.last->clock=[&]{return mono;};b.last->expiry=131;(void)e.start(p,id);
    mono=101000;b.last->expiry=132;e.tick();b.living=false;
    bool denied=false;try{(void)e.status(p,id);}catch(...){denied=true;}
    check(denied,"current negative remains fatal");
  }
  // Late negative liveness for intentionally removed A cannot kill sibling B
  // or an authorization installed after retiring the old operation's grant.
  for(int mutation=0;mutation<3;++mutation) {
    std::int64_t mono=100000;FakeBackend b;Engine e(p,b,[]{return 100;},std::make_shared<Namespace>(),[&]{return mono;});
    auto id=e.authorize(p,"old-operation","{}");b.last->clock=[&]{return mono;};
    auto live=e.start(p,id),sibling=e.start(p,id);std::string current_id=id;Binding survivor=sibling;bool fired=false;
    b.on_alive=[&](const Binding& observed){
      if(!fired && observed==live){
        fired=true;
        if(mutation==0)(void)e.stop(p,id,Cursor{live.sandbox,live.generation});
        if(mutation==1)survivor=e.start(p,id,Cursor{live.sandbox,live.generation});
        if(mutation==2){e.retire(p,id);current_id=e.authorize(p,"old-operation","{}");b.last->clock=[&]{return mono;};survivor=e.start(p,current_id);}
        return false;
      }
      return true;
    };
    try{(void)e.status(p,id);}catch(...){check(mutation==2,"stop/switch old negative must not retire current grant");}
    check(fired && e.status(p,current_id).find(survivor.tunnel)!=std::string::npos,"old stop/switch/retire operation cannot kill surviving/new tuple");
    if(mutation<2)check(e.status(p,id).find(sibling.tunnel)!=std::string::npos,"sibling preserved after old negative");
  }
  std::cout<<"PASS status/watchdog/maintenance stale metadata interleavings; old/new D and negative liveness (policy only)\n";
}
