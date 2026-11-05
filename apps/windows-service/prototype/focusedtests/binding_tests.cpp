#include "service_binding.hpp"
#include <cassert>
using namespace orangespace::prototype;
int main(){
 // Shared owner/writer authority policy; app directory and leaves use ancestor=false.
 assert(TrustedAuthority(false,true,true)); // TI ancestor owner and effective writer.
 assert(!TrustedAuthority(false,true,false)); // TI app directory / inventory / file denied.
 for(bool ancestor:{false,true}){
  assert(!TrustedAuthority(false,false,ancestor)); // Untrusted owner/writer everywhere.
  assert(TrustedAuthority(true,false,ancestor)); // SYSTEM or Administrators unchanged.
  assert(TrustedAuthority(true,true,ancestor));
 }
 assert(ValidRelative("locales/en-US.pak"));
 for(auto x:{"../client.exe","foo/./x","foo//x","foo./x","CON","aux.dll","a:N","/root","a/COM1.txt","a/..","a/","runtime.inventory.tsv"})assert(!ValidRelative(x));
 BoundedSnapshot canonical;assert(canonical.put("ab",2));assert(canonical.put("c",1));BoundedSnapshot other;assert(other.put("a",1));assert(other.put("bc",2));assert(canonical.bytes!=other.bytes);auto saved=canonical.bytes;assert(!canonical.put("x",65537));assert(canonical.bytes==saved);assert(!canonical.put(nullptr,1));for(unsigned i=0;i<16;i++)assert(other.put(saved.data(),saved.size()));
 Request q{};q.pid=42;q.session=3;q.created=91;q.nonce[0]=1;
 Binding b{42,3,91}; assert(Matches(q,b));
 auto bad=q;bad.pid++;assert(!Matches(bad,b));bad=q;bad.created++;assert(!Matches(bad,b));
 bad=q;bad.reserved=1;assert(!Matches(bad,b));bad=q;bad.nonce={};assert(!Matches(bad,b));
 Reply snap{};snap.generation=1;snap.rules_epoch=2;snap.job_cookie[0]=3;snap.rules_digest[0]=4;snap.evidence=1;
 auto drift=snap;assert(SameSnapshot(snap,drift));drift.rules_digest[31]++;assert(!SameSnapshot(snap,drift));drift=snap;drift.generation++;assert(!SameSnapshot(snap,drift));drift=snap;drift.job_cookie[15]++;assert(!SameSnapshot(snap,drift));drift=snap;drift.evidence++;assert(!SameSnapshot(snap,drift));drift=snap;drift.rules_epoch++;assert(!SameSnapshot(snap,drift));drift=snap;drift.server_created++;assert(!SameSnapshot(snap,drift));drift=snap;drift.root_created++;assert(!SameSnapshot(snap,drift));
 BoundedSnapshot limit;std::vector<std::uint8_t> block(65532,1);for(unsigned i=0;i<16;i++)assert(limit.put(block.data(),block.size()));assert(limit.bytes.size()==1048576);assert(!limit.put(nullptr,0));
 Commit before;assert(!before.ack(6,q,b)); Commit c;assert(c.offer(q,b));assert(!c.offer(q,b));
 bad=q;bad.nonce[1]=1;assert(!c.ack(6,bad,b));assert(!c.committed());
 Commit d;assert(d.offer(q,b));assert(!d.ack(5,q,b));
 Commit e;assert(e.offer(q,b));auto stale=b;stale.created++;assert(!e.ack(6,q,stale));
 Commit f;assert(f.offer(q,b));assert(f.ack(6,q,b));assert(f.committed());assert(!f.ack(6,q,b));
}
