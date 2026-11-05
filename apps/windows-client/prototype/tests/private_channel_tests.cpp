#include "private_channel.hpp"
#include <cassert>
using namespace orangespace::prototype;
int main(){
 Reply base{};base.status=2;base.pid=base.root_pid=7;base.created=base.root_created=8;base.nonce[0]=1;
 PrivateOffer o{};o.base=base;o.nonce[0]=2;o.port=1234;o.generation=1;o.started=100;o.ttl=30000;o.deadline=30100;o.proof=101;o.binding_deadline=30100;o.expiry=1;
 for(auto* s:{&o.user,&o.sandbox,&o.node,&o.tunnel})std::memcpy(s->data(),"33333333-3333-4333-8333-333333333333",36);
 o.username_size=o.password_size=16;std::memset(o.username.data(),'a',16);std::memset(o.password.data(),'b',16);
 assert(ValidPrivateOffer(o,base,102));assert(!ValidPrivateOffer(o,base,30100));
 auto wrong=base;wrong.nonce[0]++;assert(!ValidPrivateOffer(o,wrong,102));
 o.size++;assert(!ValidPrivateOffer(o,base,102));o.size--;o.user[0]='G';assert(!ValidPrivateOffer(o,base,102));o.user[0]='3';
 o.username_size=256;assert(!ValidPrivateOffer(o,base,102));o.username_size=16;
 auto receipt=PrivateReceipt{};receipt.base=base;receipt.nonce=o.nonce;receipt.digest[0]=3;
 auto ack=receipt;ack.phase=6;assert(ValidPrivateReceipt(receipt,ack,6));ack.nonce[0]++;assert(!ValidPrivateReceipt(receipt,ack,6));
 assert(ProxyChallenge(true,"127.0.0.1",1234,"basic",1234));assert(!ProxyChallenge(false,"127.0.0.1",1234,"basic",1234));assert(!ProxyChallenge(true,"localhost",1234,"basic",1234));assert(!ProxyChallenge(true,"127.0.0.1",1235,"basic",1234));assert(!ProxyChallenge(true,"127.0.0.1",1234,"digest",1234));
}
