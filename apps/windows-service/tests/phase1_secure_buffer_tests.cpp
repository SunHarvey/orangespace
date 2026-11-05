#include "phase1_secure_channel.hpp"
#include <iostream>
#include <type_traits>
using namespace phase1::secure;
static_assert(!std::is_copy_constructible_v<SecretBuffer>);
static_assert(std::is_nothrow_move_constructible_v<SecretBuffer>);
int wmain(){try{
 SecretBuffer a;a.assign("NONSECRET_BUFFER_MARKER");
 a.assign(a.view());require(a.view()=="NONSECRET_BUFFER_MARKER","assign_self_view_preserves_marker");
 SecretBuffer b(std::move(a));require(a.size()==0&&b.view()=="NONSECRET_BUFFER_MARKER","move_ownership");
 for(unsigned i=0;i<32768;++i)require(a.data()[i]==0,"move_source_full_capacity_wipe");
 b.assign("N");for(unsigned i=1;i<32768;++i)require(b.data()[i]==0,"shorter_assignment_tail_wipe");
 alignas(SecretBuffer) unsigned char storage[sizeof(SecretBuffer)]{};
 auto p=new(storage)SecretBuffer;p->assign("NONSECRET_DESTRUCTOR");auto offset=reinterpret_cast<unsigned char*>(p->data())-storage;p->~SecretBuffer();
 for(unsigned i=0;i<32768;++i)require(storage[offset+i]==0,"destructor_full_capacity_wipe");
 std::cout<<"{\"case\":\"fixed_buffer_ownership_and_wipe\",\"ok\":true}\n";return 0;
 }catch(const Failure& f){std::cout<<"{\"ok\":false,\"stage\":\""<<f.stage<<"\",\"code\":"<<f.code<<"}\n";return 1;}}
