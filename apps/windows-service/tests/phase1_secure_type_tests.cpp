#include "phase1_secure_channel.hpp"
#include <type_traits>
#include <iostream>
using namespace phase1::secure;
int wmain(){
#ifndef PHASE1_SECURE_TYPED_PIPE
 std::cout<<"RED: channel can adopt arbitrary synchronous pipe handles\n";return 1;
#else
 static_assert(!std::is_constructible_v<Pipe,HANDLE>);
 static_assert(!std::is_constructible_v<Pipe,Handle>);
 static_assert(!std::is_copy_constructible_v<Pipe>);
 static_assert(std::is_nothrow_move_constructible_v<Pipe>);
 std::cout<<"{\"case\":\"overlapped_only_pipe_ownership_type\",\"ok\":true,\"kind\":\"compile_time_contract\"}\n";return 0;
#endif
}
