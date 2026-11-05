#include "admission_client_win.hpp"
#include "admission_protocol.hpp"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstring>
#include <iostream>
using namespace orangespace::prototype;
int main() {
  assert(AdmissionFailureExitCode(AdmissionStage::none)==23);
  static_assert(AdmissionFailureExitCode(AdmissionStage::allocation)==80);
  static_assert(AdmissionFailureExitCode(AdmissionStage::open_thread_token)==81);
  static_assert(AdmissionFailureExitCode(AdmissionStage::open_sc_manager)==82);
  static_assert(AdmissionFailureExitCode(AdmissionStage::open_service)==83);
  static_assert(AdmissionFailureExitCode(AdmissionStage::query_service_status)==84);
  static_assert(AdmissionFailureExitCode(AdmissionStage::open_process)==85);
  static_assert(AdmissionFailureExitCode(AdmissionStage::system_token)==86);
  static_assert(AdmissionFailureExitCode(AdmissionStage::process_birth)==87);
  static_assert(AdmissionFailureExitCode(AdmissionStage::pipe_open)==88);
  static_assert(AdmissionFailureExitCode(AdmissionStage::pipe_mode_scm_bound)==89);
  static_assert(AdmissionFailureExitCode(AdmissionStage::nonce)==90);
  static_assert(AdmissionFailureExitCode(AdmissionStage::provisional_write)==91);
  static_assert(AdmissionFailureExitCode(AdmissionStage::provisional_read)==92);
  static_assert(AdmissionFailureExitCode(AdmissionStage::provisional_validation)==93);
  static_assert(AdmissionFailureExitCode(AdmissionStage::own_job)==94);
  static_assert(AdmissionFailureExitCode(AdmissionStage::pre_ack_storage_thread)==95);
  static_assert(AdmissionFailureExitCode(AdmissionStage::ack_write)==96);
  static_assert(AdmissionFailureExitCode(AdmissionStage::committed_read)==97);
  static_assert(AdmissionFailureExitCode(AdmissionStage::committed_validation)==98);
  static_assert(AdmissionFailureExitCode(AdmissionStage::postcommit_live_checks)==99);
  static_assert(AdmissionFailureExitCode(AdmissionStage::monitor_release)==100);
  assert(AdmissionFailureExitCode(static_cast<AdmissionStage>(255))==23);
  Request q{}; q.pid=42; q.session=2; q.created=99; q.nonce[0]=7;
  Reply r{};
  assert(!ValidProvisionalReply(r,q,5,100));
  r.magic=kMagic; r.version=kVersion; r.size=sizeof(r); r.status=1;
  r.pid=q.pid; r.session=q.session; r.created=q.created; r.nonce=q.nonce;
  r.server_pid=5; r.server_created=100; r.root_pid=42; r.root_created=99;
  r.generation=1; r.rules_epoch=1; r.job_cookie[0]=1; r.rules_digest[0]=1;
  r.evidence=kRequiredEvidence;
  assert(!ValidReply(r,q,5,100)); // provisional reply alone cannot admit
  assert(ValidProvisionalReply(r,q,5,100));
  auto good=r;
  Reply committed=good; committed.status=2;
  assert(ValidReply(good,q,5,100,&committed));
  assert(!ValidReply(good,q,5,100,&good)); // ACK/provisional is not commit
  // Every byte of the exact reply is bound, including nonce, generation, root,
  // rules, caller, server, evidence, framing and reserved fields.
  for(std::size_t i=0;i<sizeof(Reply);++i) {
    Reply bad=committed;
    reinterpret_cast<unsigned char*>(&bad)[i]^=1;
    assert(!ValidReply(good,q,5,100,&bad));
  }
  auto wrong=q; ++wrong.nonce[0];
  assert(!ValidReply(good,wrong,5,100,&committed));
  assert(!ValidReply(good,q,6,100,&committed));
  assert(!ValidReply(good,q,5,101,&committed));
  for(unsigned bit=0;bit<8;++bit) { r=good; r.evidence &= ~(1u<<bit); assert(!ValidProvisionalReply(r,q,5,100)); }
  r=good; r.evidence |= 0x80000000u; assert(!ValidProvisionalReply(r,q,5,100));
  r=good; ++r.pid; assert(!ValidProvisionalReply(r,q,5,100));
  r=good; ++r.created; assert(!ValidProvisionalReply(r,q,5,100));
  r=good; ++r.session; assert(!ValidProvisionalReply(r,q,5,100));
  r=good; ++r.nonce[0]; assert(!ValidProvisionalReply(r,q,5,100));
  r=good; ++r.server_created; assert(!ValidProvisionalReply(r,q,5,100));
  r=good; r.rules_digest={}; assert(!ValidProvisionalReply(r,q,5,100));
  r=good; r.root_created=0; assert(!ValidProvisionalReply(r,q,5,100));
  r=good; r.reserved=1; assert(!ValidProvisionalReply(r,q,5,100));
  assert(AllowedNavigation(kOfflineUrl));
  for(auto url:{"https://example.com","http://127.0.0.1","file:///x","data:text/html,evil","about:blank"}) assert(!AllowedNavigation(url));
  std::cout << "admission/policy negative controls passed\n";
}
