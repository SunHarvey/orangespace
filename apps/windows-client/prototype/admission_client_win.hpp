#pragma once
#include <memory>
#include "private_channel.hpp"
namespace orangespace::prototype {
// Fixed nonsecret failure stage, local to the calling Acquire thread.
enum class AdmissionStage {
  none,
  allocation,
  open_thread_token,
  open_sc_manager,
  open_service,
  query_service_status,
  open_process,
  system_token,
  process_birth,
  pipe_open,
  pipe_mode_scm_bound,
  nonce,
  provisional_write,
  provisional_read,
  provisional_validation,
  own_job,
  pre_ack_storage_thread,
  ack_write,
  committed_read,
  committed_validation,
  postcommit_live_checks,
  monitor_release,
  private_offer_read,
  private_offer_validate,
  private_commit,
};
constexpr int AdmissionFailureExitCode(AdmissionStage stage) noexcept {
  switch (stage) {
    case AdmissionStage::allocation: return 80;
    case AdmissionStage::open_thread_token: return 81;
    case AdmissionStage::open_sc_manager: return 82;
    case AdmissionStage::open_service: return 83;
    case AdmissionStage::query_service_status: return 84;
    case AdmissionStage::open_process: return 85;
    case AdmissionStage::system_token: return 86;
    case AdmissionStage::process_birth: return 87;
    case AdmissionStage::pipe_open: return 88;
    case AdmissionStage::pipe_mode_scm_bound: return 89;
    case AdmissionStage::nonce: return 90;
    case AdmissionStage::provisional_write: return 91;
    case AdmissionStage::provisional_read: return 92;
    case AdmissionStage::provisional_validation: return 93;
    case AdmissionStage::own_job: return 94;
    case AdmissionStage::pre_ack_storage_thread: return 95;
    case AdmissionStage::ack_write: return 96;
    case AdmissionStage::committed_read: return 97;
    case AdmissionStage::committed_validation: return 98;
    case AdmissionStage::postcommit_live_checks: return 99;
    case AdmissionStage::monitor_release: return 100;
    case AdmissionStage::private_offer_read: return 101;
    case AdmissionStage::private_offer_validate: return 102;
    case AdmissionStage::private_commit: return 103;
    default: return 23;
  }
}
// Holds authenticated service process + pipe for the entire CEF lifetime.
// Any revoke/disconnect/service exit kills this admitted process. Service owns
// the single root Job and must terminate the complete tree independently.
class Admission final {
 public:
  static std::unique_ptr<Admission> Acquire() noexcept;
  static AdmissionStage LastFailureStage() noexcept;
  ~Admission();
  const PrivateOwner* private_channel() const noexcept;
  Admission(const Admission&)=delete;
  Admission& operator=(const Admission&)=delete;
 private:
  Admission();
  struct State;
  std::unique_ptr<State> state_;
};
}
