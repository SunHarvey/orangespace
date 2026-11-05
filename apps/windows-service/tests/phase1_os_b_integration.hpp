#pragma once
#include "phase1_os_b_policy.hpp"
#include <functional>
#include <memory>
namespace phase1_os_b {
// TEST ONLY. Account/name/SID/profile are nonsecret recovery identifiers held in
// controller memory, NOT worker stdout. Never print Request/Fields/body.
struct Receipt {
 std::wstring account,sid,profile_path;
 ProfileState profile_state=ProfileState::unknown;
 bool account_created=false,sid_recorded=false,profile_attempted=false,profile_loaded=false,profile_path_recorded=false;
 bool process_created=false,process_reaped=false,handles_closed=false,profile_unloaded=false,profile_deleted=false,profile_absence_verified=false,account_deleted=false,account_absence_verified=false;
 bool launch_privileges_present=false,b_token_session2=false,atomic_job_attribute_set=false,atomic_launch_created=false;
 bool cleanup_ok=false,worker_exit_observed=false,io_quarantined=false;
 std::uint32_t worker_exit=0,error=0,cleanup_error=0,process_id=0,creation_low=0,creation_high=0;
 Observations observations;
};
// Must live until cleanup succeeds or parent has captured exact recovery IDs.
// Destructor attempts only owned cleanup; it never sweeps by name prefix.
// Calls on one ControllerRun must be serialized. The protected recovery sink
// must retain profile_state and io_quarantined, including UNKNOWN/preexisting
// profile gates: a known owned SID alone is not permission to delete its SAM row.
// Private framing errors abort/close the channel. Delayed cancellation retains
// one heap operation (buffer, OVERLAPPED, event and duplicate pipe handle) and
// permanently denies this process further OSB I/O, even after eventual reaping.
// Never reset the global budget; process exit is the ultimate pending-I/O bound.
enum class ControlPoint { before_a_load, before_raw };
class ControllerRun final {
 struct Impl;std::unique_ptr<Impl> p_;
public:
 ControllerRun();~ControllerRun();
 ControllerRun(const ControllerRun&)=delete;ControllerRun& operator=(const ControllerRun&)=delete;
 // No action when approved=false. root is the parent's existing protected fresh
 // fixture; body is borrowed OSB1 from an authenticated private A-client pipe.
 // held_a_process is the borrowed actual limited-A process HANDLE retained by
 // parent creation (not opened by guessed PID); library validates its token/image.
 // still_live has two typed points: begin negative-load audit, then end that
 // audit BEFORE making fresh A status calls and confirming the raw prerequisite;
 // parent must validate the exact held service + actual A grant/binding still live.
 // Worker independently observes WaitNamedPipe success before accepting error5.
 bool execute(const std::wstring& root,std::string_view body,void* held_a_process,bool approved,
  const std::function<bool(ControlPoint)>& still_live,
  const std::function<bool(const Receipt&)>& recovery_sink) noexcept;
 bool cleanup() noexcept;
 const Receipt& receipt()const noexcept;
};
// recovery_sink is REQUIRED and must durably flush only nonsecret exact OS
// allocation/cleanup receipts into parent's protected recovery ledger. No API
// username, password, grant, envelope or body belongs in that ledger. A crash
// between NetUserAdd and SID receipt remains an UNKNOWN-OWNERSHIP gate: preserve
// exact intent name and request parent recovery; never delete by prefix/name alone.
// Atomic Job admission covers child lifetime only, NOT account/profile cleanup.
// Integration requirements (not fulfilled by compiling this library):
// - Existing highest controller is session2 A; worker is separate ordinary B.
// - Real A CredentialStore::save/load and real A Grant/live binding first.
// - Copy exact encrypted file bytes + canonical alias/node, never A token.
// - body includes B Node API account credentials through private memory transport.
// - Parent must audit no API requests during the A-cipher negative interval to
//   independently assert "before NodeAPI"; production throws generic errors.
// - Entropy always includes CURRENT process SID. Canonical A node/origin is exact;
//   byte-for-byte A SID entropy under B via CredentialStore is intentionally
//   impossible without changing production, which this extension never does.
// - Controller/runner aggregate os_b_covered/full_acceptance remain false until
//   native run + independent review + parent external acceptance gates pass.
}
