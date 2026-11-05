#pragma once
#ifdef _WIN32
#include <windows.h>
#include <vector>
namespace orangespace::wfp_prototype {
// Explicit one-owner operation. No destructor mutation, no reset-all operation.
// NetworkIsolation has no CAS: other privileged writers MUST be quiescent.
class OwnedLoopbackExemption final {
public:
  struct Entry { std::vector<BYTE> sid; DWORD attributes; bool operator==(const Entry&) const = default; };
  using Snapshot = std::vector<Entry>;
  struct Receipt {
    DWORD getBefore=ERROR_SUCCESS, set=ERROR_SUCCESS, getAfter=ERROR_SUCCESS;
    bool setAttempted=false, exact=false;
  };
  explicit OwnedLoopbackExemption(PSID newlyCreatedUniqueSid);
  ~OwnedLoopbackExemption() = default; // Never silently mutate global state.
  OwnedLoopbackExemption(const OwnedLoopbackExemption&)=delete;
  OwnedLoopbackExemption& operator=(const OwnedLoopbackExemption&)=delete;
  Receipt appendAfterVerifiedWfp();
  Receipt removeOnlyOwned(); // Also required after failed/uncertain append.
  const Snapshot& baseline() const noexcept { return baseline_; }
  static DWORD read(Snapshot& out);
  static bool equivalent(Snapshot a, Snapshot b);
private:
  std::vector<BYTE> sid_;
  Snapshot baseline_;
  bool attempted_=false;
};
}
#endif
