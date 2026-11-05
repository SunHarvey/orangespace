// Fixed NONSECRET action. No file/pipe/report/credential/child-process interface.
// Its exit code and self-report are NEVER evidence of task/action execution.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "phase1_task_identity_probe_config.hpp"
int wmain(int argc, wchar_t**) {
  volatile const bool compilation_fixture = phase1_task_identity_probe_config::compilation_fixture;
  if (argc != 1 || compilation_fixture) return 77;
  // Future independently reviewed native diagnostic only. No work is admitted.
  Sleep(10000);
  return 0;
}
