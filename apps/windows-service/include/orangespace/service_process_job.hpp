#pragma once
#include <windows.h>

namespace orangespace::service::win {
namespace detail {
inline SRWLOCK service_process_job_lock = SRWLOCK_INIT;
// Deliberately NOT an RAII handle. Closing a Job containing this process would
// terminate the service before SCM status/CRT cleanup. Only kernel process
// teardown releases this successfully installed, non-inheritable handle.
inline HANDLE service_process_job_handle = nullptr;
inline DWORD service_process_job_error() noexcept {
    const DWORD error = GetLastError();
    return error == ERROR_SUCCESS ? ERROR_GEN_FAILURE : error;
}
}

// Call once at trusted startup, before constructing any helper/backend. This
// closes the trusted foreground helper's spawn -> per-helper Job assignment
// lifetime gap; it is not containment against malicious delegated spawning or
// privileged alternate-parent brokers. Existing helper Jobs remain nested.
// No active-process limit: service workers/browser multiprocess stay allowed.
[[nodiscard]] inline DWORD install_service_process_job() noexcept {
    AcquireSRWLockExclusive(&detail::service_process_job_lock);
    if (detail::service_process_job_handle != nullptr) {
        ReleaseSRWLockExclusive(&detail::service_process_job_lock);
        return ERROR_SUCCESS;
    }
    // Null security attributes: non-inheritable. Null name: no named opening.
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    DWORD error = ERROR_SUCCESS;
    if (!job) {
        error = detail::service_process_job_error();
    } else {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                     &limits, sizeof(limits))) {
            error = detail::service_process_job_error();
            CloseHandle(job); // This process has NOT joined on failure.
        } else if (!AssignProcessToJobObject(job, GetCurrentProcess())) {
            error = detail::service_process_job_error();
            CloseHandle(job); // Failed assignment did not transfer membership.
        } else {
            // No allocation, fallible ownership transfer, or CloseHandle after
            // successful assignment. Repeated startup cannot leak another Job.
            detail::service_process_job_handle = job;
        }
    }
    ReleaseSRWLockExclusive(&detail::service_process_job_lock);
    return error;
}
}
