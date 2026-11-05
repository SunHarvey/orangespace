//! Single-process policy for the protected sing-box helper, NOT for browsers.
//!
//! Configure the unnamed, non-inheritable Job BEFORE spawn: kill-on-close,
//! active-process limit one, no breakaway. Assign the actual root once before
//! stdin delivery and retain its kernel identity. While that root can execute,
//! another ordinary child cannot be admitted; limit-rejected CreateProcess
//! cannot run child user code. This is not a generic untrusted-code boundary:
//! delegated creation (for example via a privileged broker/WMI) may select a
//! different parent and is outside this trusted foreground helper's contract.
//! Once the root exits it cannot create children, and the private
//! assignment guard never reopens the Job for another root. No enumeration,
//! PID identity, lifetime counters, or historical-coverage inference is needed.
//! Completion waits for the retained actual root's signal, not Job accounting.
//! This still relies on the protected executable's pre-stdin contract: spawn
//! and assignment are NOT atomic, and pre-assignment crashes are not contained.

use std::{
    io,
    os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle},
    process::Child,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_BASIC_LIMIT_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};

#[cfg(test)]
std::thread_local! {
    static FAIL_CREATE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_ASSIGN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAILED_CHILD: std::cell::RefCell<Option<OwnedHandle>> = const { std::cell::RefCell::new(None) };
    static FAILURE_PROBE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

pub(super) struct Job {
    handle: OwnedHandle,
    // Never clear this identity, including after exit. It is also the private
    // one-successful-assignment guard; callers cannot readmit another root.
    root: Option<OwnedHandle>,
    stopping: bool,
}
impl Job {
    pub(super) fn new() -> io::Result<Self> {
        #[cfg(test)]
        if FAIL_CREATE.replace(false) {
            let invalid_name: Vec<u16> = "invalid\\job\0".encode_utf16().collect();
            // SAFETY: terminated string deliberately rejected by the real API.
            let raw = unsafe { CreateJobObjectW(std::ptr::null(), invalid_name.as_ptr()) };
            assert!(raw.is_null());
            return Err(io::Error::last_os_error());
        }
        // SAFETY: NULL security attributes => non-inheritable; NULL name => a
        // fresh unnamed Job. No other component receives this private handle.
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let job = Self {
            // SAFETY: successful creation transfers a unique owned handle.
            handle: unsafe { OwnedHandle::from_raw_handle(raw) },
            root: None,
            stopping: false,
        };
        let limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
            BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
                LimitFlags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
                ActiveProcessLimit: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        // SAFETY: live handle and exact initialized SDK structure/size. Neither
        // BREAKAWAY_OK nor SILENT_BREAKAWAY_OK is enabled.
        if unsafe {
            SetInformationJobObject(
                job.handle.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(job)
    }
    pub(super) fn assign(&mut self, child: &Child) -> io::Result<()> {
        if self.root.is_some() || self.stopping {
            return Err(io::Error::other("helper job assignment already sealed"));
        }
        // Acquire the stable identity BEFORE assignment: no fallible operation
        // may lose the one-assignment guard after successful OS admission.
        let root = child.as_handle().try_clone_to_owned()?;
        #[cfg(test)]
        if FAIL_ASSIGN.replace(false) {
            FAILED_CHILD.with(|slot| *slot.borrow_mut() = Some(root));
            FAILURE_PROBE.with(|slot| {
                if let Some(probe) = slot.borrow_mut().take() {
                    probe();
                }
            });
            // SAFETY: null is an invalid handle, not a memory pointer. This
            // injects a real API failure before any stdin writer exists.
            assert_eq!(
                unsafe { AssignProcessToJobObject(std::ptr::null_mut(), child.as_raw_handle()) },
                0
            );
            return Err(io::Error::last_os_error());
        }
        // SAFETY: both handles are live, owned actual kernel objects.
        if unsafe { AssignProcessToJobObject(self.handle.as_raw_handle(), child.as_raw_handle()) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        self.root = Some(root);
        Ok(())
    }
    pub(super) fn terminate(&mut self) -> io::Result<()> {
        if !self.stopping {
            // SAFETY: only this binding's private Job is affected. The original
            // single-process admission policy remains in force throughout stop.
            if unsafe { TerminateJobObject(self.handle.as_raw_handle(), 1) } == 0 {
                return Err(io::Error::last_os_error());
            }
            self.stopping = true;
        }
        Ok(())
    }
    pub(super) fn root_exited(&self) -> io::Result<bool> {
        use windows_sys::Win32::{
            Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT},
            System::Threading::WaitForSingleObject,
        };
        let Some(root) = &self.root else {
            // Failed assignment: std Child still owns/waits for the unassigned
            // process. No successful member has ever existed in this Job.
            return Ok(true);
        };
        // SAFETY: stable actual root process handle, zero-time signal query.
        match unsafe { WaitForSingleObject(root.as_raw_handle(), 0) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            _ => Err(io::Error::last_os_error()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{binding, settings};
    use super::super::*;
    use super::*;
    use std::{
        io::Read,
        net::{TcpListener, TcpStream},
    };
    use windows_sys::Win32::{
        Foundation::{GetHandleInformation, HANDLE_FLAG_INHERIT},
        System::{
            JobObjects::{IsProcessInJob, QueryInformationJobObject},
            Threading::{
                OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
                PROCESS_TERMINATE, TerminateProcess, WaitForSingleObject,
            },
        },
    };
    const ROOT: &str = "helper::helper_job_win::tests::root_fixture";
    const LEAF: &str = "helper::helper_job_win::tests::leaf_fixture";
    const CRASH: &str = "helper::helper_job_win::tests::abrupt_supervisor_fixture";
    const PROBE: &str = "helper::helper_job_win::tests::stdin_probe_fixture";

    struct Process(OwnedHandle);
    impl Process {
        fn open(pid: u32) -> Self {
            // SAFETY: only controlled fixture PID; immediately retain identity.
            let raw = unsafe {
                OpenProcess(
                    PROCESS_SYNCHRONIZE | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                    0,
                    pid,
                )
            };
            assert!(
                !raw.is_null(),
                "OpenProcess: {}",
                io::Error::last_os_error()
            );
            // SAFETY: successful OpenProcess transfers an owned handle.
            Self(unsafe { OwnedHandle::from_raw_handle(raw) })
        }
        fn exited(&self, millis: u32) -> bool {
            // SAFETY: live, owned process handle with synchronization rights.
            match unsafe { WaitForSingleObject(self.0.as_raw_handle(), millis) } {
                windows_sys::Win32::Foundation::WAIT_OBJECT_0 => true,
                windows_sys::Win32::Foundation::WAIT_TIMEOUT => false,
                value => panic!(
                    "fixture wait failed: {value}: {}",
                    io::Error::last_os_error()
                ),
            }
        }
    }
    impl Drop for Process {
        fn drop(&mut self) {
            // SAFETY: cleanup only our independently retained fixture identity.
            unsafe {
                TerminateProcess(self.0.as_raw_handle(), 99);
            }
            assert!(self.exited(5000), "fixture cleanup failed");
        }
    }
    fn listener() -> TcpListener {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        listener
    }
    fn accept(listener: &TcpListener) -> TcpStream {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(10)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(10)))
                        .unwrap();
                    return stream;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "fixture accept timeout");
                    thread::sleep(Duration::from_millis(2));
                }
                Err(e) => panic!("accept: {e}"),
            }
        }
    }
    fn command(name: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", name, "--nocapture"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }
    fn supervisor() -> HelperSupervisor {
        let mut executable =
            TrustedExecutable::acknowledge_protected_installation(std::env::current_exe().unwrap())
                .unwrap();
        executable.arguments = vec!["--exact".into(), ROOT.into(), "--nocapture".into()];
        HelperSupervisor::new(executable, Duration::from_secs(3)).unwrap()
    }
    fn running(s: &mut HelperSupervisor, b: Binding) -> (Process, TcpStream) {
        let listener = listener();
        let mut config = settings(b, "stay");
        config.socks_port = listener.local_addr().unwrap().port();
        let root = Process::open(s.start(b, &config).unwrap());
        let job = &s.active[&b].job;
        let mut member = 0;
        // SAFETY: independently retained actual root and private live Job.
        assert_ne!(
            unsafe {
                IsProcessInJob(
                    root.0.as_raw_handle(),
                    job.handle.as_raw_handle(),
                    &mut member,
                )
            },
            0
        );
        assert_eq!(member, 1);
        let mut flags = 0;
        // SAFETY: the stable duplicated root identity is owned and live.
        assert_ne!(
            unsafe { GetHandleInformation(job.root.as_ref().unwrap().as_raw_handle(), &mut flags) },
            0
        );
        assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
        let mut stream = accept(&listener);
        stream.read_exact(&mut [0; 4]).unwrap();
        (root, stream)
    }
    #[test]
    fn leaf_fixture() {
        let Some(port) = std::env::var_os("ORANGESPACE_JOB_LEAF_PORT") else {
            return;
        };
        let mut stream =
            TcpStream::connect(("127.0.0.1", port.to_str().unwrap().parse::<u16>().unwrap()))
                .unwrap();
        stream.write_all(&std::process::id().to_le_bytes()).unwrap();
        // Intentionally independent of socket EOF, including RED cleanup.
        loop {
            thread::sleep(Duration::from_secs(60));
        }
    }
    #[test]
    fn root_fixture() {
        if !std::env::args().any(|a| a == ROOT) {
            return;
        }
        let mut bytes = Vec::new();
        io::stdin().read_to_end(&mut bytes).unwrap();
        let config: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let port = config["inbounds"][0]["listen_port"].as_u64().unwrap() as u16;
        let mut control = TcpStream::connect(("127.0.0.1", port)).unwrap();
        control
            .write_all(&std::process::id().to_le_bytes())
            .unwrap();
        loop {
            let mut request = [0];
            if control.read_exact(&mut request).is_err() {
                // Do not let loss of a socket simulate process termination.
                loop {
                    thread::sleep(Duration::from_secs(60));
                }
            }
            if request[0] == 3 {
                let mut value = [0; std::mem::size_of::<usize>()];
                control.read_exact(&mut value).unwrap();
                let handle = usize::from_le_bytes(value) as *mut std::ffi::c_void;
                let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
                // SAFETY: deliberately probe the parent numeric handle in this
                // process; invalid/wrong-type handles are rejected by Windows.
                let inherited = unsafe {
                    QueryInformationJobObject(
                        handle,
                        JobObjectExtendedLimitInformation,
                        (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                        std::mem::size_of_val(&limits) as u32,
                        std::ptr::null_mut(),
                    )
                };
                control.write_all(&[u8::from(inherited != 0)]).unwrap();
                continue;
            }
            use std::os::windows::process::CommandExt;
            let mut command = command(LEAF);
            command.env("ORANGESPACE_JOB_LEAF_PORT", port.to_string());
            if request[0] == 2 {
                command.creation_flags(
                    windows_sys::Win32::System::Threading::CREATE_BREAKAWAY_FROM_JOB,
                );
            }
            match command.spawn() {
                Ok(child) => {
                    control.write_all(&[1]).unwrap();
                    drop(child);
                }
                Err(error) => {
                    assert!(error.raw_os_error().is_some());
                    control.write_all(&[0]).unwrap();
                }
            }
        }
    }
    #[test]
    fn single_process_policy_denies_child_user_code() {
        for request in [1, 2] {
            let mut supervisor = supervisor();
            let b = binding();
            let listener = listener();
            let mut config = settings(b, "stay");
            config.socks_port = listener.local_addr().unwrap().port();
            let root = Process::open(supervisor.start(b, &config).unwrap());
            let mut control = accept(&listener);
            control.read_exact(&mut [0; 4]).unwrap();
            control.write_all(&[request]).unwrap();
            let mut admitted = [0];
            control.read_exact(&mut admitted).unwrap();
            // Retain/clean a successful child's actual identity on RED too.
            let leaf = if admitted == [1] {
                let mut stream = accept(&listener);
                let mut pid = [0; 4];
                stream.read_exact(&mut pid).unwrap();
                Some(Process::open(u32::from_le_bytes(pid)))
            } else {
                None
            };
            println!(
                "native child CreateProcess request={request} admitted={}, child user code observed={}",
                admitted[0],
                leaf.is_some()
            );
            assert!(!root.exited(0));
            assert_eq!(
                admitted,
                [0],
                "single-process helper admitted child user code"
            );
            assert!(matches!(listener.accept(), Err(e) if e.kind() == io::ErrorKind::WouldBlock));
            supervisor.close(b).unwrap();
            assert!(root.exited(0));
        }
    }
    #[test]
    fn assigned_job_cannot_be_reused_after_root_exit() {
        let listener = listener();
        let spawn = || {
            command(LEAF)
                .env(
                    "ORANGESPACE_JOB_LEAF_PORT",
                    listener.local_addr().unwrap().port().to_string(),
                )
                .spawn()
                .unwrap()
        };
        let mut root = spawn();
        let root_handle = Process::open(root.id());
        let _root_stream = accept(&listener);
        let mut job = Job::new().unwrap();
        job.assign(&root).unwrap();
        root.kill().unwrap();
        root.wait().unwrap();
        assert!(root_handle.exited(0));
        let mut other = spawn();
        let other_handle = Process::open(other.id());
        let _other_stream = accept(&listener);
        let reassignment = job.assign(&other);
        other.kill().unwrap();
        other.wait().unwrap();
        assert!(other_handle.exited(0));
        assert!(
            reassignment.is_err(),
            "assigned Job admitted replacement root after original exit"
        );
        // The retained root still names exactly the original kernel object.
        assert_ne!(
            unsafe {
                windows_sys::Win32::Foundation::CompareObjectHandles(
                    job.root.as_ref().unwrap().as_raw_handle(),
                    root_handle.0.as_raw_handle(),
                )
            },
            0
        );
    }
    #[test]
    fn external_second_process_assignment_is_denied() {
        let mut supervisor = supervisor();
        let b = binding();
        let (root, _control) = running(&mut supervisor, b);
        let listener = listener();
        let mut other = command(LEAF)
            .env(
                "ORANGESPACE_JOB_LEAF_PORT",
                listener.local_addr().unwrap().port().to_string(),
            )
            .spawn()
            .unwrap();
        let other_handle = Process::open(other.id());
        let _other_stream = accept(&listener);
        let job = &supervisor.active[&b].job;
        // Bypass the Rust guard to exercise actual OS admission denial.
        assert_eq!(
            unsafe { AssignProcessToJobObject(job.handle.as_raw_handle(), other.as_raw_handle()) },
            0
        );
        println!(
            "external second assignment native error={}",
            io::Error::last_os_error()
        );
        let mut member = 1;
        assert_ne!(
            unsafe {
                IsProcessInJob(
                    other.as_raw_handle(),
                    job.handle.as_raw_handle(),
                    &mut member,
                )
            },
            0
        );
        assert_eq!(member, 0);
        supervisor.close(b).unwrap();
        assert!(root.exited(0));
        // Windows may terminate a process whose external assignment hit the
        // active limit. It is a preexisting external fixture, not a descendant.
        if !other_handle.exited(0) {
            other.kill().unwrap();
        }
        other.wait().unwrap();
    }
    #[test]
    fn job_limits_and_handles_are_private_before_spawn() {
        let a = Job::new().unwrap();
        let b = Job::new().unwrap();
        assert_eq!(
            unsafe {
                windows_sys::Win32::Foundation::CompareObjectHandles(
                    a.handle.as_raw_handle(),
                    b.handle.as_raw_handle(),
                )
            },
            0
        );
        for job in [&a, &b] {
            let mut flags = 0;
            assert_ne!(
                unsafe { GetHandleInformation(job.handle.as_raw_handle(), &mut flags) },
                0
            );
            assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            assert_ne!(
                unsafe {
                    QueryInformationJobObject(
                        job.handle.as_raw_handle(),
                        JobObjectExtendedLimitInformation,
                        (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                        std::mem::size_of_val(&limits) as u32,
                        std::ptr::null_mut(),
                    )
                },
                0
            );
            assert_eq!(
                limits.BasicLimitInformation.LimitFlags,
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            );
            assert_eq!(limits.BasicLimitInformation.ActiveProcessLimit, 1);
            assert!(job.root.is_none());
        }
    }
    #[test]
    fn root_does_not_inherit_job_handle() {
        let mut supervisor = supervisor();
        let b = binding();
        let (root, mut control) = running(&mut supervisor, b);
        let job = &supervisor.active[&b].job;
        let value = job.handle.as_raw_handle() as usize;
        control.write_all(&[3]).unwrap();
        control.write_all(&value.to_le_bytes()).unwrap();
        let mut inherited = [1];
        control.read_exact(&mut inherited).unwrap();
        assert_eq!(inherited, [0], "child inherited a usable parent Job handle");
        drop(control);
        assert!(
            !root.exited(100),
            "fixture must not self-exit on socket EOF"
        );
        supervisor.close(b).unwrap();
        assert!(root.exited(0));
    }
    #[test]
    fn stdin_probe_fixture() {
        if !std::env::args().any(|a| a == PROBE) {
            return;
        }
        let port: u16 = std::env::args().next_back().unwrap().parse().unwrap();
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetStdHandle(n: u32) -> *mut std::ffi::c_void;
            fn PeekNamedPipe(
                h: *mut std::ffi::c_void,
                buffer: *mut std::ffi::c_void,
                size: u32,
                read: *mut u32,
                available: *mut u32,
                left: *mut u32,
            ) -> i32;
        }
        let mut available = u32::MAX;
        // SAFETY: inherited stdin is the live pipe; null unused outputs and a
        // valid available-byte output. Do not consume or disclose any bytes.
        assert_ne!(
            unsafe {
                PeekNamedPipe(
                    GetStdHandle((-10i32) as u32),
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut available,
                    std::ptr::null_mut(),
                )
            },
            0
        );
        assert!(!std::env::args().any(|a| a.contains("secret")));
        assert!(std::env::vars().all(|(k, v)| !k.contains("SECRET") && !v.contains("secret")));
        stream.write_all(&available.to_le_bytes()).unwrap();
        loop {
            thread::sleep(Duration::from_secs(60));
        }
    }
    #[test]
    fn job_setup_failures_are_closed_and_consume_generation_without_stdin() {
        for fail_creation in [true, false] {
            let mut supervisor = supervisor();
            let b = binding();
            let listener = listener();
            supervisor.executable.arguments = vec![
                "--exact".into(),
                PROBE.into(),
                "--nocapture".into(),
                "--skip".into(),
                listener.local_addr().unwrap().port().to_string().into(),
            ];
            if fail_creation {
                FAIL_CREATE.set(true);
            } else {
                FAIL_ASSIGN.set(true);
                FAILURE_PROBE.with(|slot| {
                    *slot.borrow_mut() = Some(Box::new(move || {
                        let mut stream = accept(&listener);
                        let mut available = [0xff; 4];
                        stream.read_exact(&mut available).unwrap();
                        assert_eq!(
                            u32::from_le_bytes(available),
                            0,
                            "config bytes delivered before successful assignment"
                        );
                    }))
                });
            }
            let result = supervisor.start(b, &settings(b, "stay"));
            assert!(result.is_err());
            assert!(supervisor.active.is_empty());
            assert_eq!(
                supervisor.history.get(&b.sandbox_id),
                Some(&(b.user_id, b.generation))
            );
            assert!(supervisor.start(b, &settings(b, "stay")).is_err());
            if !fail_creation {
                let child = Process(FAILED_CHILD.with(|slot| slot.borrow_mut().take().unwrap()));
                assert!(
                    child.exited(0),
                    "failed assignment child not terminated/reaped"
                );
            }
        }
        println!(
            "real Job create/assign failures: zero stdin bytes before failure; generation consumed; child signaled"
        );
    }
    #[test]
    fn normal_close_waits_actual_root_signal() {
        let mut supervisor = supervisor();
        let b = binding();
        let (root, _control) = running(&mut supervisor, b);
        assert!(!supervisor.active[&b].job.root_exited().unwrap());
        supervisor.close(b).unwrap();
        assert!(root.exited(0));
        assert!(supervisor.active.is_empty());
    }
    #[test]
    fn independent_jobs_never_stop_the_other_root() {
        let mut supervisor = supervisor();
        let a = binding();
        let b = binding();
        let (a_root, _a) = running(&mut supervisor, a);
        let (b_root, _b) = running(&mut supervisor, b);
        supervisor.close(a).unwrap();
        assert!(a_root.exited(0));
        assert!(!b_root.exited(0));
        assert!(supervisor.poll(b).unwrap().is_none());
        supervisor.close(b).unwrap();
        assert!(b_root.exited(0));
    }
    #[test]
    fn root_exit_poll_and_reap_wait_actual_root_signal() {
        for use_reap in [false, true] {
            let mut supervisor = supervisor();
            let b = binding();
            let (root, _control) = running(&mut supervisor, b);
            assert_ne!(unsafe { TerminateProcess(root.0.as_raw_handle(), 23) }, 0);
            assert!(root.exited(5000));
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let exit = if use_reap {
                    supervisor.reap_exits().unwrap().pop()
                } else {
                    supervisor.poll(b).unwrap()
                };
                if let Some(exit) = exit {
                    assert_eq!(exit.binding, b);
                    assert_eq!(exit.status.code(), Some(23));
                    break;
                }
                assert!(Instant::now() < deadline);
                thread::sleep(Duration::from_millis(2));
            }
            assert!(supervisor.active.is_empty());
        }
    }
    #[test]
    fn abrupt_supervisor_fixture() {
        let Some(port) = std::env::var_os("ORANGESPACE_JOB_CRASH_PORT") else {
            return;
        };
        let mut supervisor = supervisor();
        let b = binding();
        let (root, _control) = running(&mut supervisor, b);
        let mut controller =
            TcpStream::connect(("127.0.0.1", port.to_str().unwrap().parse::<u16>().unwrap()))
                .unwrap();
        controller
            .write_all(&supervisor.active[&b].id().to_le_bytes())
            .unwrap();
        controller.read_exact(&mut [0]).unwrap();
        assert!(!root.exited(0));
        // No Rust destructors, including the fixture's emergency cleanup guard.
        std::process::exit(37);
    }
    #[test]
    fn abrupt_supervisor_exit_kills_root_without_drop() {
        let listener = listener();
        let mut fixture = command(CRASH)
            .env(
                "ORANGESPACE_JOB_CRASH_PORT",
                listener.local_addr().unwrap().port().to_string(),
            )
            .spawn()
            .unwrap();
        let _supervisor_guard = Process::open(fixture.id());
        let mut controller = accept(&listener);
        let mut pid = [0; 4];
        controller.read_exact(&mut pid).unwrap();
        let root = Process::open(u32::from_le_bytes(pid));
        assert!(!root.exited(0));
        controller.write_all(&[1]).unwrap();
        assert_eq!(fixture.wait().unwrap().code(), Some(37));
        assert!(
            root.exited(5000),
            "root survived supervisor exit without Drop"
        );
        println!("abrupt supervisor exit=37 without Drop: actual root signaled");
    }
}
