# Bounded Centre HTTPS login diagnostic (no Windows execution yet)

Existing executable, new opt-in branch only:

```text
OrangeSpaceLogin.exe --platform-https-stdin <absolute-protected-platform.json> [expected-authorized-nodeUUID]
```

Use the existing administrator-protected PlatformConfig, including its protected
schema-2 ca_file validation. No trust/ACL bypass or certificate-store change.
A parent supplies a private anonymous stdin pipe (console and disk-file handles
are rejected; FILE_TYPE_PIPE itself cannot distinguish anonymous/named pipes).
Write exactly UTF-8 username + LF + UTF-8 password + LF, no BOM, CR or controls.
Username: 1..256 bytes (SDK actual limit); password: 1..1024 bytes. Maximum
accepted frame: 1282 bytes. Reads stop at the second LF, never await EOF and do
not consume trailing bytes. A missing LF can wait on an open producer: byte
bounds are not a wall-clock timeout. The parent owns cancellation/pipe closure.
Secrets must never be argv, environment, disk fixtures, echoed or logged.

Order: protected config; framed stdin; unequal synthesized wrong password must
return precisely HTTP 401; real SDK login; revalidate; SDK nodes() (all pages,
including zero grants); in-memory envelope; SDK restore and all identity fields
comparison; logout only the exact session returned by this mode's login; old
envelope restore must return precisely HTTP 401. The optional canonical UUID
is only compared with authenticated nodes(), never supplied as authority.

Exit 0 stdout (one line, Windows CRT may emit CRLF):

```text
Platform HTTPS diagnostic passed nodes=<decimal-count>
```

Exit 1 stderr (one line):

```text
Platform HTTPS diagnostic failed stage=<constant>
```

Allowed stages: config, arguments, stdin, wrong-password, login, revalidate,
nodes, export, restore, logout, stale-restore. Invalid argc: exit 2 with the same
failure marker and stage=arguments. No exception text, response body, identity,
access token or serialized envelope is output. No success on unknown logout.
On failure cleanup attempts logout only for its own returned session; failure
stays failure even if retry succeeds. A login request that succeeds remotely but
throws/loses its response before returning a Session cannot be cleaned up by
this caller (SDK API limitation); no session-list or user-wide logout is used.

Local tests (portable extraction of exact production parser/caller, injected
Session operations, not native transport evidence):

```sh
python3 apps/windows-client/tests/platform_https_stdin_tests.py
```

Observed RED: missing bounded platform HTTPS diagnostic; GREEN after parser/
caller implementation; second RED: missing Windows command dispatch; GREEN
after opt-in command branch. Covers framing/UTF-8/length, no EOF consumption,
strict 401 negative controls, wrong-login accidental success exact cleanup,
node failure, identity mismatch, unknown logout, stale 503/200 rejection,
optional missing expected node and zero authorized nodes. SDK pagination remains
the existing SDK's responsibility, exercised by platform_session_tests.cpp.

GNU production TU and OrangeSpaceLogin link are compile-only evidence. No
Windows binary is executed here. No DPAPI, Service, helper, GUI, browser or WFP
acceptance is claimed. Existing modes and browser denial remain unchanged.
