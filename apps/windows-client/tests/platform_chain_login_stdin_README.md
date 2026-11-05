# 有限平台 → Service 联合诊断

仅新增 `login_win.cpp` 的 `--platform-chain-login-stdin` 分支；不替代或修改既有 `--platform-https-stdin`、Node/DPAPI modes。没有通用 launcher。

## 调用契约

```text
OrangeSpaceLogin.exe --platform-chain-login-stdin <absolute-protected-platform-config-path> <expected-node-UUID>
```

恰好两个公开位置参数。使用现有 `PlatformConfig::load` 的绝对路径/管理员保护校验。预期 UUID 必须严格匹配 SDK `Session::nodes()` 完整分页结果中的唯一 NodeRef，不接受 alias 代替 UUID。

由实际 **limited、interactive、非零 session token** 运行；进程令牌不提权且包含 Interactive SID。线程 impersonation、SSH session 0 在 `stage=token` 拒绝，发生在读取配置/凭据/网络请求之前。Service 仍自行校验 OS pipe peer；没有伪造 peer 或放宽 Service 接纳。

stdin 必须为 pipe，由既有受限交互令牌 runner 给该子进程提供 anonymous pipe。两个 UTF-8 LF 帧：

```text
username\n
password\n
```

真实输入是两行，不是字面反斜线；username 1–256 字节、password 1–1024 字节。复用 `platform_diag::line`；CRLF、空行、控制字节、无效 UTF-8、超长/未终止帧拒绝。读完第二个 LF 即运行，不等待 EOF。凭据不放 argv、env 或明文 fixture，也不回显。父进程负责及时交付帧和进程总超时；字节上界不是 wall-clock stdin 超时。

## 实际路径

SDK login → all nodes/唯一 UUID → `authorize_platform` (OSP3) → 两个 BCrypt OS-random RFC4122 v4 localSandboxUUID → 两次 `start_registered_tunnel`（API 内部 `register_sandbox`）→ 验证 sandbox/user/node 与不同 tunnel/full tuple → fresh active 恰为 A+B → exact stop A → active 仅 B → 再次 fresh active 验证 B 当前存活 → exact stop B → active 空 → exact grant `logout` → 仅该调用自身中央 Session `logout`。

两个 localSandboxUUID **只是诊断新 workspace**；不创建 SQLite 沙盒/UI Profile，不使用 DPAPI，不启动浏览器。typed start/status API 已验证 process_started/tunnel_authenticated/forwarding_verified proof 三位；不是独立 Windows WFP/持续转发证明。

## 固定输出 / 退出

成功 stdout 唯一行，退出 0：

```text
Platform chain diagnostic passed stage=complete browser_allowed=false wfp_verified=false renewal_tested=false
```

失败 stderr 唯一行：

```text
Platform chain diagnostic failed stage=<fixed-stage> cleanup=<complete|pending>
```

- 2：参数数量错误，`stage=arguments cleanup=complete`。
- 1：操作失败但已知自己持有的 grant/session 补偿清理已确认，或尚未创建它们。
- 3：补偿清理不能确认；不得当成测试成功/允许删除仍可能运行的原生 fixture。
- 固定阶段：`token arguments config stdin login nodes authorize workspace-ids start-a start-b active-two stop-a active-b status-b stop-b active-zero grant-logout central-logout complete`。

失败保留原失败阶段，不输出异常文本。预分配 optional 持有自身返回的 Session/Grant/精确 A/B Binding，typed 返回以 nothrow move 入槽。stop 成功前不丢 binding；先分别 exact stop，再 exact grant logout。logout 失败只尝试同一 grant 的 local-only `retire`，仍报告 pending，不把 retire 当远端 logout 成功。最后尝试仅自身中央 session logout；绝不按 user 全局注销或清理其他 grant。进程退出后未知远端结果/Service cleanup receipt 的观察和重试仍由既有 Service 生命周期与原生验收负责；本模式不增加持久凭据或跨进程清理 authority。

## 已亲跑与边界

```sh
TMPDIR=/var/tmp/hermes-runtime/tmp python3 apps/windows-client/tests/platform_chain_login_stdin_tests.py
TMPDIR=/var/tmp/hermes-runtime/tmp python3 apps/windows-client/tests/platform_https_stdin_tests.py
```

新测试先实际 RED（缺失 production caller），再提取并编译精确 production caller，通过注入登录/Service RPCs 覆盖正常链、逐次操作失败、错误 tuple、B 当前死亡、missing Node、补偿 logout/retire 均失败不假成功。既有 parser/HTTPS caller 回归通过。属于 portable caller policy evidence，不是 Windows interactive IPC/TUIC 实机通过。

GNU 共享统一 runtime 构建：

```sh
TMPDIR=/var/tmp/hermes-runtime/tmp flock /var/tmp/hermes-runtime/tmp/orangespace-dev-delivery-ixrznt39/https-integration/unified-build/orangespace-build.lock cmake --build /var/tmp/hermes-runtime/tmp/orangespace-dev-delivery-ixrznt39/https-integration/unified-build/client --target OrangeSpaceLogin -j1
```

已实际成功链接。父独审后才可在真实 limited interactive token 下跑中央 HTTPS + 正式 Service + Node/TUIC。没有在此开发切片操作 remote/SCM/DB/创建账号。**超过 30 秒续租尚未测试**；成功 marker 显式 `renewal_tested=false`。浏览器/WFP 始终 false。
