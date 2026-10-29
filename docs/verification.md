# 验证记录

## 2026-10-29 接手后的第一阶段增量

基线 `38d9739`；以下是 Linux x86-64 与 Windows 11 build 26200 的实际执行，不覆盖后文历史记录。第一阶段仍在进行，尚未开放浏览器。

- Linux：Rust 27 项测试通过（broker 单元 3、CLI 2、core 单元 14、隔离集成 8）；fmt 和 Clippy `-D warnings` 通过。
- Linux：统一 CMake/CTest 4/4 通过（管理模型、节点会话、CEF 拒绝策略、服务策略）。CEF 包离线测试 4/4 通过。
- PostgreSQL 17：临时专用测试数据库实际运行，Python 38/38 通过；SQLite 路径 37 通过、1 跳过。第三方 Starlette TestClient 弃用警告仍在。
- 真实 HTTP：1 MiB 文件、同用户多会话共享、跨用户拒绝、令牌撤销、原子冲突和 Range 通过。
- sing-box 1.14.4：固定 Linux amd64 包 SHA-256 核对通过，双回环节点 64 次并发 TCP/native UDP 往返、单节点失效隔离、浏览器门禁拒绝通过。不是深圳/广州公网节点或 Windows WFP 验收。
- Windows 交叉编译：管理器、登录诊断、服务、原生测试和策略测试成功；使用 MinGW 静态编译运行库。WFP 基础工具仍需 Windows SDK，当前 MinGW 缺相关定义。
- Windows 实机：管理模型、节点会话 100 项校验、CEF 拒绝策略、服务策略通过；Rust core 14、broker 单元 2、隔离集成 8 通过。Windows 少一个 broker 测试是 Unix symlink 测试受平台条件限制，不冒充全部平台覆盖。
- Windows 实机：以临时 limited interactive-token 计划任务运行 DPAPI roundtrip/tamper/scope、Named Pipe DACL、实际令牌校验、restricted-token 拒绝、超时/取消及浏览器拒绝测试，通过；计划任务清理通过。这不是独立第二个账号验证。
- Windows 实机：临时服务在全新、管理员保护的 Program Files 子目录中运行，读取 SCM 验证 LocalSystem、精确二进制路径与 PID，启动/停止通过；服务、进程和目录均清理。该桌面会话断开，没有验收已安装服务的 active-WTS 端点或管理窗口。
- CEF：官方索引匹配固定版本；实际下载 minimal 包 175051364 字节，核对 SHA-1 并新增项目 SHA-256 锁；完整安全解包、真实头文件/layout 校验通过。bootstrap/host 两个源文件的 MinGW 编译探针通过；不是 MSVC 链接、sandbox 启动或可运行浏览器。

- 后续 CI（提交 `cc26506`，run `40898175322`）：Linux、PostgreSQL、Windows 三项全部通过。Windows 原生组件 MSVC 编译及固定 CEF wrapper/client.dll 编译链接、导出、bootstrap 复制哈希检查均通过；依然没有启动 CEF 或验收 sandbox。
- 真实 runtime 增量：`ORANGESPACE_TEST_SING_BOX` 显式运行 helper_runtime 通过，两个 sing-box 进程由 Rust supervisor 通过 stdin 配置，分别认证，跨沙盒密码拒绝，关闭 A 不影响 B，drop 后监听关闭。该项默认 ignored，不能由普通 cargo test 冒充已执行。
- 真实 Windows TLS 负例：新建受保护的管理员测试 catalog，原生 NodeSession 对不受信 TLS 服务返回保留的 WinHTTP `12175`，服务端记录 1 个 TCP 连接、0 字节 HTTP 应用数据。未修改证书库，配置和测试文件清理通过。服务端 TLS 握手可完成后再被 Windows 拒绝，不能错误声称 handshake 一定失败。

- 最新 UI/IPC 增量：统一 CMake/CTest 6/6 通过；Windows 实机通过工作区认证控制器、服务缺失/会话 0 的 IPC 负例、节点会话 100 项校验。IPC 负例不是已安装服务握手验收。13 项 Python 脚本／依赖闭包测试通过；TLS fixture 的独立超时清理、上传顺序和成功输出时机已补回归，并在真实 Windows 重跑成功。

- 已安装服务 IPC 初轮（其整表重建 DACL 策略被复核阻断，后续修正见下）：在原有 Disconnected 会话 2，以真实非提权客户端完成 LocalSystem SCM + 实际 pipe PID + `locked_foundation` + ACK 握手；停止服务时旧 read 失败、旧连接失效，重启后新握手成功。不改变 RDP 状态。为保留服务进程句柄而增加的最小观察权限仍需独立审查；这不是凭据 IPC。父流程核对两份二进制 SHA-256、重新构建并通过 CTest 6/6，另行读回服务、任务、进程、精确 Program Files 测试目录和上传目录均不存在。详见 `docs/service-ipc-validation.md`。

- DACL 修正版（二次独立复核通过，已独立提交并推送 `56a0edf`，GitHub SunHarvey／Verified 已核验；该 SHA 的 Linux、PostgreSQL、Windows 三项 CI 全部成功）：保存不可变基线，保持原 ACE 字节／顺序及拒绝语义，仅追加或撤销服务管理的观察授权；不再合成 SYSTEM／Administrators 全权规则。原生 AccessCheck 记录覆盖基线／继承拒绝、同 SID 原有权利、重复 SID、增撤、幂等和外部漂移拒绝；已安装服务握手与重启记录通过。父流程核对三份二进制及脚本 SHA-256，重新构建 Linux CTest 6/6 通过。修正版日志记录了成功运行的精确服务／任务／进程／目录／上传清理；额外 SCM 历史查询审批受阻未执行，未重试或绕过，不将其计为验收证据。特权并发写不存在原子比较交换、已打开句柄不可撤销等限制见 `docs/service-ipc-validation.md`。

- Windows helper 单进程实现已完成，父流程在真实 Windows 重跑 core 28/28、isolation 8/8 通过；普通创建及 breakaway 均被拒绝，唯一 assignment guard、无 Drop 异常退出及失败前 stdin 零字节通过。独立生产复核通过；真实 Windows sing-box A/B 认证与独立关闭通过，无 Drop 的 supervisor 退出回收连续 3 次通过，外层独立失败清理回归也通过。完整 workspace／fmt／Linux 与 Windows all-target Clippy、Linux 真实 helper 及 64 次 TCP/native UDP 回环烟测再次通过；runtime 夹具、最后测试修正和 CI 增量均已独立复核通过，浏览器多进程架构不变。以下是已废止旧方案的历史验证，不能视为新策略验收：每 Binding 独立不可继承的 kill-on-close Job，真实 Windows 验证普通关闭、无 Drop 的异常退出、后代回收及 A/B 独立。初轮 core 23 通过后，复核仍发现 PID 复用和停止快照竞态；修正版增加实际归属校验、零准入屏障和生命周期句柄覆盖。父流程使用 Rust 1.89.0 和当前依赖锁（未降级 uuid）实际重跑 Windows core 27、runtime 辅助 2、隔离模型 8 均通过，并修正未知历史后代测试的前置条件竞态后连续重跑该用例 20 次通过。无法捕获已消失的历史后代时可能永久保留绑定，属于明确的保守可用性损失；Job 仍不等于 WFP、受限浏览器身份或所有竞态已排除。详见 `docs/helper-lifecycle.md`。
- 最低版本修正：真实复现 Rust 1.85 `--locked` 因 uuid 1.29.0 需要 1.89 而失败，改为最低 1.89，不更改已锁定 uuid；Rust 1.89 workspace 测试／fmt／Clippy 实际通过。`31bbccc` 的 Linux、PostgreSQL、Windows CI 已全部通过；后续 Job/MSRV 增量需核对其自己的 CI。

**未验证/未完成**：管理窗口成功登录和交互验收、服务与 broker/helper 串联、持久凭据库、成功的真实 HTTPS 节点登录及其余 TLS/重定向负例、独立第二账号、active-WTS 多会话、CEF sandbox 子进程、WFP TCP/UDP/受管 DNS/抓包、完整浏览器与文件桥、安装/驱动签名分发。

相关复现：`apps/windows-service/README.md`、`docs/client-login.md`、`docs/cef-build.md`、`docs/delivery-plan.md`。

## 2026-10-29 初始 macOS 基线记录（历史）

环境：macOS arm64、Python 3.14.8、Rust 1.97.1、Apple Clang 21、CMake 4.4.4。
以下记录来自实际执行，不将配置文件或桩返回值视为 Windows 网络隔离证明。

| 验证 | 实际结果 |
|---|---|
| FastAPI/文件存储测试 | 37 passed，1 skipped；跳过项为未配置真实 PostgreSQL 的集成测试 |
| Python 依赖与语法 | pip check 无冲突，compileall 通过；TestClient 有第三方弃用提示 |
| Rust | 14 项通过；cargo fmt、clippy `-D warnings` 通过 |
| C++ 客户端模型 | CMake 构建、CTest 通过；另用 Clang `-Wall -Wextra -Werror` 通过 |
| Windows 管理器 | Zig/MinGW 交叉编译 C++ 与 manifest 并成功链接，确认为 Windows x64 GUI PE；未在 Windows 运行 |
| WFP 基础工具 | 源码已实现，Zig 的 MinGW 头缺 WFP 定义，未完成 Windows SDK 编译和实机验证 |
| 真实 HTTP 文件 API | 临时 uvicorn 服务、两个账号、1 MiB 二进制上传下载、同账号多会话共享、跨账号拒绝、冲突不覆盖、Range、logout 失效均通过 |
| 真实 TUIC | sing-box 1.14.4，两个回环节点、两个独立客户端，64 次并发 TCP/native UDP 请求均返回正确节点标签 |
| TUIC 节点失效 | 停止深圳测试节点后其 TCP/UDP 请求失败，广州仍返回正确结果；未切换节点 |
| 部署 TUIC 配置 | 两份由 node_config.py 生成的部署结构通过实际 `sing-box check` |
| 浏览器启动限制 | CLI 与客户端模型均拒绝未完成防护的浏览器启动，无解锁开关 |

TUIC 测试校验了官方 macOS arm64 发布资产：

```text
sing-box-1.14.4-darwin-arm64.tar.gz
SHA-256 0d8c7f5ed5d587b0f1a5e9772a708ec3bfa4ac4c9329604b01d8d9c2ba406838
```

Linux CI 下载固定 amd64 资产，并校验 `699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968`。
临时隧道用一次性自签证书显式信任和名称校验，没有关闭证书验证；所有监听均为回环地址。

可重跑：

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
server/.venv/bin/python -m pytest server/tests
server/.venv/bin/python scripts/smoke_node.py
python3 scripts/smoke_tuic.py --sing-box /absolute/path/to/sing-box
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

尚未执行：真实 PostgreSQL、Linux systemd/Caddy/Unbound 部署、MSVC/Windows SDK 构建、Windows 交互操作、CEF 构建运行、完整 WFP TCP/UDP 和 DNS 泄漏验证、浏览器文件桥。
本机验证记录生成时 GitHub Actions 尚未执行，后续 CI 结果见仓库 Actions 页面。当前源码不是完整可用的安全浏览器发行版。
