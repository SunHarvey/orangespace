# Windows 通道 helper 单进程策略

**范围：每沙盒的可信 Windows sing-box helper；不限制浏览器多进程。** 这不是 WFP、浏览器受限身份、服务授权或浏览器启动许可。服务/broker 完整串联仍未完成，浏览器门禁不变。

当前：单进程实现、原生策略与真实 Windows sing-box 验证均已完成，生产代码独立复核通过。父流程实际验证 A/B 认证与独立停止、异常 supervisor 退出回收；真实崩溃用例连续 3 次通过。runtime 外层清理夹具、最后测试修正及 CI 增量均已独立复核通过。发布 SHA 的 CI 结果需在推送后单独核对，不将本机测试等同为整个第一阶段完成。

## 实现

- 完整绑定 `(user_id, sandbox_id, node_id, generation, tunnel_id)`，拒绝活动沙盒覆盖、改变所有者、复用代次或隧道 ID；A/B 独立停止。
- 在 spawn **前**创建每 Binding 独立、无名称、不可继承的 Job，设置 `KILL_ON_JOB_CLOSE | ACTIVE_PROCESS`、`ActiveProcessLimit=1`，不启用任何 breakaway。
- 先复制真实根进程句柄，再完成唯一 assignment，之后才发送 stdin 配置。成功后保留该对象作为生命周期身份和私有 assignment guard；即使根退出，也不允许将另一个根分配到同一个 Job。
- close/poll/reap 同时依据真实 Child 退出状态和保留根句柄的 signal；不枚举 PID、不推断历史成员、不以有限生命周期计数证明任意进程树回收。
- Job 设置／分配失败时不发送配置或凭据，已尝试代次被消费，已生成进程由持有的 Child 回收；清理不确定时保留所有权并失败，不启动替代连接。
- 固定公开 sing-box 参数，有界配置仅送 stdin；密码不进入 argv、环境或明文配置文件，helper stdout/stderr 不转发。Windows SystemRoot 来自 OS 查询，不继承任意环境值。
- start 成功仅代表配置写入，不代表 TUIC 在线。Linux 仍只监督直接 Child，不将开发测试平台描述成 Windows Job 策略已经覆盖的产品平台。

## 当前原生证据

Windows 11 build 26200、Rust 1.89.0、仓库锁定依赖：

- 策略 RED：旧实现真实创建子进程，`admitted=1, child user code observed=true`；limit=1 后同一原生用例为 `admitted=0, child user code observed=false`。
- 普通 CreateProcess 与 `CREATE_BREAKAWAY_FROM_JOB` 均拒绝；外部第二进程 assignment 返回原生 1816。
- 根退出后重用 Job 的 RED 被私有 assignment guard 修正。
- 正常关闭、无 Drop 的 `process::exit(37)`、A/B 独立、poll/reap、句柄不继承均有真实进程用例。
- 失败前 stdin 实测零字节，generation 消费及实际进程 signal 均检查。
- 父流程从 Cargo compiler-artifact JSON 发现程序、交叉构建并核对上传哈希，在实际 Windows 重跑 **core 28/28、isolation 8/8** 通过。只读回本次精确临时目录及 owned processes，均已清理。
- 父流程 Linux **core 14/14、isolation 8/8**、完整 `--locked` workspace 测试、最低工具链与 stable fmt、Linux/Windows all-target Clippy `-D warnings` 均通过。

本机证据：scratch `singlejob-parent-native-final.json`；实现阶段 RED/GREEN 与阶段哈希位于 `os-singlejob-20261029-a72d/`。以前允许后代并通过 PID 快照／历史计数判断清理的方案已废弃，其 23／27 项和 20 次重复均不作为当前策略证据。

## 真实 Windows runtime：父流程实机通过

使用官方 SagerNet release API 中固定 v1.14.4 Windows amd64 asset 的 publisher digest 校验 archive，再从已验证成员计算程序哈希。父流程独立重新请求官方 API、核对 CRC、archive/member 字节及 AMD64 PE：

- ZIP SHA-256：`99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df`
- EXE SHA-256：`8f30682ee198855440d2a7fe070d5d3653793b2d01bb8c85eea88f93bbe7c8b9`

后者是 archive-derived hash，不是独立发布签名。测试程序与 runtime 不随源码捆绑分发。父流程核对上传哈希后实际执行：

- 真实 A/B stdin 配置、独立 SOCKS 认证、跨沙盒密码拒绝、关闭 A 不影响 B、Drop 后 B 监听关闭；
- 真实 Go helper 已完成认证就绪，保留其实际进程观察句柄，子 supervisor 明确 `process::exit(37)`，实际 Go 句柄 signal 且监听关闭；该真实崩溃用例连续 **3 次通过**；
- 独立、非生产 inner Job 的外层清理 guard 在 activation 前建立，私有 stdin nonce 认证控制通道，观察句柄仅 query/synchronize 并验证 owned Job 归属；失败前 readiness 的 unwind 清理回归也实际通过；成功观察发生在外层 guard 清理前，不能由清理伪造；
- 默认 Windows runtime 辅助测试 **3 passed / 4 ignored**；无 opt-in 的 broad ignored gate **4 passed**，仅验证不会自行启动 runtime，不能算真实运行；
- 最终精确临时目录不存在、owned processes 为零。完整结果及 artifact hashes：scratch `real-runtime-parent-final.json`。

首轮真实崩溃 fixture 遇到 accepted socket 继承 Windows listener 非阻塞模式导致的 10035；显式恢复阻塞并保留读取期限后，上述全部复跑通过。Linux 的真实 A/B helper 测试及双回环节点 **64 次并发 TCP/native UDP**、一侧节点故障隔离也再次通过，仍不是 Windows WFP／DNS 数据面验收。

## 边界与前提

1. 这是可信前台 sing-box 的普通进程创建路径约束，不是任意恶意代码沙箱。WMI 等代理创建、具备权限的替代父进程不由这项 Job 策略普遍防御；不得据此声称浏览器子进程／任意外部进程已隔离。
2. spawn→assignment **不是原子或 suspended 创建**。分配前崩溃窗口仍在，只能依赖已验证的受保护 runtime 在收到 stdin 配置前不开展网络工作、不委托创建逃离本 Job 的进程；不能将此假设扩大为浏览器启动授权。
3. `acknowledge_protected_installation` 是调用方明确承担的来源／签名／哈希／ACL 前提，不是验证器。正式服务仍须保护 executable、目录及依赖，从真实认证会话绑定用户并使失效路由关闭。
4. Job 不实现 TCP/UDP 接管、DNS、IPv4/IPv6/loopback/WebRTC 防绕过，不提供限制令牌，也不产生任何浏览器许可。
5. 等待期限约束 polling／配置交付，不保证 OS 调用或调度的硬实时边界。Drop 保持 best-effort 回收，不将后台 waiter 当作已完成网络验收。

## 最低工具链

原 manifest 的 1.85 与已锁定 `uuid 1.29.0` 要求的 1.89 不一致，已实际复现 1.85 `--locked` 失败。工作树改为最低 **1.89**，保留既有依赖版本；源码／锁定仓库检查和临时降依赖构建不能混为一谈。完整 `--locked` workspace 检查已执行；CI 新增最低版本锁定检查及带 archive／binary 双哈希、精确测试存在性检查的 Windows 真实 runtime 用例。相应发布 SHA 的 CI 仍须提交后单独核对。
