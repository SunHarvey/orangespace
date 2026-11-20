# 路线图

原生 Windows 方案的架构见同目录 `architecture-windows-native.md`（已退役，现行路线见 `docs/architecture.md`）。更早的旧路线（内核级 WFP 重定向/UDP 回注、浏览器永久拒绝）的交付计划与验证记录已移到 `docs/archive/`，仅供参考。

## 现有可复用部分

- Linux 节点与中心：认证、节点授权、个人文件 API、隧道租约（`server/`）。
- 每沙盒 sing-box helper 的启动、认证、独立停止与回收（`crates/orangespace-core`、`crates/orangespace-runtime`）。
- Windows 服务：SCM、按 OS 令牌认证的命名管道、DPAPI 凭据、OSP2 授权与 helper 链路（`apps/windows-service`）。
- 管理器：登录、沙盒列表、文件面板（`apps/windows-client`）。
- 原型中已验证可用的片段：显式代理 CEF 客户端（`apps/windows-client/prototype/online_app.hpp`）、AppContainer + Job 启动（`apps/windows-service/prototype/service_win.cpp`）、按包 SID 的 WFP 规则（`drivers/wfp-prototype` 的 `PackageNetworkPolicy`）。

## P0 收敛（当前）

- 文档与开发约定改为新路线。
- 删除不再使用的代码：内存路由模型 `routing.rs`、`wfp-baseline`、只能编译的 CEF 宿主。
- 删除只读源码做字符串断言的测试；新测试必须验证行为。
- 过程性验收文档归档。

## P1 单沙盒联网

1. 技术验证（2026-11-20 完成，Windows 11 26H2 虚拟机）：BrowserHost 以 `SetAsChild` 嵌入另一进程的容器窗口并正常渲染，GPU 进程正常；经本沙盒认证代理加载页面。浏览器主进程放进 AppContainer 启动即崩溃，已采用每沙盒独立程序路径 + 按 AppId 的 WFP 规则（`apps/windows-service/sandbox`，`tools/sandbox-devlaunch` 双沙盒验证；`orangespace-netcheck` 实测隔离）。输入法、焦点、DPI 细节随第 4 步验收。
2. helper 入站改为带认证的 HTTP 代理（代码完成）：主服务改用 mixed 入站的后端，`take_local_channel` 只在服务进程内取出端口与凭据。
3. 并入主服务（代码完成，Windows 编译与全部 ctest 通过；真实节点端到端待第 6 步）：OSP3 op 10 `browser_open`（auth_id、精确 binding、容器窗口）。服务核验管道客户端进程就是该登录会话的用户、容器窗口属于该进程，准备 `sandboxes/<id>/`、安装并读回 WFP，以 `WTSQueryUserToken` 令牌启动 BrowserHost，写入含凭据的配置行后把命令/事件管道复制给客户端；隧道 close 时先结束浏览器树再撤销规则，`alive` 轮询时规则被改动即切断。同一逻辑 `SandboxBrowser` 已由 `tools/sandbox-devlaunch` 在 Windows 上实测（双沙盒显示、杀 helper 后立即全阻断）。原型服务及其 `NetworkPolicy`/`PackageNetworkPolicy` 尚未删除。
4. 客户端内嵌（代码完成，待真实节点验收）：每个沙盒一个容器窗口和 `BrowserPane`，地址栏和前进/后退/刷新直接写入本沙盒命令管道；删除了原型的 op 9 轮询、顶层窗口查找 + `SetParent`，以及修改窗口站 DACL 的 `InstanceStationRight`（实测会破坏整个登录会话）。限制：一次隧道代次只能打开一次浏览器（本地通道只取一次），浏览器退出后需重新连接沙盒。
5. 合并 SG 与 windows-dev 两套安装包为一个；BrowserHost 构建加入 CI。安装布局：服务目录下 `browser\`（BrowserHost 运行时，授予 ALL APPLICATION PACKAGES、ALL RESTRICTED APPLICATION PACKAGES 与 `lpacChromeInstallFiles` 读/执行）和服务所有、用户只读的 `sandboxes\`。
6. 验收（真实 Windows 抓包）：浏览器进程只连 `127.0.0.1:P`；本机对外只有 sing-box 到节点的 UDP；IP/DNS/WebRTC 泄漏测试页显示节点出口；杀掉 helper 后浏览器立即断网。

## P2 多沙盒并发

- 每沙盒独立程序路径、端口、凭据、规则；同一用户同时打开多个沙盒、绑定不同节点。
- 客户端按沙盒保存进程句柄与容器窗口，切换沙盒标签只显示/隐藏，后台沙盒继续运行；单个沙盒无响应时只结束该沙盒浏览器。
- 验收：A/B 同开出口 IP 不同；A 访问 B 的端口被 WFP 阻断且代理认证失败；切换节点、关闭、删除互不影响；在 A、B 标签间切换后两边网页会话均保持。

## P3 浏览器与文件打通

- 客户端网页标签栏：一个沙盒内多个网页标签（同一 BrowserHost、同一请求上下文），弹窗作为该沙盒的新网页标签，登录状态持久。
- 下载到原节点个人区、从节点个人区选择上传文件（流程见架构文档）。

## P4 文件管理增强

- 服务端：重命名/移动、递归删除（显式确认）、用户配额、分片续传上传；带额外硬链接的文件不再静默隐藏。
- 管理器文件面板按沙盒所绑节点显示，列出该沙盒的文件任务。

## P5 分发

- 单一安装器、exe/dll Authenticode 签名（无内核驱动）、日志脱敏、卸载时清理本产品的 WFP 规则与 AppContainer。
