# 路线图

架构见 `docs/architecture.md`，选型依据见 `docs/proposal-wsl-linux-desktop.md`。原生 Windows CEF/WFP 路线（P0/P1）的计划与记录在 `docs/archive/roadmap-windows-native.md`。

## 可复用部分

- **中心与节点**（`server/`）：认证、节点授权、个人文件 API、隧道租约（[租约协议 v2](lease-protocol-v2.md)）。
- **Rust 核心**（`crates/orangespace-core`、`crates/orangespace-https`）：绑定与代次模型、文件任务归属、TUIC 配置生成、应用私有 HTTPS。
- **客户端**（`apps/windows-client`）：中心登录、授权节点、沙盒列表与绑定、节点文件面板、DPAPI 凭据。节点会话与租约的 C++ 库（`node_session`、`platform_session`）目前由服务和客户端共用，迁到客户端直接使用。
- **分支 `feat/linux-desktop-sandboxes`**：
  - 每沙盒网关（`linux-desktop/network/gateway.py`），其真实内核回归已在 WSL2 上通过；
  - 桌面镜像与生命周期（`linux-desktop/guest/`）；
  - 认证帧协议（`linux-desktop/bridge/`）。

## 退役

`apps/browserhost`、`apps/windows-service`（含 `sandbox/` WFP 库、原型服务与 OSP 协议）、`apps/windows-client` 中的浏览器嵌入与 CEF 打包、`tools/sandbox-devlaunch`、`drivers/wfp-prototype`。

退役前先把 `p0-consolidation` 上的原生方案完整提交保存，之后从主线删除，代码可在 git 历史中查到。退役时连同只服务于它们的测试和构建脚本一起删除，不保留无法运行的代码。

## L0 定案（当前）

- 方案文档定案，`AGENTS.md`、架构、路线图、README 改为新路线（已完成）。
- 提交保存原生方案的 P0/P1 工作。
- 新开开发分支，并入分支 `feat/linux-desktop-sandboxes` 的 `linux-desktop/`，作为新代码的起点。

## L1 运行底座

状态（2026-11-20）：代码完成，测试虚拟机验收通过；物理机体验待测。

已完成的部分：
- `linux-desktop/wsl/`：`build-rootfs`（289 MB，248 个软件包，附清单与 SHA-256）、`wsl.conf`、`agent.py` 及其测试。
- `apps/windows-client`：`wsl_channel.hpp`（帧编解码，含测试）、`wsl_runtime`（导入、从交互会话启动、请求、关闭），以及验收工具 `orangespace-wsl`。

测试机实测（从全新导入开始）：代理约 4 秒启动；不挂载任何 Windows 磁盘；无法运行 Windows 程序；systemd 与 WSLg 可用；常驻 20 秒后正常关闭。客户端界面接入随 L2 一起做。

计划：

- **构建根文件系统**：用 mmdebstrap 构建 `OrangeSpace` 的 Debian 13 根文件系统，内含客体代理、Podman、sing-box、网关、Xephyr、LXQt、Chromium、fcitx5。`wsl.conf` 开启 systemd，关闭自动挂载与互操作。同时输出软件包清单。
- **客户端管理 WSL**：检测 WSL 是否可用，`wsl --import` 导入，从交互会话启动，常驻控制进程，正常关闭。
- **控制通道**：客体代理经 `wsl.exe` 的标准输入/输出与客户端通信，沿用分支 bridge 的认证帧协议。
- **验收**：
  - 测试机和一台物理 Windows 机器上，客户端都能一键启动、停止发行版；
  - 发行版内 `/mnt` 下没有 Windows 磁盘，也无法启动 Windows 程序；
  - 在物理机上记录桌面滚动、视频、高分屏的实际体验，据此决定是否需要换显示方案。

## L2 沙盒桌面

状态（2026-11-20）：测试虚拟机验收通过，两个沙盒并排运行。

- **隔离检查**（A、B 两个沙盒都通过）：
  - 容器只有 `lo`；
  - 连得上自己的显示，连不到 WSLg 的 `:0`；
  - `/mnt` 为空；
  - Chromium 无任何能力、禁止提权、开着 seccomp；
  - A、B 的进程分属不重叠的宿主 UID 段；
  - 模拟 A 逃出容器后读 B 的 HOME，被拒绝。
- **持久化**：停止后重开，文件仍在；停止时容器和窗口一并关闭。
- **用户实测**：中文拼音可用；Windows 的文字粘贴不进沙盒（符合隔离设计）。
- **待确认**：窗口标题中的中文需要发行版里有 CJK 字体（已加入根文件系统），WSL 重启后再确认。


- 每个沙盒：
  - 一个 Podman 容器，加固见架构文档；
  - 私有 Xephyr 显示，容器只拿到本沙盒的 socket 和 cookie；
  - 会话内 fcitx5 拼音，默认开启；
  - 持久 HOME。
- 支持打开、唤回、停止、重开、删除。
- 把分支的 AppArmor 配置换成 seccomp + Landlock。
- **验收**：
  - 两个沙盒窗口并排使用；
  - 容器内连不上 `:0`，看不到 `/mnt`，读不到对方的 HOME；
  - 剪贴板与 Windows 及另一沙盒都不互通；
  - 中文输入可用；
  - 重开后文件和书签保留。

## L3 全流量出口

- 每个沙盒接入分支网关，先用静态节点配置跑通。
- 再改为由客户端创建、续租节点租约，代理据此续期内核限时许可；续租停止后许可自动过期。
- 新增 Linux 侧出口检查工具，相当于原生方案的 `orangespace-netcheck`，验证真实投递：TCP、UDP、DNS、IPv6、跨沙盒、宿主与内网地址。
- **验收**（用真实节点）：
  - Windows 物理网卡抓包，只见到发往两个节点端点的 UDP；
  - IP、DNS、WebRTC、QUIC 泄漏测试页分别显示各自节点的出口；
  - 断开节点 A，A 离线、B 不受影响；
  - 结束客户端进程，许可在租约剩余寿命内失效；
  - 切换节点后，旧代次的凭据与许可无法复活。

## L4 产品功能

- 中心登录、授权节点、沙盒列表同步，状态显示"网络离线 / 网关就绪 / 节点在线"。
- 节点个人文件：
  - 客户端文件面板继续管理节点文件；
  - 新增"节点文件 ↔ 当前沙盒下载目录"双向传送，经客体代理完成；
  - 文件任务在创建时固定 node_id。
- 多沙盒并发：每个沙盒有独立的容器、网关、租约和显示；单个沙盒异常只影响它自己。

## L5 安装与升级

- **安装器**：
  - 检测最低系统版本（Windows 11 22H2+ x64、Windows 10 22H2 x64）和硬件虚拟化；
  - 开启"虚拟机平台"和 WSL，按需提示重启；
  - 安装 WSL 并导入发行版。
- **升级**：替换系统部分，保留用户数据。
- **卸载**：默认保留用户数据，另行提供"删除全部数据"。
- **分发清单**：附软件包清单和源码获取方式。
- **验收**：在全新机器上安装、升级、卸载各一遍。
