# 橙域 OrangeSpace

<p align="center">
  <img src="assets/brand/orangespace-logo-approved.png" width="160" alt="橙域 OrangeSpace Logo">
</p>

**远方的网络，眼前的工作空间。**

Windows 上同时运行多个沙盒，每个沙盒是一个窗口里的完整 Linux 桌面（任务栏、文件管理器、Chromium），文件和浏览器数据各自独立；每个沙盒的全部网络流量只经它绑定的 Linux 节点出网，不同沙盒可用不同节点。同一节点上的多用户分别拥有自己的个人文件区。

沙盒运行在 Windows 自带的 WSL2 中、本项目自己的 Debian 发行版里：每个沙盒一个容器、一个私有显示窗口（WSLg）和一个网关网络命名空间，网关经 TUIC 连到绑定节点，出口许可随节点租约续期、到期由内核自动断开。详见 [架构说明](docs/architecture.md)、[路线图](docs/roadmap.md) 与 [选型方案](docs/proposal-wsl-linux-desktop.md)。

**2026-11-20 起改为 WSL2 Linux 桌面路线，当前处于 L0 定案阶段。** 原生 Windows CEF/WFP 方案（下表中标为“退役”的部分）已在测试机跑通，但无法让 UDP 经节点、也没有完整桌面，不再推进。

| 部分 | 当前实现 |
|---|---|
| Windows 客户端 | C++20 原生管理器：新建、列表、绑定节点、关闭、删除沙盒；实际调用 Rust broker |
| 本机数据 | SQLite 元数据，每沙盒独立 profile/cache/tasks；关闭、切换节点保留，删除才清理 |
| TUIC | sing-box 1.14.4 配置生成；真实双节点 TCP/UDP 回环集成测试；尚未接入 Windows 流量捕获 |
| Linux 节点与中心 | Python/FastAPI、SQLAlchemy/Alembic、MySQL、中心身份和节点授权、个人文件 API；实际 RDS 资料待提供 |
| Linux 桌面沙盒 | 新路线。分支 `feat/linux-desktop-sandboxes` 的每沙盒网关回归已在 WSL2 内核通过；WSL2 中每沙盒完整桌面窗口与 fcitx5 中文输入已做可行性验证。见路线图 L1–L3 |
| Windows 网络防护（退役） | `apps/windows-service/sandbox`：按程序路径或包 SID 的 WFP 规则与读回核实，`orangespace-netcheck` 实测通过 |
| 浏览器（退役） | `apps/browserhost`：CEF 156 BrowserHost 以原生子窗口嵌入，`tools/sandbox-devlaunch` 双沙盒实测显示；服务 op 10 与客户端内嵌代码完成 |
| 客户端登录 | 管理窗口接入受保护中心配置、中心 HTTPS SDK、授权节点、DPAPI 与本机 SQLite；真实 GUI 完整流程验收仍待完成 |
| helper 生命周期 | 每沙盒独立 TUIC helper、LocalSystem Service 独立授权、精确停止；短时双沙盒真实链路通过，GUI 多租约周期与 WFP 分开验收 |
| 浏览器文件桥 | 已确定接口与任务归属规则；尚未接入浏览器文件选择、下载回调 |

管理窗口身份来自中心认证回复，授权节点来自中心 API；CLI 的 UUID 参数仍仅用于本机开发操作。Web 管理后台与 Windows 本机沙盒管理器是独立入口，Linux 不运行浏览器。干净源码三包构建见 [开发包构建](deploy/packages/README.md)，后续阶段见 [路线图](docs/roadmap.md)。

## 目录

```text
apps/windows-client/          Windows 管理器、客户端模型、CEF 组件
apps/browserhost/             每沙盒一个的 CEF BrowserHost（子窗口嵌入、管道协议）
apps/windows-service/sandbox/ 每沙盒运行时、Job 启动、WFP 规则与读回核实
tools/sandbox-devlaunch/      开发用双沙盒启动器与 WFP/会话实测工具（不分发）
crates/orangespace-core/      绑定模型、helper 监督、任务归属及 TUIC 配置
crates/orangespace-broker/    本地 SQLite 和 JSON CLI
drivers/wfp-prototype/       按 AppContainer 包 SID 的 WFP 规则库
server/                     Linux 多用户个人文件 API
deploy/                     systemd、Caddy 和 Unbound 配置
scripts/                    Windows 构建、节点配置生成、真实 TUIC 烟测
assets/brand/               用户确定的 Logo 原图
docs/                       架构、路线图；docs/archive/ 为旧路线历史记录
```

## 本机开发验证

Rust stable（最低 **1.89**；现有锁定依赖不支持 1.85）、Python 3.12+、CMake 3.24+、C++20 编译器：

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
python3 -m venv server/.venv
server/.venv/bin/python -m pip install -r server/requirements.lock -e 'server[test]'
server/.venv/bin/python -m pytest server/tests
```

Rust CLI 可在 Mac/Linux 上验证管理逻辑；指定一个自己的开发数据目录：

```sh
cargo run -p orangespace-broker -- --data-dir ./state status
cargo run -p orangespace-broker -- --data-dir ./state create --user 11111111-1111-4111-8111-111111111111 --name 深圳工作区
```

Windows 11 x64 安装 VS2022 C++ 工具、Windows SDK、Rust 和 CMake 后：

```powershell
./scripts/build-windows.ps1
./artifacts/windows-dev/OrangeSpace.exe
```

该构建产物是开发管理器，暂不含 BrowserHost（P1 接入）。旧路线下的 Windows 实机验证记录见 [docs/archive](docs/archive/README.md)。

## 运行节点与隧道验证

按 [节点服务说明](server/README.md) 设置稳定的节点 UUID、数据库和数据目录，用管理员 CLI 创建账号，再运行文件 API；公网使用 HTTPS 反向代理。服务端不运行浏览器。

独立 TUIC 双节点测试只监听本机，临时创建证书和凭据，不联系公网网站。安装官方 sing-box **1.14.4** 和 OpenSSL，运行：

```sh
cargo build --workspace --locked
python3 scripts/smoke_tuic.py --sing-box /absolute/path/to/sing-box
```

它测试同一目标地址经两个通道得到不同节点回包、并发 TCP/native UDP、一侧节点失效不影响另一侧，以及防护未完成时 broker 拒绝打开浏览器。它**不证明** Windows 已接管流量或 DNS 无泄漏。

部署草案见 [部署说明](deploy/README.md)，授权测试节点的隔离部署与来源核验见 [节点验证](docs/archive/node-staging-validation.md)，整体边界见 [架构说明](docs/architecture.md)。GitHub Actions 提供 Linux/Windows 构建、测试和隧道检查，执行结果以仓库 Actions 页面为准。

本仓库独立编写；IdenGrid 只作为架构参考，未复制其代码。第三方组件和品牌资源说明见 [THIRD_PARTY.md](THIRD_PARTY.md)。
