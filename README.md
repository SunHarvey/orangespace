# 橙域 OrangeSpace

<p align="center">
  <img src="assets/brand/orangespace-logo-approved.png" width="160" alt="橙域 OrangeSpace Logo">
</p>

**远方的网络，眼前的工作空间。**

Windows 上同时运行多个沙盒，每个沙盒是一个窗口里的完整 Linux 桌面（任务栏、文件管理器、Chromium），文件和浏览器数据各自独立；每个沙盒的全部网络流量只经它绑定的 Linux 节点出网，不同沙盒可用不同节点。同一节点上的多用户分别拥有自己的个人文件区。

沙盒运行在 Windows 自带的 WSL2 中、本项目自己的 Debian 发行版里：每个沙盒一个容器、一个私有显示窗口（WSLg）和一个网关网络命名空间，网关经 TUIC 连到绑定节点，出口许可随节点租约续期、到期由内核自动断开。详见 [架构说明](docs/architecture.md)、[路线图](docs/roadmap.md) 与 [选型方案](docs/proposal-wsl-linux-desktop.md)。

**2026-11-20 起改为 WSL2 Linux 桌面路线。** L1–L3（运行底座、沙盒桌面、全流量经节点）已在测试虚拟机配合真实节点验收，L4（产品功能）进行中。原生 Windows CEF/WFP 方案曾在测试机跑通，但无法让 UDP 经节点、也没有完整桌面，已于 2026-11-21 从主线删除（代码在 git 历史与 `p0-consolidation` 分支，记录在 `docs/archive/`）。

| 部分 | 当前实现 |
|---|---|
| Windows 客户端 | C++20 窗口 `OrangeSpace.exe`：中心登录、本机沙盒列表、新建/打开/停止/换节点/删除，显示每个沙盒的桌面、网络与租约状态；每沙盒独立节点会话与租约续期（见 [客户端说明](apps/windows-client/README.md)） |
| 本机数据 | 每个中心用户一份沙盒列表（`%LOCALAPPDATA%\OrangeSpace\users\<用户>\sandboxes.json`）；沙盒的桌面数据在发行版内，删除沙盒才清理，节点文件不受影响 |
| 应用私有 HTTPS | Rust `crates/orangespace-https`（rustls，只信任客户端钉住的 CA），客户端经 C ABI 调用 |
| Linux 节点与中心 | Python/FastAPI、SQLAlchemy/Alembic、MySQL、中心身份和节点授权、个人文件 API；实际 RDS 资料待提供 |
| Linux 桌面沙盒 | WSL2 发行版 `OrangeSpace`：每沙盒一个加固容器、私有显示与可重连窗口、网关命名空间与 TUIC 租约隧道（`linux-desktop/`）。见路线图 L1–L3 |
| 节点文件 | 节点个人文件 API 已完成；客户端与沙盒“下载”目录之间的传输属 L4，进行中 |

客户端身份来自中心认证回复，授权节点来自中心 API。Web 管理后台与 Windows 本机沙盒管理器是独立入口，Linux 不运行浏览器。干净源码三包构建见 [开发包构建](deploy/packages/README.md)，后续阶段见 [路线图](docs/roadmap.md)。

## 目录

```text
apps/windows-client/          Windows 客户端：沙盒窗口、中心与节点会话、WSL 运行时
apps/control-console/         Web 管理后台（Vue）
linux-desktop/                WSL 发行版：桌面镜像、每沙盒容器与网关、agent
crates/orangespace-core/      绑定与代次模型、helper 监督、任务归属
crates/orangespace-https/     应用私有 HTTPS（C ABI 静态库）
server/                     中心与节点（认证、授权、隧道租约、个人文件 API）
deploy/                     节点与中心的 systemd、Caddy、Unbound 配置与开发包构建
scripts/                    Windows 客户端构建、节点配置生成、节点烟测
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

Windows 11 x64 安装 VS2022 C++ 工具、Windows SDK、Rust 和 CMake 后，构建并测试客户端（先构建 `orangespace-https` 静态库）：

```powershell
./scripts/build-windows.ps1
./build/windows/apps/windows-client/Release/OrangeSpace.exe
```

运行沙盒还需要导入 `OrangeSpace` 发行版，见 [Linux 桌面说明](linux-desktop/README.md) 与 [客户端说明](apps/windows-client/README.md)。旧路线下的 Windows 实机验证记录见 [docs/archive](docs/archive/README.md)。

## 运行节点与隧道验证

按 [节点服务说明](server/README.md) 设置稳定的节点 UUID、数据库和数据目录，用管理员 CLI 创建账号，再运行文件 API；公网使用 HTTPS 反向代理。服务端不运行浏览器。

部署草案见 [部署说明](deploy/README.md)，授权测试节点的隔离部署与来源核验见 [节点验证](docs/archive/node-staging-validation.md)，整体边界见 [架构说明](docs/architecture.md)。GitHub Actions 提供 Linux/Windows 构建与测试，执行结果以仓库 Actions 页面为准。

本仓库独立编写；IdenGrid 只作为架构参考，未复制其代码。第三方组件和品牌资源说明见 [THIRD_PARTY.md](THIRD_PARTY.md)。
