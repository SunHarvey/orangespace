# 橙域 OrangeSpace

<p align="center">
  <img src="assets/brand/orangespace-logo-approved.png" width="160" alt="橙域 OrangeSpace Logo">
</p>

**远方的网络，眼前的工作空间。**

Windows 上的多个独立浏览工作区，分别使用指定 Linux 节点的网络；同一节点上的多用户分别拥有自己的个人文件区。浏览器程序共用，Cookie、登录状态及网站数据按沙盒保存在 Windows 本机。

这是第一阶段开发代码，**当前可管理本机沙盒、运行节点文件 API、验证独立 TUIC 通道；尚不能作为安全联网浏览器使用。** Windows 的完整 CEF 宿主、WFP TCP/UDP 接管和 DNS 防泄漏尚未完成，因此“打开浏览器”始终拒绝，仓库没有解除该限制的调试开关。

| 部分 | 当前实现 |
|---|---|
| Windows 客户端 | C++20 原生管理器：新建、列表、绑定节点、关闭、删除沙盒；实际调用 Rust broker |
| 本机数据 | SQLite 元数据，每沙盒独立 profile/cache/tasks；关闭、切换节点保留，删除才清理 |
| 独立路由 | Rust 类型和状态机：用户/沙盒/节点/连接代次绑定，TCP 流与 UDP 关联映射，失效回包拒绝 |
| TUIC | sing-box 1.14.4 配置生成；真实双节点 TCP/UDP 回环集成测试；尚未接入 Windows 流量捕获 |
| Linux 文件服务 | FastAPI、PostgreSQL/SQLite、账号和令牌、个人目录、上传/下载/目录/删除 |
| Windows 网络防护 | WFP 持久阻断基础工具；完整接管驱动、受限身份、DNS 和服务 IPC 未实现 |
| 完整浏览器 | CEF Views / Chrome-style 组件初始源码，未完成 bootstrap 集成，不参与构建 |
| 浏览器文件桥 | 已确定接口与任务归属规则；尚未接入浏览器文件选择、下载回调 |

当前 UI 输入的用户 UUID 是开发用本机工作区标识，不是服务端登录。节点 API 的真实认证已实现；客户端登录、受信节点清单、凭据保护与个人文件面板仍待接入。

## 目录

```text
apps/windows-client/          Windows 管理器、客户端模型、CEF 组件
crates/orangespace-core/      沙盒、路由、任务归属及 TUIC 配置
crates/orangespace-broker/    本地 SQLite 和 JSON CLI
drivers/wfp-baseline/        真实的 block-only WFP 策略工具（不是接管驱动）
server/                     Linux 多用户个人文件 API
deploy/                     systemd、Caddy 和 Unbound 配置
scripts/                    Windows 构建、节点配置生成、真实 TUIC 烟测
assets/brand/               用户确定的 Logo 原图
docs/                       架构、当前验证记录和 Windows 验收条件
```

## 本机开发验证

Rust stable（本次验证版本 1.97.1）、Python 3.12+、CMake 3.24+、C++20 编译器：

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

该构建产物是开发管理器，不含可联网 CEF 浏览器。Windows 实机运行和完整网络验收尚未完成，详见 [Windows 验证](docs/windows-validation.md)。

## 运行节点与隧道验证

按 [节点服务说明](server/README.md) 设置稳定的节点 UUID、数据库和数据目录，用管理员 CLI 创建账号，再运行文件 API；公网使用 HTTPS 反向代理。服务端不运行浏览器。

独立 TUIC 双节点测试只监听本机，临时创建证书和凭据，不联系公网网站。安装官方 sing-box **1.14.4** 和 OpenSSL，运行：

```sh
cargo build --workspace --locked
python3 scripts/smoke_tuic.py --sing-box /absolute/path/to/sing-box
```

它测试同一目标地址经两个通道得到不同节点回包、并发 TCP/native UDP、一侧节点失效不影响另一侧，以及防护未完成时 broker 拒绝打开浏览器。它**不证明** Windows 已接管流量或 DNS 无泄漏。

部署草案见 [部署说明](deploy/README.md)，整体边界见 [架构说明](docs/architecture.md)，本机实际运行结果见 [验证记录](docs/verification.md)。GitHub Actions 提供 Linux/Windows 构建、测试和隧道检查，执行结果以仓库 Actions 页面为准。

本仓库独立编写；IdenGrid 只作为架构参考，未复制其代码。第三方组件和品牌资源说明见 [THIRD_PARTY.md](THIRD_PARTY.md)。
