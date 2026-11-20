# 橙域 OrangeSpace

<p align="center">
  <img src="assets/brand/orangespace-logo-approved.png" width="160" alt="橙域 OrangeSpace Logo">
</p>

**远方的网络，眼前的工作空间。**

Windows 上的多个独立浏览工作区，分别使用指定 Linux 节点的网络；同一节点上的多用户分别拥有自己的个人文件区。浏览器程序共用，Cookie、登录状态及网站数据按沙盒保存在 Windows 本机。

联网路线是“显式代理 + 每沙盒 WFP 兜底”：每个沙盒的浏览器只通过本沙盒 sing-box helper 的本机认证代理上网，WFP 规则按沙盒的 AppContainer 只放行到该代理端口的 TCP，其余全部阻断。详见 [架构说明](docs/architecture.md) 和 [路线图](docs/roadmap.md)。

**当前处于 P0 收敛阶段，主线还不能打开浏览器。** 可用的是本机沙盒管理、节点文件 API、每沙盒独立 TUIC helper；浏览器启动链在 P1 接入。

| 部分 | 当前实现 |
|---|---|
| Windows 客户端 | C++20 原生管理器：新建、列表、绑定节点、关闭、删除沙盒；实际调用 Rust broker |
| 本机数据 | SQLite 元数据，每沙盒独立 profile/cache/tasks；关闭、切换节点保留，删除才清理 |
| TUIC | sing-box 1.14.4 配置生成；真实双节点 TCP/UDP 回环集成测试；尚未接入 Windows 流量捕获 |
| Linux 节点与中心 | Python/FastAPI、SQLAlchemy/Alembic、MySQL、中心身份和节点授权、个人文件 API；实际 RDS 资料待提供 |
| Windows 网络防护 | 按 AppContainer 包 SID 的 WFP 规则库（`drivers/wfp-prototype`），仅在原型服务中使用；P1 并入主服务 |
| 浏览器 | 固定 CEF 版本；显式代理 BrowserHost 目前只在原型（`apps/windows-client/prototype`）中，P1 并入主线 |
| 客户端登录 | 管理窗口接入受保护中心配置、中心 HTTPS SDK、授权节点、DPAPI 与本机 SQLite；真实 GUI 完整流程验收仍待完成 |
| helper 生命周期 | 每沙盒独立 TUIC helper、LocalSystem Service 独立授权、精确停止；短时双沙盒真实链路通过，GUI 多租约周期与 WFP 分开验收 |
| 浏览器文件桥 | 已确定接口与任务归属规则；尚未接入浏览器文件选择、下载回调 |

管理窗口身份来自中心认证回复，授权节点来自中心 API；CLI 的 UUID 参数仍仅用于本机开发操作。Web 管理后台与 Windows 本机沙盒管理器是独立入口，Linux 不运行浏览器。干净源码三包构建见 [开发包构建](deploy/packages/README.md)，后续阶段见 [路线图](docs/roadmap.md)。

## 目录

```text
apps/windows-client/          Windows 管理器、客户端模型、CEF 组件
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
