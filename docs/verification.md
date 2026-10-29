# 2026-10-29 本机验证记录

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
