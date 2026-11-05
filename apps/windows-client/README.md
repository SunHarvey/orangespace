# OrangeSpace Windows 客户端

当前交付的是 **可构建的原生管理器源码**，不是已经具备安全联网能力的完整浏览器发行版。管理器通过相邻的 Rust broker 真实创建、读取、绑定、关闭和删除本机沙盒；不会显示假在线状态，也不会启动不受保护的浏览器。

## Windows 构建

需要 Windows 11 x64、Visual Studio 2022 的 Desktop development with C++、Windows SDK、CMake 3.24+，以及 Rust stable。

在仓库根目录运行：

```powershell
cargo build --release -p orangespace-broker
cmake -S apps/windows-client -B build/windows-client -A x64
cmake --build build/windows-client --config Release
ctest --test-dir build/windows-client -C Release --output-on-failure
Copy-Item target/release/orangespace-broker.exe build/windows-client/Release/
& build/windows-client/Release/OrangeSpace.exe
```

管理窗口已替换手输用户/节点 UUID 的路径：先验证管理员保护的节点清单，选择可信别名，再通过 HTTPS 登录和 `/v1/me` 取得真实身份；同名账号不会自动跨节点合并。实现与限制见 [窗口登录](../../docs/windows-login-ui.md)。当前已完成控制器测试与交叉编译，尚未完成真实 HTTPS 登录和交互验收。服务端令牌撤销、刷新、DPAPI 持久存储和文件面板仍待接入。

“绑定节点”当前只调用 broker 固定节点 ID；不会伪造隧道已经建立。“打开浏览器”由 broker 和管理器两处拒绝，没有配置或命令行开关可以解除。

## 本机数据约定

broker 管理 `%LOCALAPPDATA%/OrangeSpace/users/<用户 UUID>/sandboxes/<沙盒 UUID>/`。每个沙盒分别拥有 `profile`、`cache`、`tasks`；节点切换和关闭保留这些数据，删除沙盒才清理本机数据。Linux 文件不由删除本机沙盒操作触碰。

管理器仅从自身目录启动 `orangespace-broker.exe`，不搜索 PATH、不调用 shell。参数按 Windows 规则单独引用；只继承专门的输入输出句柄，任务对象约束其生命周期，输出限 1 MiB，15 秒超时失败。JSON 响应严格解析，并校验 schema、用户和沙盒 UUID。

## 测试范围

跨平台模型测试涵盖 Profile 路径隔离、拒绝路径穿越、跨用户响应拒绝、Unicode/异常 JSON、Windows 参数引用和不可由 JSON 声明解锁的启动门禁。在 Mac 上可以运行：

```sh
clang++ -std=c++20 -Wall -Wextra -Werror -I apps/windows-client/include apps/windows-client/tests/model_tests.cpp -o /tmp/orangespace-client-model-tests
/tmp/orangespace-client-model-tests
```

本次还使用临时 Zig/MinGW 工具链将 `main_win.cpp`、`broker_win.cpp` 按 x86_64-windows-gnu、`-Wall -Wextra -Werror` 交叉编译，编译 manifest 资源并成功链接 Windows GUI PE 可执行文件；Windows 版模型测试也成功链接。交叉编译只验证源码和链接，不验证运行行为。

该测试不验证 Win32 窗口、WFP 或实际网络隔离。Win32 管理器仍须在真实 Windows 上运行，并使用发布所需的 MSVC/SDK 构建。CEF 组件状态见 [cef/README.md](cef/README.md)。
