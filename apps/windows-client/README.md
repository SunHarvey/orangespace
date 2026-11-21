# OrangeSpace Windows 客户端

`OrangeSpace.exe` 是用户使用的窗口：登录中心、管理本机沙盒列表、打开沙盒桌面并显示每个沙盒的状态。每个沙盒是 WSL2 发行版 `OrangeSpace` 里的一个 Linux 桌面，以自己的窗口显示，全部流量只经绑定节点出网（见 [docs/architecture.md](../../docs/architecture.md)）。

## 窗口

- **登录**：用管理员保护的 `trust\platform.json`（中心）登录，节点证书固定在 `trust\catalog.json`。两份文件放在程序旁的 `trust` 目录（或用 `--trust <目录>` 指定），普通用户可写的文件会被拒绝。没有本机直连回退。
- **沙盒列表**：每个中心用户一份，存于 `%LOCALAPPDATA%\OrangeSpace\users\<中心用户 UUID>\sandboxes.json`，只记沙盒的名称和绑定节点。桌面本身（HOME、浏览器资料、下载）在发行版里。
- **新建沙盒**：起名并选择中心授权的节点；新建后立即打开。
- **打开**：为沙盒换取它自己的节点会话、创建隧道租约，把租约交给客体，启动桌面；桌面已在运行时只把关掉的窗口重新打开。
- **停止**：撤销隧道并停止桌面。
- **改用此节点**：仅在沙盒停止时可用；桌面数据保留，下次打开时经新节点联网。
- **删除**：确认后删除该沙盒在本机的桌面数据；节点上的个人文件不受影响。
- **退出登录 / 关闭窗口**：先停止所有沙盒，再退出。客户端被强行结束时，代理随控制通道关闭停掉所有桌面，内核许可在租约剩余寿命内自行过期。

状态列只显示观察到的情况：

| 列 | 内容 |
|---|---|
| 桌面 | 已停止、正在启动、运行中（窗口已关闭）、正在停止、启动失败、正在删除 |
| 网络 | 客体网关最近一次报告：网络离线、网关就绪、节点在线（经隧道的 HTTPS 探测成功，需在 `trust\probe.json` 配置探测目标）；租约失效时一律显示网络离线 |
| 租约 | 当前隧道租约的剩余时间，或"正在建立""已失效，正在重建" |

每个沙盒在客户端里有自己的工作线程（`sandbox_engine`）：独立的节点会话与隧道，每 10 秒续租并把客体的内核许可续到新的截止时间。续租失败就用更高代次新建隧道，连续失败则重新换取节点会话。与 WSL 代理的控制通道可并发，一个沙盒启动桌面时不影响其他沙盒续租。事件记录在同目录的 `client.log`（不含凭据）。

## 开发工具

- `orangespace-wsl`：导入、启动、查询、关闭发行版。
- `orangespace-sandbox <session.json> [--password-stdin] [--seconds N]`：按会话文件登录并运行一组沙盒，用与窗口相同的 `sandbox_engine`，供验收脚本使用。
- `OrangeSpace.exe --username <账号> --password-stdin`：仅供验收，从重定向的标准输入读取密码登录，测试不需要显示或键入密码。

## 构建与测试

需要 Windows 11 x64、Visual Studio 2022（C++ 桌面开发）、Windows SDK、CMake 3.24+。在仓库根目录：

```powershell
cmake -S . -B build/windows -A x64
cmake --build build/windows --config Release --target OrangeSpace orangespace-sandbox orangespace-wsl
ctest --test-dir build/windows -C Release -R "sandbox-model|wsl-channel" --output-on-failure
```

`sandbox-model` 测试本机沙盒列表的解析与校验和状态文字；`wsl-channel` 测试代理帧协议。窗口、续租与出口要在 Windows 实机配合真实节点验收，见 [docs/roadmap.md](../../docs/roadmap.md)。
