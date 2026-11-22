# OrangeSpace Windows 客户端

`OrangeSpace.exe` 是用户使用的窗口：登录中心、管理本机沙盒列表、打开沙盒桌面并显示每个沙盒的状态。每个沙盒是 WSL2 发行版 `OrangeSpace` 里的一个 Linux 桌面，以自己的窗口显示，全部流量只经绑定节点出网（见 [docs/architecture.md](../../docs/architecture.md)）。

## 安装与首次运行

正式安装由安装包完成（见 [deploy/windows](../../deploy/windows/README.md)）：程序装在 `Program Files\OrangeSpace`，旁边是 `trust`（中心与节点钉扎）和 `system`（发行版根文件系统、桌面镜像和 `release.json`）。WSL 发行版属于单个 Windows 账号，所以每个账号第一次打开时，客户端在登录界面之前按 `release.json` 准备自己的发行版（`system_setup`）：

- 没有发行版就导入并载入桌面镜像；
- 版本号不同就升级：先把沙盒数据导出到 `%LOCALAPPDATA%\OrangeSpace\upgrade` 并记下摘要，再替换发行版、放回数据、核对后删除；
- 升级中断后，下次启动从保存的数据继续。

过程写在 `%LOCALAPPDATA%\OrangeSpace\setup.log`。没有 `system` 文件夹的开发构建跳过这一步。客户端单实例运行，再次启动只会把已有窗口带到前面。

## 窗口

- **登录**：用管理员保护的 `trust\platform.json`（中心）登录，节点证书固定在 `trust\catalog.json`。两份文件放在程序旁的 `trust` 目录（或用 `--trust <目录>` 指定），普通用户可写的文件会被拒绝。没有本机直连回退。
- **记住登录**（默认勾选）：把中心会话的刷新凭据用当前 Windows 用户的 DPAPI 保存在 `%LOCALAPPDATA%\OrangeSpace-Platform-Credentials-v1`（不保存密码和访问凭据），每次刷新后换成新的。下次打开橙域时自动用它登录；关闭窗口保留，**退出登录**撤销中心会话并删除它。保存的登录被中心拒绝（退出登录、改密码、停用账号、超过 14 天未用或 30 天硬截止）时删除并回到登录界面；中心暂时连不上时保留，下次再试，也可以直接输入密码登录。用密码登录会替换之前保存的登录。
- **沙盒列表**：每个中心用户一份，存于 `%LOCALAPPDATA%\OrangeSpace\users\<中心用户 UUID>\sandboxes.json`，只记沙盒的名称和绑定节点。桌面本身（HOME、浏览器资料、下载）在发行版里。
- **新建沙盒**：起名并选择中心授权的节点；新建后立即打开。
- **打开**：为沙盒换取它自己的节点会话、创建隧道租约，把租约交给客体，启动桌面；桌面已在运行时只把关掉的窗口重新打开。
- **停止**：撤销隧道并停止桌面。
- **改用此节点**：仅在沙盒停止时可用；桌面数据保留，下次打开时经新节点联网。
- **文件…**：打开该沙盒的文件窗口。左边是绑定节点上的个人文件（双击进入文件夹，“上一级”返回），右边是沙盒的“下载”文件夹。
  - “放入下载 →”把节点文件复制进沙盒；已有同名文件时取“名称 (1).ext”。
  - “← 存到节点”把沙盒文件复制到当前节点文件夹；节点上已有同名文件时拒绝，不覆盖。
  - 复制经当前 Windows 用户的私有中转目录 `users\<中心用户 UUID>\transfer`，完成或失败后即删除；可以取消。沙盒一侧以该沙盒自己的 UID 读写，需要沙盒至少打开过一次（不必正在运行）。
  - 节点要授予该账号文件读写权限，按钮才可用。删除沙盒、退出登录或关闭主窗口时，先取消进行中的复制并关闭文件窗口。
- **删除**：确认后删除该沙盒在本机的桌面数据；节点上的个人文件不受影响。
- **删除本机全部数据…**（登录界面）：注销当前 Windows 账号的发行版，删除 `%LOCALAPPDATA%` 下的客户端文件夹和保存的登录信息，然后关闭；节点上的个人文件不受影响。卸载时选择删除数据，执行的是同一操作（`OrangeSpace.exe --remove-all-data`）。
- **退出登录 / 关闭窗口**：先停止所有沙盒，再退出（是否保留保存的登录见上面“记住登录”）。客户端被强行结束时，代理随控制通道关闭停掉所有桌面，内核许可在租约剩余寿命内自行过期。

状态列只显示观察到的情况：

| 列 | 内容 |
|---|---|
| 桌面 | 已停止、正在启动、运行中（窗口已关闭）、正在停止、出错停止（启动失败或桌面意外停止，提示列写明原因）、正在删除 |
| 网络 | 客体网关最近一次报告：网络离线、网关就绪、节点在线（经隧道的 HTTPS 探测成功，需在 `trust\probe.json` 配置探测目标）；租约失效时一律显示网络离线 |
| 租约 | 当前隧道租约的剩余时间，或"正在建立""已失效，正在重建" |

每个沙盒在客户端里有自己的工作线程（`sandbox_engine`）：独立的节点会话与隧道，每 10 秒续租并把客体的内核许可续到新的截止时间。续租失败就用更高代次新建隧道，连续失败则重新换取节点会话。租约有效、桌面在运行而网关连续 3 次（约 30 秒）报告网络离线时（例如网关没能启动、隧道进程退出），同样换新隧道，客体随新租约重建网关；换了仍不通就把等待加倍，最多约 5 分钟一次。与 WSL 代理的控制通道可并发，一个沙盒启动桌面时不影响其他沙盒续租。

中心会话可续期：登录时取得一次性的刷新凭据，后台线程在访问凭据过半时换新（失败每 20 秒重试，中心拒绝即停止）。后台线程每 15 秒对一次时钟，所以电脑睡眠醒来后很快换新。中心以 401 拒绝一个本机认为还有效的访问凭据时（本机时钟慢），客户端立即刷新并重试，之后按中心的时钟安排刷新。登录超过访问凭据寿命（1 小时）后，沙盒、节点会话和文件传送照常工作，直到会话硬截止（默认 30 天）或退出登录。各沙盒的工作线程和“文件”窗口共用这一个中心会话，不复制凭据。事件记录在同目录的 `client.log`，每行带本地时间，不含凭据。

## 开发工具

- `orangespace-wsl`：导入、启动、查询、关闭发行版。
- `orangespace-sandbox <session.json> [--password-stdin] [--seconds N]`：按会话文件登录并运行一组沙盒，用与窗口相同的 `sandbox_engine`，供验收脚本使用。
- `OrangeSpace.exe --username <账号> --password-stdin`：仅供验收，从重定向的标准输入读取密码登录，测试不需要显示或键入密码。

## 构建与测试

需要 Windows 11 x64、Visual Studio 2022（C++ 桌面开发）、Windows SDK、Rust（最低 1.89）、CMake 3.24+。应用私有 HTTPS 来自 Rust 静态库 `orangespace-https`，配置时用 `ORANGESPACE_HTTPS_LIBRARY` 指定。在仓库根目录：

```powershell
./scripts/build-windows.ps1
```

它依次执行：

```powershell
cargo build --locked --release -p orangespace-https
cmake -S . -B build/windows -A x64 "-DORANGESPACE_HTTPS_LIBRARY=$PWD/target/release/orangespace_https.lib"
cmake --build build/windows --config Release
ctest --test-dir build/windows -C Release --output-on-failure
```

C/C++ 运行库静态链接（CMake `CMAKE_MSVC_RUNTIME_LIBRARY`，Rust 由 `.cargo/config.toml` 的 `+crt-static`），程序不依赖 VC++ 运行库。安装包由 `scripts/build-release.ps1` 构建。

`sandbox-model` 测试本机沙盒列表的解析与校验和状态文字；`system-setup` 测试 `release.json` 与发行版信息的解析以及安装/升级/续做的判断；`wsl-channel` 测试代理帧协议。窗口、续租与出口要在 Windows 实机配合真实节点验收，见 [docs/roadmap.md](../../docs/roadmap.md)。
