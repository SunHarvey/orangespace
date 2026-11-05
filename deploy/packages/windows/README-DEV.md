# OrangeSpace Windows 管理开发包（干净源码构建）

**Windows x86-64 管理开发包，未签名，不是完整浏览器或正式发行版。** 包含 Manager、Login、LocalSystem Service、Rust Broker、固定 sing-box，以及既有安装/启停/卸载脚本；使用预编译包不需要自行编译。

## 来源和验证边界

- `BUILD-MANIFEST.json` 记录这份包的准确 `source_commit`、干净源码标记、依赖和实际编译器版本；`SHA256SUMS` 与 `payload/manifest.json` 记录文件哈希。
- 默认使用 Linux→Windows GNU 的静态构建路线。构建、归档成员读回、实机启动、GUI 操作和多租约链路是不同证据；以绑定本包提交及程序哈希的独立交付报告为准。
- 不包含或自动继承旧包的 `ACCEPTANCE.json`。旧 dev1 的实机安装和短时隧道正控不能证明本包已经完成 GUI、DPAPI、SQLite 重开或续租验收。
- 浏览器保持关闭；WFP/DNS、完整 CEF 浏览器及文件桥属于后续里程碑，不提供直连回退。
- 两个现有开发 Node 同机并共享物理出口。用户 RDS、容量、原生 MSVC 和正式签名发行分别验收，不能从交叉编译推导。

## 包内容

- `payload/`：五个 EXE 与 size/SHA-256 manifest。
- `tools/`：既有 `Service.ps1`、`Common.ps1`、`Start.ps1` 及源码构建脚本副本。
- `examples/`：保留地址/UUID 的非秘密示例，不是真实运行配置。
- `third-party/`：固定 helper 上游记录、许可证和对应源码归档；未替 OrangeSpace 新增项目许可证。

## 安装前准备

需要 Windows x64 管理员。先核对交付 ZIP 的 SHA-256，再解压到**全新、管理员独占写入的 Program Files 子目录**。不能从 Downloads/桌面等普通用户可写目录直接安装。

```powershell
# STAGE 为本次全新 Program Files 解压后的包目录。
$STAGE = 'C:\Program Files\OrangeSpace-Package-management'
. "$STAGE\tools\Common.ps1"
Set-Protected $STAGE $true
Set-Protected "$STAGE\payload" $true
Set-Protected "$STAGE\payload\manifest.json"
foreach ($name in $script:Names) { Set-Protected (Join-Path "$STAGE\payload" $name) }
```

另外准备包外管理员保护目录，恰含 `platform.json`、`nodes.json`、`service-state.json`。真实中心/节点配置和应用私有 CA 由环境管理员提供；正常验证 TLS，不修改系统信任或关闭证书验证。

`service-state.json` 必须仅允许 SYSTEM/Administrators，不能添加普通用户读取 ACE。只有真正全新实例才能使用空账本示例；升级保留原账本、UUID 和世代，不用示例覆盖旧数据。用户/节点身份必须显式映射，不按用户名合并。

## 实际操作

仅按已批准方式在当前 PowerShell 进程使用 RemoteSigned；不使用 Bypass/Unrestricted，不修改机器/用户级策略，不降级强制签名策略。

服务名和管道由编译身份及经过校验的 `payload/manifest.json` 确定，普通用户不能指定任意 SCM 名称。默认构建仍使用 `OrangeSpaceFoundation`；带 `--development-install-id ui-v2-p1` 的构建使用独立的 `OrangeSpaceFoundation.Dev.ui-v2-p1`，其他开发 ID 同理。

**仅要求本包选定的服务名和本次 Leaf/安装目录此前不存在。自定义开发实例可以与原 Foundation 并存，不停止、覆盖或切换原服务。若本包选定的服务已存在，install 必须拒绝；升级该实例须另行安排，只管理其准确自有资源。**

自定义开发 ID 同时隔离本机状态，空 ID 保持默认版原路径不变：

- Broker/SQLite/Profile：`%LOCALAPPDATA%\OrangeSpace.Dev.<id>`。
- Node 凭据：`%LOCALAPPDATA%\OrangeSpace-Credentials-v1.Dev.<id>`。
- 中心凭据：`%LOCALAPPDATA%\OrangeSpace-Platform-Credentials-v1.Dev.<id>`。
- 默认沙盒设置：`HKCU\Software\OrangeSpace.Dev.<id>\DefaultSandboxes`。

不读取、复制或迁移默认版的本机记录、Profile、保存凭据或默认设置；因此新开发实例首次打开不会自动显示默认版的本机沙盒。新实例内关闭/重开仍复用其自身原 UUID/Profile。安装目录、受保护配置和服务账本也必须分别使用本次自有目录；不同服务不能同时接管旧远端 binding/generation。Linux 个人文件区仍按真实账号和节点归属共享/隔离，不因本机开发 ID 自动复制或清空。

```powershell
# 管理员；Leaf 和安装目标必须此前不存在，配置路径为自己的保护目录。
& "$STAGE\tools\Service.ps1" install -Leaf OrangeSpace-Dev-management `
  -Package "$STAGE\payload" -ProtectedConfig 'C:\Program Files\OrangeSpace-PrivateConfig'
& "$STAGE\tools\Service.ps1" start -Leaf OrangeSpace-Dev-management
& "$STAGE\tools\Service.ps1" status -Leaf OrangeSpace-Dev-management
```

之后由目标用户在**非管理员、已连接并解锁的交互桌面**运行：

```powershell
& "$STAGE\tools\Start.ps1" -Leaf OrangeSpace-Dev-management
```

客户端按自身程序位置自动读取安装脚本预置的受保护 `platform.json` 和 `nodes.json`，不再要求用户输入路径或点击验证载入。缺少配置时仅显示配置帮助，不降低 HTTPS、身份或 ACL 校验。

v2 四页操作与验收（是否通过以本次交付收据为准）：

1. 启动后输入真实中心账号、密码；按需勾选“记住登录”。成功后自动显示获授权节点，不手工读取工作区。
2. 点击节点卡片“打开沙盒”，自动读取／创建或恢复该节点默认沙盒、绑定并请求 Service 建立独立隧道。重复点击不能重复创建。“＋”返回授权节点选择；节点旁“···”菜单可选择本实例已有沙盒（精确恢复原 UUID/Profile），或显式“新建独立沙盒”。
3. 打开两个沙盒标签，切换只改变当前内容。关闭保留本机数据；重新打开确认原归属。菜单删除需确认，且不删除 Linux 个人区。状态只依据真实响应；浏览器区域在门禁开放前显示明确提示，不启动直连浏览器。
4. 点击“文件”：进入目录、新建文件夹，选择或拖入已知内容文件上传；服务端提交成功才显示完成。选中远端文件下载到新的本机位置并核对内容；已有本机文件不静默覆盖。文件管理使用独立 HTTPS API，不是网页上传下载桥。
5. 查看并取消真实传输，切换标签后确认任务仍固定原用户／沙盒／节点／目录。检查同账号同节点共享个人区、不同节点隔离；不以两个同机节点宣称不同物理出口。
6. 注销后确认授权运行状态和记住登录凭据清除、数据仍保留，迟到响应不能恢复旧身份。重新启动检查勾选／未勾选记住登录的行为。

密码仅由用户在 GUI 输入，不放命令行、环境或日志。账号、真实保护配置和私钥不在包内。“本机许可”“近期转发验证”和建立时的历史证明分别展示；一次近期验证不是连续业务流证明。租约倒计时来自最近 DTO 快照，续租或响应延迟时可能过时，不能据此判断当前授权已失效，更不能用它授予工作权限；必须结合新的真实转发和续租观测验收。浏览器门禁不因这些展示状态开放。

```powershell
# 管理员；只管理本次准确自有安装，不按进程名结束其他程序。
& "$STAGE\tools\Service.ps1" stop -Leaf OrangeSpace-Dev-management
& "$STAGE\tools\Service.ps1" uninstall -Leaf OrangeSpace-Dev-management
```

卸载移除准确自有 SCM 项，保留安装目录和账本，不删除用户 SQLite/Profile 或 Linux 个人文件。失败或未知状态保留目录，不重新 install 覆盖、不猜 PID 清理。

## 从仓库重新构建

在完整、干净的已提交 checkout 按 `deploy/packages/README.md` 准备独立核验的离线依赖后执行：

```sh
export TMPDIR=/var/tmp/hermes-runtime/tmp
python3 deploy/packages/build.py windows --deps /absolute/reviewed-dependencies --output /absolute/output/windows-dev.zip
# 经批准的并行开发实例另用全新输出，开发 ID 固定在程序/manifest 中：
python3 deploy/packages/build.py windows --development-install-id ui-v2-p1 \
  --deps /absolute/reviewed-dependencies --output /absolute/output/windows-ui-v2-p1-dev.zip
```

入口自行持有项目构建锁，并使用 Cargo/CMake 单任务。默认 GNU 路线不要求 WSL/MSVC；可选原生路线单独核验。`tools/Build.ps1` 只是完整仓库构建入口的副本，不能仅凭预编译包重新编译。交叉编译、Service Running 或 IPC 存在均不替代实际 GUI、认证、转发和内核隔离验收。
