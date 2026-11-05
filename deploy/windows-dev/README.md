# Windows 开发交付工具（不是 Native 整包验收）

仅支持项目固定程序：`OrangeSpace.exe`（Manager）、`OrangeSpaceLogin.exe`、`OrangeSpaceService.exe`、`orangespace-broker.exe`、`sing-box.exe`。真实 SCM 名称为 `OrangeSpaceFoundation`，固定 LocalSystem / Own Process / Manual，ImagePath 为带引号的精确 Service EXE 路径，无参数。

## 边界

本轮交付脚本与可运行打包策略，不复制正在漂移的 PE，不改变源码/CMake/Cargo，不签名、不提交、不修改 CI/许可。父任务冻结源码和配置后才运行构建/最终装包。Windows Service/ACL、交互 Manager、真实 HTTPS 登录、broker SQLite、helper 链仍须实机验收。浏览器/CEF、WFP、DNS、文件桥未验始终关闭；没有自动浏览器、guardian、通用回滚或同名进程终止。

## 构建与打包

需要 Windows x64、适用 VS C++ 工具链/SDK、CMake、Rust MSVC 工具链、Python 3。先审查工具目录并置于管理员保护位置。PowerShell 执行策略只允许当前进程：

```powershell
if ((Get-ExecutionPolicy) -in @('AllSigned','Restricted')) { throw '保留严格策略，不自动降级；按现有签名/授权流程执行' }
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\Build.ps1 -BuildRoot C:\Build\OrangeSpace-fresh-run -Helper C:\Reviewed\sing-box.exe -Output C:\Reviewed\OrangeSpace-package-fresh
```

`Build.ps1` 重用已读 `scripts/build-windows.ps1` 的 cargo → runtime archive → 根 CMake 构建顺序，但使用全新输出目录，只构建三项 C++ 程序并打包五个程序；不调用旧脚本中既有 artifacts 的覆盖复制逻辑。构建不等于测试；构建脚本不伪称 CTest 或 Native 验收。命令需在父冻结后单任务执行；GNU 交叉构建若另行运行，必须使用父任务共享 flock `/var/tmp/hermes-runtime/tmp/orangespace-build.lock` 和该目录 TMPDIR，本轮未交叉构建。

已有冻结产物可放在一个**只含这五个普通文件**的新源目录，用平台无关工具装包：

```text
python3 package.py create EXACT_PROGRAMS NEW_PACKAGE
python3 package.py verify NEW_PACKAGE
python3 -m unittest discover -s tests -v
```

manifest.json 记录每个程序完整字节大小/SHA-256；固定 helper 必须为官方 Windows 1.14.4 EXE 的 `8f30682ee198855440d2a7fe070d5d3653793b2d01bb8c85eea88f93bbe7c8b9`。拒绝缺项、重复、路径穿越、链接、额外文件/目录、credentials、Profile、DB、keys、logs；不扫描/递归复制用户目录。Python 用 lstat 拒绝包根及全部祖先的非目录/reparse，检测唯一硬链接；Windows junction 属性仅有本轮注入模型证据。PowerShell 强制校验包根、manifest、五程序及全部祖先的 ACL/reparse；冻结源 manifest 与哈希，复制后按同一快照核对，不重新信任目标 manifest。仍需管理员审核包来源，不能把 manifest 自签哈希当供应链签名。manifest 不证明编译源码来源；父需另存源冻结、工具链、Runtime archive 和程序哈希证据。

## 外部受保护配置协议

`-ProtectedConfig` 指向管理员预先准备的目录，**恰含** `platform.json`、`nodes.json`、`service-state.json`。脚本不生成真实端点/UUID/密钥或凭据。文件为实际产品 DTO，不能用任意示例替代：

- platform.json：供中心 PlatformConfig 真实保护加载器读取；UI 中手选安装目录内该绝对路径。
- nodes.json：中心返回节点到静态节点目录的准确映射，仍由产品严格验证；缺失/不符拒绝，不回退旧登录。
- service-state.json：管理员审核的真实持久代次账本。必须已有且有效，不自动造空账本/重置代次。Service 会更新，因此不把运行后 state 哈希固定为初值。
- 私有 CA 如配置引用外部受保护文件，必须由管理员另行按产品读取规则部署；本工具不复制私钥、不安装信任根、不忽略 TLS。

目录/文件要求 SYSTEM 或 Administrators owner、protected DACL；无非特权写入；state 与输入目录仅允许 SYSTEM/Administrators。父目录不允许 reparse 或非特权修改（盘根仅允许创建不相关兄弟项）。脚本只检查 JSON 语法；映射/中心 HTTPS/节点身份等语义由现有 Service/UI 严格拒绝，不能把安装成功当认证成功。包内绝不放这些外部 config 或用户 SQLite/Profile。

## 安装与精确操作

本地管理员控制台（仅经授权执行，**本轮未在远程运行 SCM**）：

```powershell
if ((Get-ExecutionPolicy) -in @('AllSigned','Restricted')) { throw '保留严格策略，不自动降级；按现有签名/授权流程执行' }
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\Service.ps1 install -Leaf OrangeSpace-Dev-frozen1 -Package C:\Reviewed\OrangeSpace-package-fresh -ProtectedConfig C:\Reviewed\ProtectedConfig
.\Service.ps1 status -Leaf OrangeSpace-Dev-frozen1
.\Service.ps1 start -Leaf OrangeSpace-Dev-frozen1
.\Service.ps1 stop -Leaf OrangeSpace-Dev-frozen1
.\Service.ps1 uninstall -Leaf OrangeSpace-Dev-frozen1
```

目标只能是 OS ProgramFiles 的直接新子目录 `OrangeSpace-Dev-<固定本轮标识>`，拒绝目标已存在、固定 Service 已存在，不接管任何既有安装。先建立管理员保护 ACL，再复制精确包/外部配置；读回字节哈希与 ACL。marker 绑定 root / service / 精确 ImagePath / manifest hash / platform 与 nodes hash。每项 SCM 操作前检查 marker、二进制大小/hash、配置、LocalSystem、Own Process、Manual、精确 ImagePath；操作后重新从 SCM 读取状态，超时失败，不 kill、不批量操作、不自动恢复。

安装后保持 Stopped；start 要求 Stopped，stop 要求 Running，uninstall 要求先显式停止。卸载只移除这个精确 SCM 项并读回缺席，**保留保护目录与账本**供人工检查，不删用户数据、不调用广泛 cleanup。任一失败保留精确目录；不得反复 install 接管它。

## 启动

Service 已由管理员显式启动后，在目标用户的**非管理员交互控制台**执行：

```powershell
if ((Get-ExecutionPolicy) -in @('AllSigned','Restricted')) { throw '保留严格策略，不自动降级；按现有签名/授权流程执行' }
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\Start.ps1 -Leaf OrangeSpace-Dev-frozen1
```

入口验证公共 marker、清单、配置及实际 SCM Running 身份，仅启动精确 `OrangeSpace.exe`，不传密码、token、UUID、端点或配置正文。UI 选择安装目录内 platform.json；缺配置、缺映射、Service 不符应明确失败。返回 ProcessCreatedOnly 仅证明进程创建后短时未退出，不是窗口操作/登录/网络隔离验收。Login/helper/Broker 不独立自动运行；由已有产品链按其真实协议调用，本地 SQLite 仍由 Broker 管理。

## 本轮证据

见 `evidence.json`。本地 Python 10 项测试涵盖等条数 duplicate/traversal、hardlink、extraDir、根/祖先 reparse 属性注入。三个 PowerShell harness 在 Linux PowerShell 7.4.6 执行真实生产 caller/policy，注入 OS ACL/文件元数据/SCM 边界，仅为策略证据，不是 Windows ACL/SCM 原生行为；MZ fixture 不是可用 EXE。本次脚本完成本地 parser 语法检查；历史 Windows RAM parser 仅对应旧哈希，不能证明本次源码。未执行 Windows 安装、SCM、账号、RDP、Trust 或真实凭据操作。最终包/Windows native build、ACL/SCM 生命周期、有限用户启动及 UI 流程仍待父任务实机验收。
# 干净源码离线打包补充

统一开发包入口和 manifest v2 见 `deploy/packages/README.md`。`Build.ps1` 新增可选 `-Offline`，仅对 Cargo 添加 `--offline`；Cargo/CMake 显式单任务，不改变安装/服务/授权协议。Linux flock 由 WSL coordinator 在整个原生构建和归档读回期间持有；原生 Windows/MSVC 和 WSL UNC 路径组合本次未执行。不得把这些定点包装改动当作新 native build/SCM 验收。
