# SG 单安装 Windows ZIP 入口

## 构建（仅本机文件，不连接 Windows 或生产服务）

```sh
python3 deploy/windows-client-sg/assemble.py \
  --cef-runtime /path/to/verified/Runtime \
  --service /path/to/fresh/OrangeSpaceSinglePrototype.exe \
  --gui /path/to/fresh/OrangeSpace.exe \
  --broker /path/to/fresh/orangespace-broker.exe \
  --config-dir /path/to/protected/build-inputs \
  --state-dir /path/to/preserved/same-namespace/State \
  --state-pins /path/to/independently-retained/state-pins.json \
  --output /path/to/fresh/OrangeSpace-SG-Installer
```

输出是解压目录及同名 `.zip`，根目录包含 `Install.cmd/ps1`、`Start.cmd/ps1`、`Uninstall.cmd/ps1`、`Common.ps1`、中文 `README.txt`、`Runtime/`，传入旧账本时还有 `State/`。完整 Runtime 必须已有 `client.exe/client.dll/libcef.dll/sing-box.exe` 和其他 CEF 资源；脚本不构造占位二进制。不硬编码文件数量，不从桌面启动 LocalSystem。`--runtime` 是 `--cef-runtime` 的同义项。已完整集成的 Runtime 可以省略三个二进制覆盖参数。

配置仅从构建输入提供，不提交真实 Centre/Node 值。`--config-dir` 内 `platform.json/nodes.json` 必须是当前构建用户拥有的 0600、单链接普通文件。平台配置必须恰为 `{schema,api_origin}` 且 HTTPS；脚本拒绝常见凭据/私钥字段。它不是通用秘密检测器：构建方仍须提供已经核验的无密公开 catalog，不能把 Profile、SQLite、登录 envelope 或运营配置混入 Runtime。

`--state-dir` 必须只有 `namespace.anchor/service-state.json` 两个同 namespace 原始文件，并与独立保留的 `--state-pins` JSON 完全匹配。格式为 `{"namespace.anchor":{"sha256":"<64 lowercase hex>","size":123},"service-state.json":{"sha256":"<64 lowercase hex>","size":456}}`。预期值必须来自原 WinDesk 两叶的可信副本/既存记录，不可由候选 State 自证。没有 State 默认拒绝；`--fresh-state` 仅使构建方明确表达全新实例意图，本轮 Install 仍拒绝无 initial_state 的包，禁止走空账本分支。

首次安装/采用已有 State 必须比对原 pair；安装器创建私有 `installer-state-binding.json`（固定 namespace 与原 pair 摘要的 ASCII receipt，非任意配置），后续重装用此 receipt 及不变的原 anchor 绑定 namespace，允许账本合法演进。无 receipt 时仍要求两叶完整匹配。只额外允许精确 `OS.SG.<48 lowercase hex>.profile` 普通、非 reparse、单链接、SY/BA-only protected marker；不删除、不重写，marker 内容与账本 ownership 仍由 native Service 严格解析，不能把文件名当授权。未知叶/权限错误拒绝，绝不 reset。卸载保留全部 State。

资源上限：每树 4096 文件、8192 entries、16 层、4 GiB 总未压缩字节；metadata/inventory 1 MiB、4096 rows；State 两叶各非空且 <=1 MiB。先统计再 hash，二进制覆盖、哈希和 ZIP 写入/读回采用流。路径规则拒绝 Profile/cache/Cookies、SQLite/db、credentials/private-key、log/dump 与本轮不需要的证书/密钥文件；不盲扫 CEF binary 内容。未来公开证书必须新增显式 role，不能混作普通 Runtime 文件。

## TRUST-1：提权前外部来源前提（有限开发安装，不是正式分发认证）

inventory 和 manifest 只证明一致性，不证明源码/脚本来源；本安装器没有签名 updater 或自认证机制。**不得从可写 Downloads/Desktop 解压树直接提权**。可信 operator 必须先通过独立渠道核验完整 ZIP SHA-256 与 scripts 来源，将完整 invocation tree（含 Common.ps1、所有 cmd/ps1、Runtime/State）复制到全新 BA/SY 控制、无 reparse 的路径，检查所有祖先/目录/叶的写权限并保持保护后才能执行。仅核过 ZIP 再在可写树提权不够。此次未增加 bootstrap，不能声称 Install.cmd 实现了该外部来源认证；父与 reviewer 必须确认这一有限 devscope 前提。

Cargo 如果提供多硬链接 broker，先在父的私有 fresh staging 以独占创建普通文件复制并核对 hash，再传入；脚本不降低外部输入的单链接规则。输出路径必须全新且不在输入 Runtime 内。文件名使用 Windows 安全部分集合；拒绝链接、设备路径、ADS、大小写碰撞和特殊文件。

## 安装行为和权限

- 唯一系统已知 Program Files 目录下 `OrangeSpace-SinglePrototype-SG-v25-20261104`；唯一 sibling `OrangeSpace-SinglePrototype-SG-v25-State`；唯一 SCM `OrangeSpaceSinglePrototype.SG.v25`。
- 安装器保留所有源 payload 文件与清单的只读共享句柄，完整枚举/校验；独占建立管理员受控 staging，逐叶独占复制后再次校验同一闭合清单，再 promote。清单本身不参与自己的 hash，其余每个文件均 `sha256lower<TAB>size<TAB>relpath<LF>`。
- 安装 root、每一子目录和公开叶（尤其 platform/nodes/helper）均显式 `DACL_PROTECTED`，owner BA，SY/BA Full，BU 与 ALL_APPLICATION_PACKAGES RX。所有公开叶都单独设 ACL，绝不依赖 SDK 不接受的 inherited leaf ACL。
- 私有 State 目录、anchor 与账本每叶均显式 SY/BA-only protected DACL。不给普通用户 read；不把可变账本放进 Runtime。
- `CreateServiceW` 固定 quoted image、WIN32_OWN_PROCESS、AUTO_START、LocalSystem、无密码；创建后核回 binary/type/start/account，设并逐 ACE 字节核回 service DACL。普通用户与 package 仅 QUERY_CONFIG/QUERY_STATUS，无启动/停止/修改权限。
- 公共桌面 `OrangeSpace.lnk` 指向实际 `OrangeSpace.exe`，不存在才建立并核回；已有同名 shortcut 不覆盖。普通用户从原 Install 调用在 UAC 子进程成功后启动 GUI；直接管理员安装不启动 GUI。`Start.cmd` 拒绝 elevated 调用，不手动启动 helper/Service。
- 日志仅固定标签；错误不打印 exception、配置或凭据。RemoteSigned 仅当前进程，不修改强制策略。

## 卸载边界

需管理员；先正常关闭 GUI。严格比对 Service 配置，保留 exact Service process handle，先核 PID/path/SCM 再 stop，30 秒限时等状态与 exact process exit；不按名字 kill。仍有此路径进程时保留安装文件；unknown shortcut 不删除。删除 SCM 后核回不存在；只删闭合 inventory 的 Runtime 叶与空目录，不递归任何未知目录。只删指向本安装的 owned link。保留原始 State、用户 AppData/SQLite/Profile/网站数据，完全不访问 Linux 文件或其他安装。

**已知接口边界**：源产品目前没有独立持久 WFP 清理 CLI。脚本只使用 Service 正常 stop 生命周期，不做全局 WFP/firewall/trust reset，不声称已清掉历史 path4 deny。需父与 Service actor 用既有产品支持核实正常 stop 的 owned cleanup；若无法移除，按同路径 strict-own recovery 处理，不换 namespace 绕过。

## 实际已做 / 父必须补做

```sh
python3 -m unittest discover -s deploy/windows-client-sg/tests -v
python3 deploy/windows-client-sg/assemble.py --help
```

Linux 测试操作真实临时文件树，覆盖缺失/多余/hash 改动、CRLF/重复/traversal/ADS/device/self 清单、symlink/hardlink/case collision，及 fresh 二进制覆盖、无密配置注入、原始 State、ZIP 根成员逐字节读回。fixture 明确不是 PE，不代表 Windows 安装或浏览。

Windows 非执行语法/C# 声明编译入口（父运行，不需要先执行安装器）：

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File deploy\windows-client-sg\tests\Parse.ps1
```

父仍须执行实际 Windows PowerShell 5.1 ParseFile + Add-Type、protected-leaf ACL/SCM ACE readback、真实完整 payload 安装、普通用户 GUI 登录/SG 内嵌浏览、正常 stop/helper-loss、卸载后精确残留与数据保留验证。Linux 未执行任何 SCM/WFP/GUI 调用，不借用旧候选证明新包通过。
