# Windows 安装包

安装包用 Inno Setup 6.7 构建，脚本是 `orangespace.iss`，由 `scripts/build-release.ps1` 调用。随附第三方软件与源码获取方式写在 `SOURCES.md`，安装后位于安装目录的 `licenses` 文件夹。

## 构建

需要三份输入，都在构建机上准备，不进仓库：

1. **发行版根文件系统**：在任意 Debian 13 / WSL 环境里以 root 运行

   ```sh
   ORANGESPACE_REVISION=0.1.0+<提交> linux-desktop/wsl/build-rootfs orangespace-rootfs.tar.gz
   ```

   同时生成 `.sha256` 和 `.packages.tsv`。`ORANGESPACE_REVISION` 写进 `/opt/orangespace/REVISION`，客户端按它判断是否升级，每次发布必须不同。
2. **桌面镜像**：在装有 podman 的 Linux（可以是开发用的 OrangeSpace 发行版）里运行

   ```sh
   linux-desktop/guest/build-image --archive desktop-image.tar
   ```

   生成 OCI 归档及 `.sha256`、`.packages.tsv`、`.base-image.txt`。
3. **信任文件夹**：本部署的 `platform.json`、`catalog.json` 和节点 CA 证书（`*.crt`/`*.pem`），即中心地址与节点钉扎。

然后在 Windows 构建机上：

```powershell
scripts\build-release.ps1 -Rootfs <根文件系统> -Image <镜像归档> -Trust <信任文件夹>
```

它先构建并测试客户端（`-SkipBuild` 跳过，使用已有 Release 构建），校验两份归档的摘要，从根文件系统读出版本号，整理出 `build\release\payload`，汇总 Rust 库许可，最后输出 `build\release\OrangeSpace-Setup-<版本>.exe` 及其 `.sha256`。客户端静态链接 C/C++ 运行库，不需要另装 VC++ 运行库。

## 安装包做什么

- **检查**：Windows 10 22H2（19045）及以上的 x64；硬件虚拟化没有开启时拒绝安装并说明原因。
- **启用 WSL**：`wsl --version` 不可用时，在复制文件前运行 `wsl --install --no-distribution`（联网下载，几分钟）。完成页要求重启，默认“现在重新启动”，重启后再打开橙域。
- **安装文件**：只装到 `Program Files\OrangeSpace`，不提供其他位置。安装目录归 Administrators，普通用户只读；`trust` 有自己的、不继承的 ACL。客户端拒绝普通用户能改动的信任文件。
- **升级**：同一个 AppId 覆盖安装，整体替换 `system`、`trust`、`licenses`。客户端正在运行时安装程序会要求先关闭。

发行版不由安装程序创建。WSL 发行版属于单个 Windows 账号，所以每个账号第一次打开橙域时，客户端按 `system\release.json` 自己导入：

| 情况 | 客户端做法 |
| --- | --- |
| 没有 `OrangeSpace` 发行版 | 导入根文件系统，再载入桌面镜像 |
| 版本号与 `release.json` 相同 | 不动 |
| 版本号不同 | 升级 |
| 已导入但缺少桌面镜像（导入后中断） | 只载入镜像 |
| 有未完成的升级 | 先把保存的数据放回去 |

**升级过程**：

1. 停止发行版，把沙盒数据（`/var/lib/orangespace/desktop`）导出到 `%LOCALAPPDATA%\OrangeSpace\upgrade`，校验并记下摘要和沙盒数。
2. 注销旧发行版，导入新的，放回数据，载入新镜像。
3. 核对版本号、镜像和沙盒数后删除保存的数据。

任何一步中断，下次启动都从保存的数据继续，不会丢失沙盒。过程记录在 `%LOCALAPPDATA%\OrangeSpace\setup.log`。

没有 `system` 文件夹的开发构建不做这些事，沿用手工导入的发行版。

## 卸载

默认保留数据：发行版、沙盒和保存的登录信息都还在，重新安装后可以继续用。卸载时选“删除”，会对运行卸载程序的 Windows 账号执行 `OrangeSpace.exe --remove-all-data`：

- 注销该账号的 `OrangeSpace` 发行版；
- 删除 `%LOCALAPPDATA%\OrangeSpace` 和保存的凭据。

其他账号在各自登录界面用“删除本机全部数据…”。节点上的个人文件不受影响。WSL 本身不卸载。

## 尚未覆盖

- 安装包没有代码签名。
- 启用 WSL 并重启已在关闭 WSL 的虚拟机上验收；物理机和需要在固件里开启虚拟化的机器尚未测过。
- 未签名、约 1 GB 的安装包第一次运行要等约 1 分钟才出现界面，看起来是在做安全扫描。
- 没有自动更新，升级靠运行新版安装包。
