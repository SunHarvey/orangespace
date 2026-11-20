# Windows 开发客户端

目标环境为 Windows 11 x64，开启固件虚拟化和 Windows Hypervisor Platform。安装 Windows x64 Python 3.11 或更新版本（勾选 Tcl/Tk）、带 WHPX 的 QEMU 和 Cygwin x64（xorg-server、socat、cygwin 包）。登录与创建沙盒时只需配置安装路径、预期系统盘、数据盘路径与节点 ID。首次打开桌面前，按本分支客体说明准备可写 Debian qcow2 启动盘，以及按镜像构建说明初始化的独立 qcow2 数据盘。Windows 只附加磁盘；客体按序列号 OrangeSpaceData 挂载数据盘。虚拟机能处理 ACPI 电源键并正常关机。初次验证建议 16 GB RAM、SSD，留给这台虚拟机 6 GiB RAM 与 4 个 vCPU。[QEMU WHPX](https://www.qemu.org/docs/master/system/whpx.html) · [XWin 窗口和命令参数](https://x.cygwin.com/docs/man1/XWin.1.html)

1. 把 runtime.example.json 复制为自己的配置。填写 QEMU 可执行文件、Cygwin 的 bin 目录、image 系统盘及 data_image 用户数据盘的完整 Windows 路径。nodes 是客体管理员已配置的节点 UUID 与显示名称。配置支持 Windows 环境变量。系统盘可能包含预置节点密码，数据盘保存各沙盒文件；请将两块盘复制到仅当前用户与 SYSTEM 可读写的 NTFS 目录，核对两份文件自身的 ACL。Windows 配置 JSON 仅保存节点名称及 UUID。客户端预留 1 GiB 客体内存，每个桌面按客体的 2 GiB 上限准入；6 GiB 可同时开两个。
2. 在仓库根目录执行以下命令。

```powershell
py -3 linux-desktop/windows/manager.py --config C:\OrangeSpaceRuntime\runtime.json
```

3. 首次使用选择「注册本地账号」，设置至少 12 个字符的密码。以后选择「登录」。新建沙盒时指定节点，这一步只保存本地记录。选择「沙盒 ID」可查看和复制账号、沙盒、节点 UUID；把沙盒凭据配置到客体后，双击打开或唤回窗口。首次镜像导入时客户端最多等待 5 分钟。再建一个沙盒即可并排操作。停止沙盒后才能更换节点。「网关就绪」表示客体网关已配置；如配置了 HTTPS 主动探测，则界面按探测结果显示「节点在线」或「网络离线」。
4. 注销或关闭管理器时，等待桌面停止、客体关机。若 ACPI 关机超时，检查客体电源按键处理后重试。结束管理器进程会触发 Windows Job 回收子进程，属于异常断电。已运行虚拟机在最后一个桌面停止后保持待机，注销或关闭客户端会释放它。

在列表选中已停止的沙盒，点击「导入节点配置」可以直接选择节点 JSON。配置中的 node_id 应等于当前选中的节点 ID。管理器启动共用虚拟机，只把该沙盒的配置存进客体私有数据盘。一个无凭据的系统镜像可以重复用于陆续创建的沙盒。[导入格式](../network/README.md)

开发版在当前 Windows 登录账户的 LocalAppData 下保存 SQLite 账号和沙盒绑定、诊断日志以及运行时私有文件。账号密码通过每用户独立盐和 scrypt 校验。本地账号负责管理器内的工作区归属，同一 Windows 用户和本机管理员属于受信主体。产品中心登录、中心节点授权和短期续租另行接入。QEMU 运行时持有磁盘的独占写锁，请勿将同一客体盘交给另一个运行实例。

每个活动沙盒使用单窗口 XWin、新的 Xauthority cookie 以及 Cygwin 私有 Unix Socket 连接。启动时验证正确 cookie 被接受、随机 cookie 被拒绝；禁用 X11 TCP、宿主剪贴板和跨内核的 MIT-SHM 扩展。管理命令通过有端点验证与双向认证的 virtio 通道交给客体。Windows GUI 和真实节点联调仍需实机。

执行可移植单测：

```powershell
py -3 -m unittest discover -s linux-desktop/windows -p test_manager.py -v
```
