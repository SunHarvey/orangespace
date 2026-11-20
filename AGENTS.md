# OrangeSpace 开发约定

- 先读 `README.md`、`docs/architecture.md`、`docs/roadmap.md`，区分已实现能力与尚未完成部分。选型理由与实测依据见 `docs/proposal-wsl-linux-desktop.md`。`docs/archive/` 是旧路线（含原生 Windows CEF/WFP 方案）的历史记录，不作为现行约束。
- 每个沙盒是一个完整的 Linux 桌面，运行在 Windows 自带的 WSL2 中、本项目自己的发行版 `OrangeSpace` 里，以一个独立的 Windows 窗口显示（WSLg + 每沙盒私有 X 显示）。客户端用 C++20，路由核心和 broker 用 Rust，中心与 Linux 节点用 Python/FastAPI。不改为远程浏览器、云端桌面或由节点渲染画面；也不改回自带 QEMU/WHPX、Cygwin/X 的底座。
- 用户/沙盒/节点/连接代次必须显式绑定；不能引入全局 current_node，或跨沙盒共用容器、网关、会话、TUIC 凭据或显示。
- 联网路线是“每沙盒一个网关命名空间 + TUN + 本沙盒 TUIC 隧道”，沙盒的全部流量（TCP、UDP、DNS）只能经绑定节点出网。桌面容器只有一条到本沙盒网关的虚拟网卡；发行版根命名空间只放行该网关到该节点 IP/UDP 端口；IPv6、跨沙盒、宿主与内网地址一律阻断。出口许可是随节点租约续期的内核限时许可，客户端退出、续租失败或撤销时由内核自动过期，不依赖进程正常收尾。不开发 Windows 内核驱动，不提供本机直连回退。
- 沙盒容器以非 root 用户运行，保留 Chromium 自身沙盒，使用 seccomp、Landlock、无新权限与资源限制（WSL 默认内核未启用 AppArmor，不依赖它）。容器只拿到本沙盒自己的显示 socket 与 cookie，不得访问 WSLg 公共显示 `:0`、`/mnt` 下的 Windows 磁盘或其他沙盒的 HOME。发行版关闭 Windows 磁盘自动挂载与互操作。
- 剪贴板默认隔离：沙盒与 Windows、沙盒与沙盒之间都不互通；只允许以后由用户在客户端逐次触发的单向粘贴。
- 不加入 no-sandbox、allow-unsafe、关闭证书验证或绕过节点的回退路径。
- Linux 个人文件区按认证用户隔离，同用户同节点共享；删除本机沙盒不删除远端文件。文件任务在创建时固定 node_id。
- 不复制 IdenGrid 源码。不要将用户凭据、私钥、沙盒数据、发行版镜像、临时文件纳入仓库。
- 测试验证行为，不新增读取源码文本做字符串断言的测试。修改网关、出口许可或文件权限边界时运行相关测试；Linux 网关回归只能证明 Linux 内核侧，不能宣称 Windows 实机或真实节点验收已通过。
- 当前工程没有对外分发许可证，未经用户决定不要替项目添加开源许可。分发的根文件系统要附完整软件包清单与源码获取方式。
