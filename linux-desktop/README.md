# OrangeSpace 本地 Linux 桌面

Windows 客户端登录后可以创建沙盒、绑定节点、并排打开桌面和停止某一个沙盒。每个桌面运行非 root Chromium、LXQt 和 PCManFM-Qt，拥有自己的浏览器配置和下载目录。基础系统使用一台 QEMU/WHPX Debian 13 虚拟机。这个分支使用本地注册账号和管理员配置的 TUIC 节点。

| 组件 | 入口 | 职责 |
|---|---|---|
| Windows 客户端 | [使用说明](windows/README.md) | 账号与沙盒列表、单台 QEMU、独立 XWin 顶层窗口、打开、唤回和停止 |
| 桌面与数据 | [桌面生命周期](guest/desktop)、[容器镜像](guest/Dockerfile) | 独立非特权容器、稳定主机名、私有 Xauthority、独立持久 HOME、Chromium 自身沙盒 |
| 网络 | [网关与节点配置](network/README.md) | 每沙盒一对虚拟接口、一个隔离网关和 TUIC 出口，可信网关与客体外层双重过滤，默认封锁 IPv6 |
| 本机显示与控制 | [宿主桥](bridge/host.py)、[客体服务](bridge/guest.py) | 本次开机密钥双向认证、帧长度与并发限制、每条图形流独立流控，慢连接不会占满其他桌面的队列 |

本机 Windows 账户、客体管理员和共享 Linux 内核属于信任边界。运行中一个节点断开，只有绑定它的工作区失去该出口。用户仍可以操作本地文件。关闭共用虚拟机会停止所有桌面。显示和键鼠通过本机 virtio-serial，节点只处理外网流量。客户端只把经沙盒内指定 HTTPS 目标验证的出口显示成「在线」。可选探测未配置时显示「网关就绪」。

## 准备 Windows 客体镜像

使用专用 x86_64 Linux 构建机，安装 Docker Engine、libguestfs-tools、qemu-utils、e2fsprogs、curl、tar 和 Python 3。以有权运行 Docker 与 libguestfs 的账户执行构建。使用经过 Debian 发布校验的 Debian 13 amd64 **genericcloud qcow2**，根分区为第一个分区。先根据 Windows 配置说明创建沙盒得到 UUID，再按网关说明准备 root 管理的节点 JSON。构建输出含节点凭据，请保存在私有目录。两条命令都要求输出文件名尚不存在。[Debian 官方云镜像](https://cloud.debian.org/images/cloud/trixie/) · [libguestfs 镜像定制](https://libguestfs.org/virt-customize.1.html)

```sh
linux-desktop/image/build-qcow2 /srv/images/debian-13-genericcloud-amd64.qcow2 /srv/private/orangespace-system.qcow2 /srv/private/nodes
linux-desktop/image/create-data /srv/private/orangespace-home.qcow2 24
```

系统盘包含桌面 OCI 镜像、Docker、固定版本 sing-box、桥接服务和 AppArmor 配置。首次启动将 OCI 包加载到 Docker。第二块稀疏盘存放沙盒用户数据，Windows 通过固定序列号附加，客体按序列挂载。挂载失败时服务会拒绝启动。更换系统盘或备份数据盘前正常退出客户端并确认虚拟机已关闭。升级时须保留两盘配套配置和用户的本地账号数据库。

也可以省略 build-qcow2 的第三个参数，构建一份无凭据系统盘供多个用户使用。在 Windows 里先注册或登录，创建沙盒并选择节点，选中已停止的沙盒后点击「导入节点配置」。管理器把所选 JSON 通过认证的本机通道交给客体，仅写入这个沙盒的数据盘目录。导入后可以直接打开桌面，新增沙盒无需重新构建镜像。[Windows 安装与启动](windows/README.md) · [节点 JSON 字段](network/README.md)

开发版尚未接入产品中心的身份、动态授权/租约与节点个人文件 API。PCManFM-Qt 和下载使用该沙盒自己的持久目录。

## 验证

在仓库根目录运行可移植测试。桥接测试会在临时目录创建真实 Unix 套接字。

```sh
python3 -m unittest discover -s linux-desktop/bridge -v
python3 -m unittest discover -s linux-desktop/guest -v
python3 -m unittest discover -s linux-desktop/windows -v
```

在具备 root、systemd 和真实 Docker 的专用 Debian 客体中，可运行下列集成测试。按照 [网络测试依赖](network/README.md) 安装网络工具、sing-box 和 openssl；图形测试需要 Xvfb、socat、x11-utils、x11-apps、xdotool 和 ImageMagick。安装源码到 /opt/orangespace，构建桌面镜像，用与上文相同的 seccomp/AppArmor 策略启动。每次测试会创建独立 UUID 的沙盒和临时测试节点。

```sh
sudo python3 /opt/orangespace/network/smoke.py
sudo python3 /opt/orangespace/bridge/smoke_desktops.py
sudo python3 /opt/orangespace/guest/smoke_x11.py /tmp/orangespace-screenshots
sudo python3 /opt/orangespace/guest/smoke_x11.py /tmp/orangespace-node-screenshots --nodes
```

本轮实测使用 Debian 13 ARM64、4 个 vCPU 和 6 GiB 配置内存。网关测试的两套 TUIC 服务、DNS 应答和直连对照服务位于同一测试机的不同网络环境。图形桥测试让两个真实 LXQt/Chromium/PCManFM-Qt 桌面经两端桥接代码连向两个 Xvfb，实现了双向图形收发以及停止 A 后 B 可用。在这个测试中，宿主与客体两端以本地双向流代替 Windows QEMU 命名管道。Windows 11 x64 的 WHPX、XWin 窗口与输入体验、睡眠唤醒首包，以及两个真实公网节点的抓包仍须独立验收。x86_64 系统盘构建脚本尚待完整构建和启动验证。
