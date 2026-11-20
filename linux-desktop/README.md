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

在具备 root、systemd 和真实 Docker 的专用 Debian 客体中，可运行下列集成测试。按照 [网络测试依赖](network/README.md) 安装网络工具、sing-box 和 openssl。图形测试需要 Xvfb、socat、x11-utils、x11-apps、xdotool 和 ImageMagick。发布盘只含列入清单的客体运行文件。运行这些测试时，将完整 linux-desktop 源码复制到测试客体的 /opt/orangespace，构建桌面镜像，用与上文相同的 seccomp/AppArmor 策略启动。每次测试会创建独立 UUID 的沙盒和临时测试节点。

```sh
sudo python3 /opt/orangespace/network/smoke.py
sudo python3 /opt/orangespace/bridge/smoke_desktops.py
sudo python3 /opt/orangespace/bridge/smoke_desktops.py --nodes
sudo python3 /opt/orangespace/guest/smoke_x11.py /tmp/orangespace-screenshots
sudo python3 /opt/orangespace/guest/smoke_x11.py /tmp/orangespace-node-screenshots --nodes
```

本轮双桌面实测使用 Debian 13 ARM64、4 个 vCPU 和 6 GiB 配置内存。网关测试的两套真实 TUIC 服务、DNS 应答和直连对照服务位于同一台测试机的不同网络环境。

| 场景 | 实测结果 |
|---|---|
| 同址访问与节点故障 | 两个真实 Chromium 分别显示 A、B 的页面。停止 A 节点后，A 的探测离线，B 重新打开页面成功。独立网络测试中 B 的 512 KiB 长连接下载哈希吻合，直连对照服务零增量 |
| 客户端导入与图形通道 | 两份凭据分别通过宿主桥导入。撤掉原始模板的授权后，两桌面仍通过自己的 HTTPS 探测。两个 LXQt/Chromium/PCManFM-Qt 桌面经桥连接独立 Xvfb，停止 A 后 B 窗口可操作。这项测试以本机双向流代替 Windows 命名管道 |
| 个人数据 | A 与 B 的文件隔离；A 关闭并重开后，文件和 Chromium 中创建的书签仍在 |
| 轻载内存 | 各开一个静态节点网页和一个文件管理器，最后一轮 A/B 的 cgroup.memory.current 约为 593/250 MiB，另一次为 245/244 MiB。此指标含可回收缓存，不含宿主图形进程、虚拟机和网关的共用开销。ARM64 桌面镜像约 1.33 GB |

另外在 x86-64 QEMU 软件模拟下，用两个临时写入层实际启动了 Debian 系统盘和数据盘，验证了数据盘挂载、身份认证、经 virtio-serial 打开 Chromium 和文件管理器、ACPI 正常关机。可从 Linux 源码目录用以下命令重跑。依赖 qemu-system-x86_64、qemu-img、Xvfb、socat 和 xprop。原始双盘在测试中只读。

```sh
python3 linux-desktop/image/smoke-boot.py /path/debian.qcow2 /path/desktop-data.qcow2 --desktop
```

Windows 11 x64 的 WHPX、XWin 窗口与输入体验、睡眠唤醒首包，以及两个真实公网节点的抓包仍须独立验收。
