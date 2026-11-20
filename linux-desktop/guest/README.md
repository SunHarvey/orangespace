# Debian 桌面运行时

`desktop` 是客体代理通过受信控制通道调用的 root 命令。Docker daemon 仅使用本机 Unix socket。每个桌面采用独立的持久 HOME、显示目录、D-Bus 会话、IPC 和网络命名空间。浏览器由普通 UID 1000 运行，保留 Chromium 自身的命名空间与 seccomp 沙盒。AppArmor 策略允许 Chromium 创建子命名空间，并限制访问宿主管理设备。一个容器的内存上限为 2 GiB，独立共享内存上限为 256 MiB。

```text
desktop configure USER_UUID SANDBOX_UUID NODE_UUID  < node.json
desktop start     USER_UUID SANDBOX_UUID NODE_UUID
desktop status    USER_UUID SANDBOX_UUID
desktop stop      USER_UUID SANDBOX_UUID
```

命令输出一行 JSON。沙盒用户、节点标识必须用规范小写 UUID。首次启动或配置记录所有者，后续跨账号操作会被拒绝。配置须在桌面停止后执行，凭据输入上限 32 KiB，直接通过 stdin 交给网关。节点的连接参数和授权格式见网关文档。

启动前，显示桥在 `/run/orangespace/display/<sandbox_uuid>/` 准备 `X0` Unix 套接字及 `Xauthority`。仅将该目录只读挂到本桌面，目录须允许 UID 1000 遍历，Xauthority 须允许其读取。Container 使用 `DISPLAY=:0`。请禁用 X server 的 MIT-SHM 扩展以适应跨内核的本地绘制。生产镜像由上级的 qcow2 工具构建。开发时在独立 Debian 13 系统安装 Docker Engine、docker-cli、AppArmor、Python 3 和 curl，将项目目录保存为 root 所有的 `/opt/orangespace` 后运行 `sudo /opt/orangespace/guest/build-image`。

每个容器先在仅有回环网卡的环境等待，完成网关配置或确认断开后才启动图形应用。首次返回成功要求窗口管理器响应，此外必须观察到真实 Chromium 顶层窗口。同一沙盒的重复请求由文件锁串行处理。停止时先撤销网关，再给 Chromium 时间写回 Profile。响应中的 `network` 取值为 `offline`、`gateway-ready` 或 `online`。最后一种需要经本沙盒完成已配置的 HTTPS 探测。

## 验证

在开发机运行 `python3 -m unittest discover -s linux-desktop/guest`。实际图形联测需要安装镜像、网关和运行时的专用 Linux 客体，以及 Xvfb、x11-utils、x11-apps、xdotool、wmctrl、ImageMagick 7。测试为 A、B 生成独立显示凭据，创建真实桌面，核对 Chromium renderer PID namespace 和 seccomp 滤链、两个窗口、独立文件及重开后的持久数据。

```sh
sudo python3 /opt/orangespace/guest/smoke_x11.py /tmp/orangespace-offline
sudo python3 /opt/orangespace/guest/smoke_x11.py --nodes /tmp/orangespace-dual-node
```

双节点模式还需安装网关测试所需的 sing-box、nftables、iproute2、iptables、openssl 和 systemd。两浏览器访问同一测试网址时应分别显示节点 A、B。切断 A 后，B 须能重新访问原网页，宿主直连对照端点的请求数须维持不变。脚本把两个真实根窗口 PNG 和同一时段的 cgroup 样本写入输出目录。
