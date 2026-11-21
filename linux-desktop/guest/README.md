# Debian 桌面运行时

`desktop` 是 OrangeSpace 发行版里的 root 命令，由客体代理（`../wsl/agent.py`）调用。每个沙盒有：

- 一个 Podman 容器 `osdesk-<sandbox>`：
  - 内跑 LXQt、Chromium、文件管理器和 fcitx5；
  - 按沙盒固定一段宿主 UID/GID，无网络，直到网关接入；
  - 只读根、无能力、无新权限、seccomp、资源限制；
  - 保留 Chromium 自身沙盒。
- 一个常驻的私有虚拟显示：Xvnc，systemd 单元 `osdisp-<sandbox>`。
  - 以本沙盒专用账户 `osdisp<slot>`（UID = GID = 190000 + slot）运行，不在任何容器的 UID 段内。
  - 无网络命名空间访问，只读系统，看不到 `/mnt`（WSLg 与 Windows 磁盘）。
  - 不开 TCP。
  - 两个 socket：
    - X socket 和 cookie 在 `/run/orangespace/display/<sandbox>/`，这是容器唯一挂载的显示目录（只读）；
    - 查看器 socket 在 `/run/orangespace/view/<sandbox>/rfb`（0700/0600，容器看不到）。
- 一个查看器窗口：vncviewer，systemd 单元 `osview-<sandbox>`，同一专用账户。
  - 作为 WSLg 客户端显示成一个 Windows 窗口。
  - 关窗只关查看器，桌面继续运行；再次 `start` 重新打开窗口。
  - WSLg 消失时（例如远程桌面断开导致合成器重启），查看器出错退出，每 3 秒重试，直到窗口恢复。
- 剪贴板在服务端和查看器两端都关闭，查看器的 F8 菜单也关闭，所以沙盒与 Windows、沙盒与沙盒之间都没有剪贴板通路。

```text
desktop lease     USER_UUID SANDBOX_UUID NODE_UUID  < lease.json
desktop renew     USER_UUID SANDBOX_UUID TUNNEL_UUID REMAINING_MS
desktop start     USER_UUID SANDBOX_UUID NODE_UUID TITLE
desktop status    USER_UUID SANDBOX_UUID
desktop stop      USER_UUID SANDBOX_UUID
desktop delete    USER_UUID SANDBOX_UUID
```

**命令与输入**

- 命令输出一行 JSON。
- 用户、沙盒、节点标识都必须是规范小写 UUID。
- 首次启动或交来租约时记录所有者，之后的跨账号操作一律拒绝。
- 节点租约（上限 32 KiB）经 stdin 直接交给网关。桌面运行中收到新租约时只重建网关，桌面不中断；租约必须属于桌面绑定的节点。
- `renew` 每次续租调用一次，只把当前隧道的内核许可续到新的剩余寿命（不超过 30 秒），不查询容器。

**启动顺序**

1. 显示；
2. 窗口；
3. 容器；
4. 网关：没有有效租约时保持离线；
5. 启动图形应用；
6. 等待窗口管理器和真实的 Chromium 顶层窗口。

**停止与输出字段**

- 停止的顺序是网关、容器（先让 Chromium 写回配置）、显示和窗口。
- 同一沙盒的操作由文件锁串行化。
- 输出字段：
  - `desktop` 取值 `running` 或 `stopped`；
  - `window` 取值 `open` 或 `closed`；
  - `network` 取值 `offline`、`gateway-ready` 或 `online`，`online` 要求租约里带 HTTPS 探测。

桌面镜像在发行版里用 `build-image` 构建（`podman build`）。

## 验证

在开发机运行 `python3 -m unittest discover -s linux-desktop/guest`。

真实验收在 Windows 上进行：用 `orangespace-wsl run` 打开沙盒，见 `docs/roadmap.md` 的 L2 和 L3 记录。
