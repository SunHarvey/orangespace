# OrangeSpace Linux 桌面（WSL2 发行版内的部分）

每个沙盒是 WSL2 发行版 `OrangeSpace` 里的一个完整 Linux 桌面，以独立的 Windows 窗口显示，全部流量经本沙盒的网关和 TUIC 租约隧道从绑定节点出网。整体架构与必须保持的约束见 [docs/architecture.md](../docs/architecture.md)，进度与验收记录见 [docs/roadmap.md](../docs/roadmap.md)。

| 目录 | 内容 |
|---|---|
| [wsl/](wsl/README.md) | 根文件系统构建（`build-rootfs`）、`wsl.conf`、客体代理 `agent.py` 及其帧协议 `wire.py` |
| [guest/](guest/README.md) | 桌面镜像、`desktop` 生命周期命令、私有虚拟显示与可重连查看器 |
| [network/](network/README.md) | 每沙盒网关（netns、TUN、sing-box）、租约与内核限时许可、真实内核回归 `smoke.py`、出口检查 `egress-check` |
| [node/](node/README.md) | 节点安装（`install-api`）与向中心登记（`enroll-node`） |

Windows 侧的对应部分在 `apps/windows-client`：`wsl_runtime`（导入、启动、请求、关闭）、`wsl_channel`（帧编解码），沙盒窗口 `OrangeSpace.exe` 与它的 `sandbox_engine`（中心登录、节点租约、续租），以及开发验收工具 `orangespace-wsl`（发行版）和 `orangespace-sandbox`。

## 测试

在仓库根目录运行可移植测试：

```sh
python3 -m unittest discover -s linux-desktop/wsl -v
python3 -m unittest discover -s linux-desktop/guest -v
```

网关的租约测试需要 Linux（CLOCK_BOOTTIME），存储权限部分需要 root；真实内核回归需要专用 Linux 客体，见 [network/README.md](network/README.md)。这些只证明 Linux 侧，Windows 实机和真实节点验收另见路线图。
