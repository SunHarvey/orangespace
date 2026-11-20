# OrangeSpace WSL 发行版（路线图 L1）

沙盒运行在本项目自己的 WSL2 发行版 `OrangeSpace` 里。架构约束见 [docs/architecture.md](../../docs/architecture.md)。

| 文件 | 作用 |
|---|---|
| `build-rootfs` | 用 mmdebstrap 构建 Debian 13 根文件系统，输出 `.tar.gz`、软件包清单（含源码包与版本）和 SHA-256 |
| `wsl.conf` | 发行版的 `/etc/wsl.conf`：开启 systemd；关闭 Windows 磁盘自动挂载与互操作；默认用户 `desk` |
| `agent.py` | 客体代理：由客户端以 `wsl.exe -d OrangeSpace -u root -- python3 /opt/orangespace/wsl/agent.py` 启动，经标准输入/输出收发帧 |
| `test_agent.py` | 以子进程方式运行代理、按真实管道收发帧的行为测试 |

Windows 侧对应 `apps/windows-client/include/orangespace/wsl_runtime.hpp`（导入、启动、请求、关闭）和 `wsl_channel.hpp`（帧编解码），开发与验收工具是 `orangespace-wsl.exe`。

## 构建根文件系统

在 Debian（或某个 Debian WSL 发行版）里以 root 运行，需要 mmdebstrap、curl、ca-certificates：

```sh
sudo linux-desktop/wsl/build-rootfs /srv/out/orangespace-rootfs.tar.gz
```

sing-box 不在 Debian 仓库中，脚本按固定版本下载官方发布包并校验 SHA-256。镜像里不含任何用户数据或凭据。

## 导入与验收（Windows，在用户自己的桌面会话里运行）

```powershell
orangespace-wsl status
orangespace-wsl import C:\path\orangespace-rootfs.tar.gz C:\Users\<用户>\AppData\Local\OrangeSpace\wsl
orangespace-wsl check 60
```

`check` 启动代理，打印发行版信息，并逐项核对：
- 没有挂载任何 Windows 磁盘；
- 互操作已关闭；
- systemd 在运行；
- WSLg 显示可用。

之后保持运行指定秒数，再正常关闭。WSLg 只连接最先启动 WSL 的会话，所以 `check` 必须在用户的交互会话里运行，不能从 SSH 会话运行。

## 测试

```sh
python3 -m unittest discover -s linux-desktop/wsl -v
```
