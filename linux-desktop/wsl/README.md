# OrangeSpace WSL 发行版（路线图 L1）

沙盒运行在本项目自己的 WSL2 发行版 `OrangeSpace` 里。架构约束见 [docs/architecture.md](../../docs/architecture.md)。

| 文件 | 作用 |
|---|---|
| `build-rootfs` | 用 mmdebstrap 构建 Debian 13 根文件系统，输出 `.tar.gz`、软件包清单（含源码包与版本）和 SHA-256 |
| `wsl.conf` | 发行版的 `/etc/wsl.conf`：开启 systemd；关闭 Windows 磁盘自动挂载与互操作；默认用户 `desk` |
| `agent.py` | 客体代理：由客户端以 `wsl.exe -d OrangeSpace -u root -- python3 /opt/orangespace/wsl/agent.py` 启动，经标准输入/输出收发帧 |
| `test_agent.py` | 以子进程方式运行代理、按真实管道收发帧的行为测试 |

Windows 侧对应 `apps/windows-client/include/orangespace/wsl_runtime.hpp`（导入、启动、请求、关闭）和 `wsl_channel.hpp`（帧编解码），开发与验收工具是 `orangespace-wsl.exe`。

## 代理协议（版本 2）

每帧是一个 JSON 对象，带 `op`；回复带 `error` 表示失败。请求可以并发，回复按请求编号对应。
- `desktop.*`：转给 `guest/desktop` 的同名命令（租约只经 stdin 交给它，不进命令行）。
- 文件传送（沙盒的“下载”文件夹）：`files.list`；上传 `files.push` → 多次 `files.write` → `files.finish`；下载 `files.pull` → 多次 `files.read`；`files.cancel` 中止。
  - 每次传送由代理生成的 UUID 标识，同时最多 8 个；每块最多 45 KiB，以 base64 装在 64 KiB 的帧里。
  - 上传按声明的大小收满才发布，多出或不足都失败；下载结束时核对总字节数。
  - 控制通道关闭（客户端退出或被强杀）时，进行中的传送全部终止，未完成的文件不会出现在“下载”里。

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
