# 部署

现行的部署入口如下。各自的说明在对应目录里，这里只做索引。

| 部分 | 位置 | 内容 |
|---|---|---|
| 中心 | [`server/deploy/install-control`](../server/deploy/install-control) | 在 Rocky/RHEL 9 管理服务器上以 root 运行：安装中心（`orangespace_control`）和 Web 管理后台，前面是 Caddy（为公网 IP 申请公开信任的证书）；数据库是 MySQL（阿里云 RDS），连接配置只放在服务器上的 root 私有文件里。重复运行即升级，保留数据库。运维命令见 [server/README.md](../server/README.md) |
| 节点 | [`linux-desktop/node/`](../linux-desktop/node/README.md) | `install-api` 装 TUIC 租约隧道（sing-box 1.14.4，校验 SHA-256）、本机解析器 unbound、节点 API 和 nginx 前端，签发每节点私有 CA；`enroll-node` 在中心登记。节点是中心的联邦节点，运行在内存模式，不建数据库，也没有本地账户 |
| Windows 安装包 | [`deploy/windows/`](windows/README.md) | Inno Setup 安装包：客户端、信任文件、发行版根文件系统与桌面镜像，附软件包清单与源码获取方式 |
| 开发包 | [`deploy/packages/`](packages/README.md) | 从干净的 checkout 构建中心与节点的开发包（不安装、不启动服务） |
| 开发运行 | [`deploy/dev/`](dev/README.md)、[`deploy/linux-node/`](linux-node/README.md) | 控制台的前台开发入口；数据库模式节点的开发运行包（两个独立实例） |

云安全组：中心放行 TCP 80（证书签发）和 443；节点放行 TCP 8443 和 UDP 20000–20015（租约隧道端口）。

早期的静态 TUIC 节点部署（手工生成的固定凭据、`orangespace-tuic.service`、Caddy 前端的文件节点）在 L3 收尾时停用，两台节点上的对应服务已删除，相关文件于 2026-11-23 从仓库删除，可在 git 历史中查到。
