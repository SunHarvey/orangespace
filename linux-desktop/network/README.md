# Linux 沙盒网关

每个桌面使用一个专属网关命名空间、一个 TUN 和一个 TUIC 进程。桌面只有到该网关的 veth。桌面 IPv4 TCP 和 UDP（含 DNS）可以转入 TUN，任何直接通往网关上行的转发均丢弃。每个网关的上行在客体根命名空间仅能向本沙盒配置的一个 IP 和 UDP 端口发送数据；返回流量也要匹配有效许可。规则覆盖已建立连接。隧道无法握手、进程退出、授权过期或节点失联时没有其他出口。IPv6、跨沙盒、宿主及常用内网目标默认封锁。

## 部署到专用 Debian 客体

需要 systemd、Python 3、iproute2、nftables、procps、TUN 设备和支持 gVisor/TUIC 的 sing-box（已测 1.14.4）。客体开启 `net.ipv4.ip_forward=1`。客体根命名空间须为专属点对点 veth 留出 `10.243.0.0/16` 和 `osw*` 接口名。根命名空间不应承载其他工作负载。桌面命名空间由客体管理器创建并只带 loopback；容器的 /etc/resolv.conf 可使用经节点可达的 IPv4 DNS 地址。Linux 内核不得把普通桌面用户提升到根网关或赋予其 CAP_NET_ADMIN。

以 root 拥有的目录安装本目录的 gateway.py 和 up/down/status/probe/configure，运行时文件保存在 root 专用的 /run/orangespace-network。Docker 的 iptables 模式如启用默认 FORWARD DROP，网关在 DOCKER-USER 注册仅匹配本沙盒隧道端点的精确规则，删除时回收。其他自定义防火墙如阻断该 veth 的已授权转发，需由客体管理员允许这条路径。

## 管理身份与节点文件

新建沙盒、添加节点或更新凭据时，客户端可以直接向已启动的 Linux 客体导入该沙盒的配置。可信客体管理代理在沙盒所有者的生命周期锁内确认桌面已停止，调用 `network/configure <沙盒 UUID> <节点 UUID>`，并通过标准输入传入一份 UTF-8 JSON。输入上限 64 KiB，网关拒绝运行中写入、重复字段、未知字段和节点 UUID 不符。请使用下列扁平结构，示例中的地址及凭据需要替换。

```json
{
  "node_id": "33333333-3333-4333-8333-333333333333",
  "endpoint_ip": "203.0.113.10",
  "endpoint_port": 10443,
  "tls_server_name": "node.example.net",
  "authorization": "local-persistent",
  "uuid": "22222222-2222-4222-8222-222222222222",
  "password": "replace-with-a-node-issued-secret"
}
```

导入完成后，数据盘上的 /var/lib/orangespace/desktop/instances/<沙盒 UUID>/nodes/<节点 UUID>.json 属主为 root、权限为 0600。两个沙盒即使绑定同一节点也各有一份文件；替换 A 的配置会保留 B 的凭据。导入先做整体验证，写临时文件并同步，随后原子替换并同步目录。桌面启动优先读取其私有节点；若已有私有文件且格式、权限或归属有误，则保持离线。持续运行中的网关会检查原授权来源，不能从被撤销的来源切换到另一份配置。

初次部署也可在 /etc/orangespace/nodes 下预置 root 拥有、权限 0600 的 `<节点 UUID>.json` 模板，为尚未导入私有配置的沙盒提供节点。此模板按 bindings 中的沙盒 UUID 授权。两种格式都支持可选的 certificate_pem（PEM 文本）和 HTTPS 探测；省略证书时使用系统信任库。模板示意如下。

```json
{
  "endpoint_ip": "203.0.113.10",
  "endpoint_port": 10443,
  "tls_server_name": "node.example.net",
  "authorization": "local-persistent",
  "bindings": {
    "11111111-1111-4111-8111-111111111111": {
      "uuid": "22222222-2222-4222-8222-222222222222",
      "password": "replace-with-a-node-issued-secret"
    }
  },
  "probe": {
    "ipv4": "198.51.100.77",
    "tls_name": "probe.example.net",
    "port": 443,
    "path": "/ready"
  }
}
```

- `authorization = local-persistent` 启动独立的网关监督进程，每 3 秒重读 root-only 节点配置，并以单个 nftables 事务续期一个 15 秒的内核许可。移除该沙盒绑定、修改端点/认证/探测配置或节点文件不可读时，监督进程清许可并停止隧道。监督进程异常退出时，已有内核许可至多在这个窗口后失效。修改配置或恢复故障后重新启动该网关。
- 如需一次性定时节点窗口，可用 `"ttl_seconds": 300` 替代 authorization。范围为 1–3600 秒，由内核独立过期。两种授权字段同时存在会被拒绝。此版本不签发或续订中心租约。部署到带中心撤销、会话或休眠重授权要求的系统之前，应对接其真实认证链并做宿主唤醒实测。
- `probe` 可省略。配置时，其目标应为能通过节点出口访问的 HTTPS 服务，返回 2xx。可单独配置 probe.certificate_pem 信任私有探测服务。探测从桌面的网络命名空间连接字面 IPv4，校验 TLS 名称和证书，不依赖宿主 DNS，不跟随重定向。单次最多等待 3 秒，每个沙盒缓存结果 3 秒。它反映所配服务的端到端可达性。

## 管理器调用

```sh
network/up <沙盒-UUID> <容器主进程PID> <节点-UUID>
network/status <沙盒-UUID>
network/probe <沙盒-UUID>
network/down <沙盒-UUID>
network/configure <沙盒-UUID> <节点-UUID> < node-import.json
```

上述入口只能由可信的客体管理代理以 root 调用。代理需在持有沙盒生命周期锁时取得并传入 Docker 主 PID。up 会先关闭该沙盒之前的网关；新节点配置无效会保持离线。不同沙盒使用独立实例锁和命名资源。up 在桌面只有 loopback 时接网，先安装封锁规则，最后添加桌面默认路由。down 可重复调用，先拆除上行，再停止进程和删除规则。status 的退出码 0 表示本地隧道进程和网关许可已就绪。probe 的 0 表示 HTTPS 探测成功，1 表示探测失败，2 表示无本地网关或未配置探测。

## 真实故障回归

在安装依赖的专用 Linux 测试虚拟机中可执行 `sudo python3 smoke.py`。测试短暂使用 198.18.250.0/29 两个链路和 198.51.100.77/32 测试目的地址，请确保专用客体未使用这些路由。脚本用随机沙盒/节点 UUID 和一次性证书启动两个本地 TUIC 服务，在两个隔离出网上分别提供带不同标识的 TCP、UDP 与 DNS 服务。根命名空间同地址提供直连对照服务。

它检验运行中导入后的沙盒配置优先级、两个网关并发启动、两侧端到端出口、HTTPS 探测、停止 A 节点时 B 的 512 KiB 长连接哈希、杀网关、停止沙盒、本地持续授权与撤销、内核到期封锁、重新开启网关及直连对照次数。`sudo python3 test_import.py` 另行验证私有记录的文件权限、跨沙盒独立性、失败写入的原子性和对无效记录的拒绝。测试自动回收命名空间、服务和节点凭据。此项验证覆盖真实 Linux 内核和 TUIC，不覆盖 Windows 物理网卡、外部节点或宿主休眠。
