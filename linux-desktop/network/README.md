# Linux 沙盒网关

每个桌面使用一个专属网关命名空间、一个 TUN 和一个 TUIC 进程。桌面只有到该网关的 veth。桌面 IPv4 TCP 和 UDP（含 DNS）可以转入 TUN，任何直接通往网关上行的转发均丢弃。每个网关的上行在发行版根命名空间仅能向本沙盒租约里的一个节点 IP 和 UDP 端口发送数据；返回流量也要匹配有效许可。规则覆盖已建立连接。隧道无法握手、进程退出、租约过期或节点失联时没有其他出口。IPv6、跨沙盒、宿主及常用内网目标默认封锁。

网关只接受中心租约，没有静态节点配置，也没有本机直连回退。

## 运行环境

OrangeSpace 发行版已装好全部依赖：systemd、Python 3、iproute2、nftables、procps、TUN 设备、固定版本的 sing-box（1.14.4），并开启 `net.ipv4.ip_forward=1`。根命名空间为专属点对点 veth 留出 `10.243.0.0/16` 和 `osw*` 接口名，不承载其他工作负载。桌面命名空间由 `guest/desktop` 创建，接网前只有 loopback。普通桌面用户不得进入根命名空间或获得 CAP_NET_ADMIN。

网关运行时文件在 root 专用的 `/run/orangespace-network`，租约在 tmpfs 上的 `/run/orangespace/leases/<沙盒 UUID>.json`（root 所有、0600），桌面停止或删除时随之删除。

## 租约与内核许可

客户端在节点上为沙盒创建隧道后，经客体代理把这条租约交给 `network/lease`，以 UTF-8 JSON 从标准输入传入，上限 64 KiB：

```json
{
  "node_id": "33333333-3333-4333-8333-333333333333",
  "endpoint_ip": "203.0.113.10",
  "endpoint_port": 20000,
  "tls_server_name": "203.0.113.10",
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n...",
  "uuid": "22222222-2222-4222-8222-222222222222",
  "password": "replace-with-a-node-issued-secret",
  "tunnel_id": "44444444-4444-4444-8444-444444444444",
  "remaining_ms": 29000
}
```

- 网关拒绝重复字段、未知字段、节点 UUID 与沙盒绑定不符、非字面 IPv4 端点和无效证书。`certificate_pem` 可省略，省略时用系统信任库。
- `remaining_ms` 是节点给出的租约剩余寿命，须在 0.5–30 秒之间。网关扣 0.5 秒余量换算成 CLOCK_BOOTTIME 截止时间保存，不使用墙上时钟。
- `network/up` 只用当前租约启动隧道；没有租约、租约属于别的节点或已过期时，桌面保持离线。根命名空间的出口许可是 nftables 带超时的集合元素，到截止时间由内核删除。
- 客户端每次续租成功后调用 `network/renew <沙盒> <tunnel_id> <剩余毫秒>`：在一个 nftables 事务里清空该沙盒的许可集合，再加入新的限时元素。只认当前 tunnel_id，旧隧道、别的沙盒的隧道或超出范围的剩余寿命一律拒绝，现有许可不变。
- 不需要常驻监督进程。客户端崩溃、续租失败、注销或中心撤销时不再续期，许可在租约剩余寿命内由内核自行过期。之后客户端用更高代次新建隧道，重新调用 `lease` 和 `up`。

租约可带可选的 HTTPS 探测：

```json
"probe": {"ipv4": "198.51.100.77", "tls_name": "probe.example.net", "port": 443, "path": "/ready"}
```

探测目标应为经节点出口可访问、返回 2xx 的 HTTPS 服务，可附 `certificate_pem` 信任私有探测服务。探测从桌面的网络命名空间连接字面 IPv4，校验 TLS 名称和证书，不依赖宿主 DNS，不跟随重定向。单次最多等待 3 秒，每个沙盒缓存结果 3 秒。

## 管理器调用

```sh
network/lease  <沙盒-UUID> <节点-UUID> < lease.json
network/up     <沙盒-UUID> <容器主进程PID> <节点-UUID>
network/renew  <沙盒-UUID> <tunnel-UUID> <剩余毫秒>
network/status <沙盒-UUID>
network/probe  <沙盒-UUID>
network/down   <沙盒-UUID>
```

这些入口只能由客体代理经 `guest/desktop` 以 root 调用，并持有该沙盒的生命周期锁。up 会先关闭该沙盒之前的网关；先安装封锁规则，最后添加桌面默认路由。不同沙盒使用独立实例锁和命名资源。down 可重复调用，先拆除上行，再停止进程和删除规则。status 的退出码 0 表示本地隧道进程在运行且许可未过期。probe 的 0 表示 HTTPS 探测成功，1 表示失败，2 表示无本地网关或未配置探测。

## 真实内核回归

在专用 Linux 客体（root、systemd、IPv4 转发）中执行 `sudo python3 smoke.py`。测试短暂使用 198.18.250.0/29 两个链路和 198.51.100.77/32 测试目的地址，请确保客体未使用这些路由。脚本用随机沙盒/节点 UUID 和一次性证书启动两个本地 TUIC 服务，在两个隔离出网上分别提供带不同标识的 TCP、UDP 与 DNS 服务；根命名空间同地址提供直连对照服务。

它检验：
- 没有租约或租约属于别的节点时网关不启动；
- 两个网关并发启动、两侧端到端出口、HTTPS 探测；
- 停止 A 节点时只断 A，B 的 512 KiB 长连接哈希吻合；
- 杀掉网关进程、重新授权；
- 持续续租时出口不断，随机或旧 tunnel 的续租被拒，停止续租后许可按时失效；
- 已过期的租约不能启动网关；
- 直连对照服务没有收到任何请求。

`test_import.py`（Linux；存储部分需 root）验证租约字段与剩余寿命的校验、节点绑定、私有文件权限、跨沙盒独立和只认当前隧道的续期。测试自动回收命名空间、服务和凭据。此项验证覆盖真实 Linux 内核和 TUIC，不覆盖 Windows 网卡、外部节点或宿主休眠。

## 出口检查（真实节点）

沙盒桌面运行且网关就绪时，在 OrangeSpace 发行版内以 root 执行：

```sh
network/egress-check <沙盒-UUID> [预期出口 IPv4]
```

它在该沙盒的桌面容器内，以桌面用户身份做泄漏测试页会做的事，并询问各远端服务看到的地址：HTTPS 回显、系统解析器（Akamai 权威服务器看到的解析器）、直接发往 8.8.8.8 的 DNS、WebRTC 方式的 STUN（Google、Cloudflare）、桌面 Chromium 强制走 HTTP/3（保留其自身沙盒）、IPv6。它还确认 WSL 宿主、局域网地址、云元数据地址和所有沙盒的网关链路都连不上。只有全部服务看到同一个地址（给了预期地址时须等于它）、Chromium 确实用了 HTTP/3、IPv6 不可达、本地地址全部不通时才返回 0。节点把发往任意 53 端口的 DNS 交给节点自己的解析器，所以沙盒内的 DNS 发给谁都由节点解析。

它衡量的是第三方服务看到的结果，不是包的走向；包的走向要在 Windows 网卡上抓（`pktmon`，物理网卡和 WSL 虚拟交换机两侧）。
