# 节点

节点装在一台 Rocky/RHEL 服务器上，是中心的联邦节点：只提供 TUIC 租约隧道、DNS 和节点 API，不运行桌面。

| 文件 | 作用 |
|---|---|
| `install-api <节点 uuid> <公网 IPv4> <TLS 名称> <server.tar.gz>` | 以 root 运行。装校验过 SHA-256 的 sing-box 1.14.4 和节点 API（`server/`），作为中心的联邦节点 |
| `enroll-node <中心地址>` | 以 root 运行，标准输入是中心一次性登记信息，在中心登记本节点 |

## 联邦节点（租约模式）

节点不建数据库，也没有本地账户：账户、授权和节点登记都在中心。节点只在内存里保存会话和租约，重启即清空，客户端重新换票、用更高代次新建隧道。中心记录每个沙盒的最新代次，旧隧道无法复活。

`install-api` 创建：
- 本机解析器 unbound（127.0.0.1:5353），供租约隧道解析 DNS；
- 每节点私有 CA，签发 HTTPS API 证书和租约 TUIC 证书，私钥不离开服务器。客户端固定信任 `/etc/orangespace/tls/ca.crt`；
- 节点 Ed25519 身份密钥，只有服务账户 `os-node` 可读，登记时向中心证明；
- 服务 `orangespace-node-api`（只听 127.0.0.1:8080，内存上限 256 MB），每条租约的 sing-box 都在它的 cgroup 里，随它退出；
- nginx TLS 前端 :8443，拒绝只供本机用的探测路由。

部署步骤：

```
# 节点上
install-api <uuid> <ipv4> <名称> server.tar.gz      # 打印密钥指纹
# 中心登记，令牌经管道直传，不显示、不落盘
ssh 中心 orangespace-control-admin enroll-node --node-id <uuid> --alias <别名> --display-name <名称> \
    --api-origin https://<ipv4>:8443 --tls-server-name <ipv4> --key-fingerprint <指纹> \
  | ssh 节点 enroll-node https://<中心 IP>
ssh 中心 orangespace-control-admin activate-node --alias <别名>
ssh 中心 orangespace-control-admin grant --username <用户> --alias <别名>
```

云安全组只需放行 TCP 8443 和 UDP 20000–20015（租约隧道端口）。

## 出站限制

节点只转发公网目的地址：私有地址、CGNAT 段与云元数据地址（`100.100.100.200`）一律拒绝，避免沙盒经节点读取服务器的云凭据。

出口验收在客户端一侧用 `network/egress-check`，见 [网关说明](../network/README.md)。
