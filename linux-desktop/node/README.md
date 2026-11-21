# 开发用 TUIC 节点

L3 用来验证"全流量走节点"的最简节点：一台 Linux 服务器上的 sing-box TUIC 服务端，自签证书，每个沙盒一组独立凭据。完整节点（中心授权、租约、个人文件 API，`server/`）在 L4 接入后取代它。

| 文件 | 作用 |
|---|---|
| `install <TLS 名称>` | 在 Rocky/RHEL 服务器上以 root 运行：安装校验过 SHA-256 的 sing-box 1.14.4、低权限用户 `os-tuic`、加固的 systemd 单元 `orangespace-tuic`，生成只留在服务器上的自签证书私钥 |
| `make-configs` | 在操作者机器上生成每台节点的服务端配置和每个沙盒的导入文件；不打印任何凭据 |

节点只转发公网目的地址：私有地址、CGNAT 段与云元数据地址（`100.100.100.200`）一律拒绝，避免沙盒经节点读取服务器的云凭据。TUIC 走 UDP，云安全组要放行对应 UDP 端口。

沙盒导入文件经客户端（开发时用 `orangespace-wsl configure`）交给客体代理，只写入该沙盒的私有目录。出口验收用 `network/egress-check`。
