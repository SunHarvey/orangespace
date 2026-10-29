# Rust 控制核心与本地 broker

当前代码实现的是控制平面的隔离规则及本地元数据管理。**尚未捕获实际 TCP/UDP 数据，也没有完成 Windows WFP/DNS 管控，因此任何 `open` 都失败；不能用它安全上网。**

## 本地试运行

```sh
cargo run -p orangespace-broker -- --data-dir /tmp/orangespace-local status
cargo run -p orangespace-broker -- --data-dir /tmp/orangespace-local create --user 11111111-1111-4111-8111-111111111111 --name 深圳工作区
cargo run -p orangespace-broker -- --data-dir /tmp/orangespace-local list --user 11111111-1111-4111-8111-111111111111
```

Windows 默认数据目录是 `%LOCALAPPDATA%\OrangeSpace`。其他平台必须显式提供 `--data-dir`。UUID 用户参数用于本地开发管理，并非服务器登录验证；正式客户端必须从经过认证的会话绑定用户，并由受限 IPC 和 Windows 身份约束请求。

`bind --user UUID --sandbox UUID --node UUID` 持久化节点绑定并递增代次，不创建隧道。`close` 保留本地数据。`delete` 仅删除指定沙盒的 profile/cache/tasks 和本地任务，不访问 Linux 文件服务。删除失败保留 `deleting` 元数据，可重试。`task-create`/`task-list` 仅演示不可变目标节点记录，尚不传输文件。

stdout 是一行 JSON，`schema_version=1`。业务错误退出 1，错误也输出 JSON；命令行语法错误由 clap 输出到 stderr。`status` 总是 `browsing_allowed=false`；`open` 无法通过配置开关绕过 GuardBackend。原生 UI 可调用此 CLI，但生产 IPC 尚未实现。

## TUIC 离线配置

`tunnel-config --user UUID --sandbox UUID --settings-file private-settings.json --output private-tuic.json` 生成 sing-box 配置文件，**不运行** helper 或浏览器。输出必须不存在，Unix 权限 0600。Windows 的受限 ACL 文件写入未完成，因此 Windows 上此命令被拒绝。

设置文件格式如下；示例凭据不可部署。请使用随机密码并保护源设置文件，勿纳入版本库：

```json
{
  "node_id": "22222222-2222-4222-8222-222222222222",
  "endpoint_ip": "203.0.113.10",
  "endpoint_port": 443,
  "tls_server_name": "sz.example.test",
  "tuic_uuid": "11111111-1111-4111-8111-111111111111",
  "tuic_password": "REPLACE_WITH_A_RANDOM_SECRET",
  "socks_port": 19080,
  "socks_username": "broker-only",
  "socks_password": "REPLACE_WITH_ANOTHER_RANDOM_SECRET"
}
```

只接受字面 IP 作为节点地址；证书的 DNS 名单独指定且验证开启。唯一 outbound 为 TUIC，`route.final` 固定该 outbound，不存在 direct 回退。UDP 为 native DATAGRAM，0-RTT 关闭，本地 SOCKS 仅监听 127.0.0.1 并要求认证。这仍不能代替 WFP：未完成管控时不得向浏览器公开此 SOCKS 凭据。

设置文件的 `node_id` 必须与该沙盒的绑定节点完全一致，若不一致，命令失败且不产生输出文件。当前仅校验人工提供的节点 ID 一致，不能证明人工填写的 IP、证书名和凭据确实属于该节点；正式连接必须从受信节点注册表取得这些信息。离线配置生成不构成生产节点身份授权。

私有证书节点可在设置中加入 `"certificate_path": "/absolute/path/to/trusted-ca.pem"`，显式信任该 PEM 链，仍校验 `tls_server_name`，不会关闭证书验证。

协议字段参考 [sing-box TUIC](https://sing-box.sagernet.org/configuration/outbound/tuic/) 和 [SOCKS inbound](https://sing-box.sagernet.org/configuration/inbound/socks/)。配置生成测试不代表已验证真实隧道、WebRTC、MTU 或 Windows DNS 无泄漏。
