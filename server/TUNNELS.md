# 节点短租约 TUIC 控制面（默认关闭）

这是 Linux 节点开发组件，不开放 Windows 浏览器、不替代 WFP/受管 DNS/安装验收。登录只授权原文件 API，**不产生隧道权限**。

## 接口

已有 login/logout/me/file 响应字段不变。所有响应保持 `Cache-Control: no-store`。

- `GET /v1/session`，Bearer：严格返回 `user_id, username, node_id, expires_at`。期限取实际数据库会话，不由客户端推算。
- `POST /v1/tunnels`，Bearer：JSON 严格只有 `sandbox_id, generation, tunnel_id`。两个 UUID 必须为小写规范形式且非零；代次为整数 `1..2^53-1`，拒绝 bool/浮点数/重复 JSON 成员和其他字段。身份和节点由服务端决定。
- CREATE 和 RENEW 都要求唯一且值恰为 `2` 的 `X-OrangeSpace-Lease-Schema` 请求头；缺失、旧版本、空白/其他值和重复头在调用 manager、保留代次、创建 child 或修改续租前返回 426。认证仍独立执行，不因版本头而绕过；其他路由不要求此头。v1/v2 不隐式互通。
- 创建成功 200，严格返回 17 个字段：`user_id, node_id, sandbox_id, generation, tunnel_id, expires_at, endpoint_ip, endpoint_port, tls_server_name, tuic_uuid, tuic_password, probe_host, probe_port, probe_request, probe_response, lease_schema, remaining_ttl_ms`。随机 TUIC UUID、256 位 URL-safe 密码、两个独立随机 probe secret；后面三个随机字符串均为 43 个字符。不复用 API token 或用户 UUID。
- `POST /v1/tunnels/{id}/renew`，Bearer；没有请求体或者空 JSON 对象。严格返回 5 个字段：`tunnel_id, expires_at, node_id, lease_schema, remaining_ttl_ms`。仅原始 API 会话、用户、有效租约和当前授权可续租，不能复活旧租约。
- `DELETE /v1/tunnels/{id}`，Bearer；仅原始认证用户和 API 会话可撤销，成功 204。对该会话拥有的已回收 tombstone 重复删除仍为 204；若授权已撤销但 child 尚未确定 kill/reap，重复 DELETE 重试准确 child，仍失败返回通用 503，不伪报清理完成；别的用户/会话和未知 ID 为 404。
- `POST /v1/tunnels/{id}/probe`：**不用 Bearer**，只用 `X-OrangeSpace-Probe: <probe_request>`。仅在配置的真实 `127.0.0.1:probe_port` 本地监听、loopback 对端上接受；拒绝 Forwarded/X-Forwarded-*/X-Real-IP，公网反向代理必须额外禁止此路由。返回恰好 `{tunnel_id, proof: <probe_response>}`，绝不回显请求 secret。不有效/不匹配为 404。

缺少 grant 为 403；grant 已开但运行时未配置为 503；格式错误 422，JSON 超过 16 KiB 为 413；旧 ID/旧代次为 409；容量或锁竞争为 429；已知租约失效的续租为 410（若 reaper 已删除则 404，API 会话已失效则 401）。启动失败只给通用 503，不输出 sing-box stderr/配置。

管理员在已有受信 CLI 中执行 `orangespace-node enable-tunnel <username>` 或 `disable-tunnel <username>`。没有公开 grant API，默认没有 grant。每次修改原子递增 grant epoch；快速 disable/enable 也不会复活旧租约。初始化仅增加三个新表 `tunnel_grants, tunnel_generations, tunnel_tombstones`，不改原表字段；未来更改现有表仍需版本迁移。

## 受保护设置

未设置 `ORANGESPACE_TUNNEL_CONFIG` 时完全不启动子进程。该变量**只指定非秘密 JSON 设置文件的绝对路径**。全部字段必填，未知字段拒绝：

| 字段 | 要求 |
|---|---|
| `executable`, `executable_sha256` | 固定、绝对、管理员审核的 sing-box 路径及小写 64 位 SHA-256；测试使用仓库已固定的 1.14.4；请求不能指定程序/参数 |
| `certificate`, `private_key` | 绝对 TLS 证书/私钥路径；key 不可给予 other 任何权限 |
| `endpoint_ip`, `listen_ip` | 实际管理员提供的字面 IP，分别为对外地址和 UDP 本地绑定地址 |
| `tls_server_name` | 与证书匹配的 DNS 名；不得在客户端跳过证书验证 |
| `port_start`, `port_end` | 1024..65535，连续范围最多 256 个端口 |
| `max_leases` | 1..128，不能超过端口数；包含尚未确定回收的子进程 |
| `lease_seconds` | 1..30；每次期限还受真实 API 会话剩余期限约束 |
| `startup_timeout` | 0.1..5 秒，配置 stdin 写入和实际监听就绪共享期限 |
| `probe_port` | 1..65535；ASGI API 必须在这个确切的 IPv4 loopback 端口监听 |
| `dns_port` | 1..65535；管理员已有的节点本地 UDP 解析器端口 |
| `lock_file` | 已预建的 root 保护普通文件；同一节点所有实例必须使用同一路径 |

设置、程序、证书、key、lock 文件以及全部祖先目录必须 root 拥有，禁止 group/other 写入和符号链接。文件不能有额外硬链接，设置/TLS/lock 大小不超过 64 KiB，程序不超过 100 MiB。服务账号需有读取/目录遍历/程序执行权限，但不能修改它们；例如通过只读组授予 key/lock 读取权限。运行期间管理员不得原地改写这些文件；更新须停服、核验、重新启动。程序以验证并保留的文件描述符执行，避免路径替换改用另一文件。

请使用专用非 root 服务账号。此实现不替部署者配置系统服务或网络：

1. **仅一个 API worker/实例**；root 保护 flock 锁拒绝同一配置并行启动。不要用多份锁绕过单 owner 条件。
2. **必须由受保护的 systemd control-group unit 管理 API 和所有 TUIC 子进程**，`KillMode=control-group`、`SendSIGKILL=yes`；异常退出/restart 前必须清空同一个 cgroup。Python 自己无法回收被 SIGKILL 后的孤儿；没有这项前提，重启时不允许启用运行时。此项没有在本次本地测试中验收。
3. API `LimitCORE=0`（运行时检查 soft core limit 为 0）；每个 TUIC 子进程在接收秘密前将 soft/hard core limit 都设为 0。禁止进程/堆快照、请求体/响应体/probe header 采集，使用禁用或加密 swap；Python 内存不能保证密码字节即时擦除。
4. API 仅绑定 loopback，公网继续由 HTTPS 代理承载。代理显式禁止 `/v1/tunnels/*/probe`，并限制连接、速率、请求超时和正文采集。probe 传输检查不是对被管理员故意剥去全部代理标记的恶意代理的防护。
5. 配置真实 TLS 文件、节点解析器和受限 UDP 端口范围的防火墙/NAT。TLS key 是管理员长期密钥，不是临时租约凭据。不要把运行时设置/程序放在个人文件区。

节点侧沿用原节点脚本的 DNS hijack/解析后私网和特殊地址拒绝策略，唯独在解析/拒绝前放行到确切 probe loopback TCP 端口。这里的 `direct` 是已授权节点的出口，不是 Windows 本机直连回退。尚未对这个新增租约路径执行真实 DNS/公网 TCP/UDP 出口验收。

## 生命周期、持久化与边界

每个租约一个前台 sing-box、一个 UDP listener；JSON 仅通过 stdin，空环境，无 shell，日志和 stdout/stderr 关闭。就绪检查匹配该子进程拥有的 socket inode，不把其他进程占端口当成功。Linux pidfd 固定进程身份，撤销只 kill/reap 这一进程，不按可重用 PID/进程组号杀其他租约。固定可信配置不运行外部程序，sing-box 不派生外部 helper；这不是通用恶意程序 containment。

创建前先提交永久 ID tombstone 和用户/sandbox 最大代次；失败也不允许重用，较高代次先关闭旧 listener。DB 不存 TUIC UUID/密码/probe secrets/活动 PID；只有 owner/session digest/绑定/最大代次/授权。重启时内存租约为空且旧 ID 不可恢复。永久 tombstone 不可随意清理，数据库会随历史创建次数增长，需管理员容量/入口速率管理。

logout 先在 DB 撤销准确 API 会话，再等待正在启动的子进程并同步回收该会话的 listeners；创建完成前再次读取会话/用户/grant/epoch。单 owner 锁串行化 create/renew/delete；锁竞争等待 100ms 后拒绝（logout 必须等待已开始的有界启动/清理）。租约同时保存 monotonic deadline，墙钟回拨不能延长已有租约。后台每 200ms 重新读取实际会话期限、撤销、用户 enable、grant epoch、持久化最大代次、lease 期限和 child 状态；不是硬实时的网络瞬时撤销保证，受线程调度、启动操作和 DB 延迟影响。DB 检查失败也撤销 listener。DELETE／替代代次／logout／close 在 kill/reap 前移除对应活动租约；所有同步和后台清理的 signal/wait 失败都保留准确 child/pidfd 所有权继续重试，并锁闭新分配直到重启，即使后续回收成功也不解除。旧租约不能再 renew/probe；无关且仍有效的租约不因另一个 child 的清理失败被全局撤销。logout 保留先撤销 DB 会话的顺序，也重试该会话已进入 pending 的 child。close 清理失败时不提前停止 reaper 或释放 owner 文件描述符，进程仍运行期间继续重试，后续 close 确认全部回收后才释放；进程退出仍依赖上述 systemd cgroup 条件。

创建成功只说明节点子进程和 listener 就绪，不声称客户端已认证或数据已转发。客户端必须通过自己的真实 TUIC/SOCKS 链路取得独立 probe_response 后，才可报告 forwarding_verified。

### 租约协议 v2 的剩余预算

`lease_schema` 为整数 `2`；`remaining_ttl_ms` 为正整数 `1..30000`。创建在真实 helper startup 和第二次授权检查之后，续租在有效性检查和新期限计算之后，均持有原 operation 锁即时计算。预算取 live monotonic deadline、节点墙钟到 `expires_at`、实际认证会话墙钟到期时间及 30 秒的最小剩余时间，再向下取整为毫秒。对浮点时钟的实际表示值先用精确有理数做减法/乘法，再整除，避免浮点乘法把不足一毫秒的值上舍入为 1。不是配置常量 TTL，也不从旧创建响应的 TTL 重算/重锚。

`expires_at` 仍在节点时间域，并受实际认证会话期限限制；未更改配置的 `lease_seconds` 或系统时钟。续租发布前还重查 OLD deadline/旧墙钟期限，不能在检查耗时后复活旧租约。预算为零、负数或不足一毫秒均拒绝发布；创建撤销准确新 child，续租先撤销活动租约再回收准确 child；原 pidfd、pending 所有权和 sticky cleanup-failure 锁闭保持不变。子进程终止仍受现有调度/清理边界限制，不声称硬实时。

客户端须按 `docs/lease-protocol-v2.md` 的共同单调时钟，在实际 CREATE/RENEW 请求开始时锚定预算；不能在收到回复、排队后或 FFI 入场时重启预算。此文件只说明节点切片，不证明 C++/Rust/Windows 的集成实现或验收。

## 验证

以下旧 SQLite/PostgreSQL 套件数量均为历史记录，不是当前 MySQL 运行模式或最新总数。正式运行只支持 MySQL。

依赖锁和来源未改变，使用已有隔离 `server/.venv`，没有修改系统 Python。安装时显式使用官方 HTTPS PyPI，例如 `python -m pip install --index-url https://pypi.org/simple -r requirements.lock -e '.[test]'`。

在根目录运行：

```sh
server/.venv/bin/python -m pytest server/tests -q --tb=short --assert=plain
ORANGESPACE_TEST_SING_BOX=/absolute/verified/sing-box server/.venv/bin/python -m pytest server/tests -q --tb=short --assert=plain
```

真实运行时夹具显式 opt-in，并需要 root 创建 root-owned 的隔离安装测试文件；实际生产服务不应 root 运行。未设置 binary 跳过，不伪装实测。`--assert=plain` 避免失败时 pytest 自动展开含一次性秘密的表达式。TLS fixture、配置和 DB 都只在 pytest 临时目录中。

实际 RED→GREEN 包括：session 404→200/默认拒绝；grant 操作缺失→明确授权且 disabled runtime 503；runtime 设置缺失→真实 stdin TUIC child；renew 404→200/准确会话撤销；logout 等启动而未立即撤销→先撤销 DB；缺少 pidfd/core 限制→真实内核句柄和 core hard=0；reaper 超时导致线程退出→保留重试并拒绝新分配；重复 JSON 403→422；公网代理/错端口 probe 200→404；私网 TCP 可达→拒绝；并发 grant 丢 epoch→原子递增；公开 key 未拒绝→启动拒绝；create 的同步 reap 后继续分配→503；墙钟回拨后旧租约仍可续租→monotonic deadline 拒绝。

真实测试通过同一 app 的 loopback uvicorn + 两个真实 sing-box TUIC clients 获取不同 proof，关闭 A 后 A 转发失败、B 仍成功，并证明其他 node loopback TCP 端口被拒绝。其他测试覆盖过期/会话撤销/禁用用户/grant disable-enable/child crash、重启 replay、秘密不在 argv/env/SQLite、秘密 repr 隐藏、最大 `2^53-1` 实际存取与 SQL BigInteger 类型、容量和受保护配置。此前完整执行为 **86 passed, 1 skipped, 1 warning，191.17 秒**（显式启用真实 sing-box）。跳过项为未设置 `ORANGESPACE_TEST_POSTGRES_URL` 的 PostgreSQL；警告为已有 Starlette TestClient/httpx 弃用提示。compileall、pip check、git diff --check 均通过，requirements.lock/pyproject.toml 无改动。PostgreSQL 只有显式临时专用数据库实跑才算通过；Windows/部署/公网/WFP 一律不由这些本地结果推断。

### 同步清理失败修正（2026-10-30，本地）

在原 `tunnels.py` SHA-256 `1a07dbeb57f4374bdd937d99d2197fe81bae39156083b8fb49b27bacd8ce6e90` 上先运行新增故障夹具：DELETE／替代代次／初始 readiness 失败／启动后 epoch 检查失败，分别注入准确 child 的 pidfd signal `OSError` 或该 child 的 wait `TimeoutExpired`，**8 项先失败**；DELETE／替代代次在第一次 kill/wait 时仍保留活动授权，startup 路径未锁闭分配。后续分片 RED 另检出最大代次未校验、多 listener logout/close 首项失败阻断后续清理、pending DELETE 假成功和 logout 漏掉已进入 pending 的会话 child，均先复现后修正。grant disable-enable 原有 epoch 防复活检查仍通过。

新增 `test_tunnel_cleanup.py` 共 **16 项**，最终连续两次独立运行均通过；真实 sing-box child 接收 stdin 配置并由真实 pidfd 定位，异常本身为 Python 精确故障注入，**不是自然发生的 Linux 内核错误或 Windows 验收**。夹具检查授权先撤销、持有准确 child/pidfd、重复失败仍继续重试、成功后真正 wait/reap/关闭 pidfd、sticky 新分配锁闭、其他有效租约仍能 renew/probe、owner/session 和 tombstone/最大代次不混用；异常断言也先解除注入再清理所有夹具 child。最终完整 opt-in server 套件 **102 passed, 1 skipped, 1 warning，249.54 秒**；PostgreSQL 环境变量未设置，明确跳过；已有 Starlette 弃用警告保留。现有真实双 TUIC forwarding、秘密不在 argv/env/SQLite 等回归包含在本次完整执行中。compileall 与现有 venv 的 pip check 通过；未运行 Git 操作，未修改 auth/app/database、依赖或远端服务。独立第二次生产审查及部署／cgroup／Windows／公网验证仍待父流程完成。

### 协议 v2 节点切片（2026-10-30，本地）

按上述唯一共享契约实现。实际 RED→GREEN：15 个版本拒绝用例先失败后通过；create 的 17 字段/启动成本和量化预算先失败后通过；renew 的 5 字段/新鲜预算先失败后通过；renew 不足一毫秒时仍持有活动授权先失败后修复；验证耗时跨 OLD deadline 的续租先错误成功，再修复为拒绝及准确 child 清理。随后增加亚秒正负墙钟偏移、短会话、三种期限的零/负/不足一毫秒/正值/30 秒上限、浮点临界点和缺认证回归。确定性测试使用注入时钟和模型 child；另有 7 项真实 sing-box/pidfd 测试，覆盖真实启动耗时以及 create/renew 预算耗尽后的正常清理和准确 signal/wait 注入失败，不把注入故障称作自然内核错误。

使用既有 `.venv`，没有安装依赖、网络下载、Git、远端或部署操作。真实二进制为本地既有 sing-box **1.14.4**（Go **1.26.10**），SHA-256 `1264361b5f8868c8768f7555d3e77e20118bf503c41ac08bb290a0d99056aa3a`。完整显式 opt-in 测试 **154 passed, 1 skipped, 1 warning，349.81 秒**；最终不启用 runtime 的正常 SQLite 套件 **97 passed, 58 skipped, 1 warning，139.14 秒**（57 项 runtime 显式 opt-in 跳过，另 1 项为 PostgreSQL）。compileall 和既有 venv 的 pip check 通过；结束后未发现本地 pytest sing-box 进程残留。跳过项为未配置的专用 PostgreSQL，警告为既有 Starlette/httpx 弃用提示。真实 TUIC 双链路 forwarding、单独撤销及既有安全回归在此次执行中通过。此证据不覆盖生产部署/cgroup、跨主机 skew、Windows、WFP 或完整阶段验收；仍需父流程独立审查和协调集成。

### 最新 MySQL 与 Centre + Node 证据（2026-10-31，本地）

真实 MySQL **8.4.13** + approved sing-box **1.14.4** 完整套件：**258 passed、0 skipped、0 failed、17 warnings，945.39 秒**。未部署；GitHub CI 仍须推送后逐 SHA 验证。CI 必须以 root 创建隔离受保护夹具、显式设置 `ORANGESPACE_TEST_SING_BOX` 并检查 JUnit 测试数大于零且 skip/error/failure 全零；未设置 binary 或非 root 不得称全过。

`test_node_permit_runtime.py` 通过真实 Centre + Node ASGI 控制请求及真实本地 TUIC proof 验证：经批准的 seed 仅为测试前置（包括夹具显式写入的映射/授权），不是完整注册部署验收；撤销中心 session A 后拒绝其 renew，原 monotonic deadline D 不变；在 D+3 观察窗口内看到 A child 退出，随后独立检查 lease/child/pidfd 所有权释放，B 续租并仍取得新 proof。不把观察结果归因于已精确证明的某一种即时撤销机制或精确退出时刻。新 TCP probe 不证明既有 TCP/UDP 流中断；ASGI 不证明公网 HTTPS，也不证明 Windows/WFP、生产 cgroup 或跨主机完整验收。
