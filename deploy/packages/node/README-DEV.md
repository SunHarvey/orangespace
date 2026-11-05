# OrangeSpace Linux Node 开发运行包

干净源码重建命令、helper 官方归档/对应源码/license hash 与离线依赖要求见仓库 `deploy/packages/README.md`；入口为 `python3 deploy/packages/build.py node --deps /absolute/reviewed-dependencies --output /absolute/output/node-dev.tar.gz`。历史 ACCEPTANCE 不会被继承到新构建。

这是 Linux x86-64 **Node 角色开发包**，不是正式安装器，也不是中心管理台包。本包含后端 wheel、锁定依赖、受保护配置示例、部署模板和固定版本 sing-box。Python wheel 名称/版本仍为 0.1.0；请以 BUILD-MANIFEST.json 的角色、源码哈希和 wheel SHA-256 区分开发构建，不能混用另一角色包中的同名 wheel。

## 新 managed Node：安装与本地状态

需要 Linux、Python 3.12+、venv、procfs/pidfd。新建独立包目录，不覆盖已有服务、状态或个人区。在解压后的包目录运行：

```sh
python3 -I -m venv .venv
.venv/bin/python -I -m pip --isolated install \
  -r server/requirements.lock server/orangespace_node-0.1.0-py3-none-any.whl
```

**RDS 仅供 Centre 管理/控制服务使用。新 HK/SG managed Nodes 使用各自明确配置的私有本地 SQLite 执行状态，不接收 RDS 凭据、不连接 RDS，也不要求额外 MySQL 库或数据库代理。** Windows 本地 SQLite 不受影响。这里的 SQLite 是 Node 持久化安全状态，不是个人文件存储，也不是 MySQL 连接失败后的自动回退。

由运维在包外准备受保护的 `runtime.json` 和 `database.json`：

- runtime profile 的 `schema` 为整数 `1`；保留真实 `nodeUUID`，通过 `dataRoot`、`dbConfig` 选择绝对路径。新 managed Node 必须显式设置 **`"deploymentMode": "managed-local"`**，拼写和值严格匹配；省略该字段是旧兼容模式，不能作为 managed 配置使用。
- `federationConfig` 必须指向有效、受保护且绑定本节点的联邦配置；缺失或无效时启动失败。配置及其机密由登记/运维流程提供，不写入包或示例。不能以删除 deploymentMode/federationConfig 绕过失败。
- `database.json` 只含 `database_url` 字符串；必须明确选择绝对、规范的 SQLite 文件 URL（`sqlite:////absolute/private-state/node.db` 这一形式），不含 query/fragment，不用内存库或其他驱动。URL 不进入 argv/env/log；`ORANGESPACE_DATABASE_URL` 不受支持。
- runtime/database/federation 配置保存在受信管理目录，使用受保护普通文件，不给组/其他用户权限，不用符号链接或多重硬链接。runtime profile 还要求绝对路径。
- SQLite 所在 state 目录由运行账号拥有、权限 `0700`，祖先必须是受信普通目录；数据库是该账号拥有的单链接普通文件、权限 `0600`。先显式准备目录，再以同一运行账号执行下面的迁移；`upgrade` 可创建尚不存在的数据库文件并配置 WAL，运行入口不创建或修复它。
- state 目录与 `dataRoot` 个人文件根必须完全分离：不得相同、相互包含或通过路径别名重叠。选择适当本地文件系统和每节点独立路径；路径检查不证明 bind mount 等价性。state 包含会话、身份绑定、grant、generation 和 tombstone 等持久状态，不得当缓存清理。

先对明确选定的本地状态显式迁移并验证：

```sh
.venv/bin/orangespace-node-migrate upgrade --database-config /your/private/database.json
.venv/bin/orangespace-node-migrate verify --database-config /your/private/database.json
# 当前 Node head: node_0002
```

启动只验证既有 schema/状态，不执行启动 DDL、不 reset、不自动换库。保留既有节点/用户 UUID、反重放记录和文件归属，不清库重建、不按用户名合并。上述命令不提供既有 MySQL 数据自动搬迁到 SQLite 的能力。

## 启停与独立实例

```sh
# 前台运行；Ctrl-C 或向此确切进程发送 SIGTERM 停止。
(ulimit -c 0; exec .venv/bin/python -I -m orangespace_node.runtime \
  --profile /your/private/runtime.json serve)

# 另一个终端查询；使用实际配置的回环端口：
curl --fail http://127.0.0.1:19091/healthz
# 文件 API 未认证应为 401，而不是 200。
curl --silent --output /dev/null --write-out '%{http_code}\n' \
  http://127.0.0.1:19091/v1/files
```

profile 默认只监听回环 HTTP，`listenHost` 只能是 `127.0.0.1`；远端 HTTPS API 需显式配置 `tlsListenHost`、`tlsListenPort`、`tlsCertificate`、`tlsPrivateKey`，保留证书和名称验证，不修改系统根信任。HTTPS 与回环 probe 共用同一 app/lifespan/manager，不要求新增代理。health 成功不证明 Centre 授权或 TUIC 转发。

**managed-local 的 runtime `admin` 包装入口明确不受支持。** 不运行旧包装入口的 `list-users`、`create-user`、`enable-tunnel` 或 `publish-identity-evidence` 来配置 managed Node，也不能去掉 deploymentMode 转发给旧 CLI。上面的显式迁移工具只负责 schema，不负责用户/授权配置。

长期运行和启用 TUIC 时使用 `deploy/linux-node/orangespace-linux-node@.service` 的独立 systemd cgroup：审核并替换自己的用户、release/venv、profile、可写 files/state 路径，安装为此前不存在的项目 unit，按准确实例名 start/status/stop；不使用通配 stop、同名 kill 或现有业务 unit。LimitCORE=0 仅限本实例。API 被强杀时必须由自己的 cgroup 收束其 sing-box 子进程；裸前台进程不提供强杀后的系统级子进程回收保证。

## 可信登记、映射与授权：独立集成仍待完成

Node 必须先经中心管理员创建登记，使用自己的原 Ed25519 key 完成 challenge/complete，再独立核验实际 HTTPS 节点身份和 key fingerprint，由管理员审核激活。pending 不等于获准服务。已有独立登记入口：

```sh
.venv/bin/python -I -m orangespace_node.enrollment_client \
  --config /your/private/enrollment-request.json
```

输入配置包含一次性登记凭据，只保存在包外私有文件中。输出目录必须全新，保护 machine.json/federation.json，失败先核对服务端状态，不盲目重放。600 秒登记过期且未消费时可用管理员 renew 接口保留原 enrollment/UUID/key 续办，不 SQL 改期/删记录/换 UUID。登记成功不自动完成本地用户、映射或 scope/grant 配置。

业务链仍要求真实 Node 本地用户主键、受保护 machine 身份 inventory、中心显式 propose/approve 的 central/local/node UUID 映射和 files.read/files.write/tunnel scope；相同用户名不是映射证据。tunnel 还受 Node 本地 grant veto 约束，不能代替中心授权。**managed-local 的本地身份/inventory/映射/grant provisioning 运维集成仍待完成；这里没有新增可支持这一全流程的管理 CLI，也不提供直接 SQL 配置步骤。**

managed-local 禁止本地密码登录（`/v1/auth/login` 返回 403），只接受联邦路径；缺失联邦运行状态时受保护请求 fail closed，不退回本地密码或本地独立授权。真实 Centre HTTPS 机密授权、exchange、scope、permit/revocation 与本地持久状态的联合验收仍是独立门槛。

## 旧 MySQL：仅既有兼容信息

未指定 deploymentMode 的旧 profile/Node MySQL 路径仍保留兼容；它不是新 managed Node 的前置条件，不授权向 Node 分发 Centre RDS 凭据。旧 MySQL 路径维持既有 MySQL 8.0.36+（8.0 线）或 8.4、InnoDB、utf8mb4 和严格模式检查，配置及数据沿原批准边界维护，不从本说明推导新的连接权限。`deploy/linux-node/node-a.runtime.example.json` 等旧示例和相关旧 CLI 不能未经调整当作 managed-local 完整部署说明。

## TUIC、文件与证据边界

`runtime/sing-box` 固定 1.14.4；上游、archive/binary/source 哈希及许可证材料在 third-party/。管理员安装运行文件到 root-controlled 路径，tunnel.json 的 executable_sha256 必须匹配，TLS key/CA/lock/端口池独立且受保护。tunnel 配置结构见 `server/TUNNELS.md`；引用部署模板时不得继承旧 MySQL 前置要求。probe_port 必须等于该实例回环 HTTP 端口；null 明确不启用 tunnel，不会伪装成功。Node 租约最多 30 秒，不放宽期限处理失败。

证据必须按准确源码及程序哈希分别记录：

- **源码审查**：Node local-store adapter 与 managed runtime 两个切片已分别通过有界源码审查；这不等于新包运行验收。父任务的 clean-source 118 项测试及另行 15 项 legacy-profile 测试是回归证据；注入身份/helper 失败的 ASGI 并发测试不是真实 Centre、成功 helper 或转发验收。
- **新包**：`BUILD-MANIFEST.json` 默认为 build-only；最终文档需审查，最终 clean build、归档内容/哈希核对与运行验收另行进行。本说明不宣称新包已构建通过、已部署或 deployment ready，不附加或继承旧包 ACCEPTANCE。
- **部署/实机**：旧同主机双 Node 的 HTTPS、登记、映射与文件测试仅属历史证据，不能继承为本地 SQLite managed 新包验收，也不证明 HK/SG 独立物理出口。实际 managed 前台启动/停止、TCP/TLS 拒绝路径、Centre 联邦、本地身份 provisioning、真实 helper 生命周期/TUIC 转发与清理、HK/SG 部署以及 Windows Service/CEF 联合验收均须独立证明。

本包没有真实运行配置、用户密码、machine token、私钥或个人文件。持续流撤销、真实 UDP/DNS 和 2 核 1 GB 容量不能由 API health 或文件测试推导。WFP/DNS、完整浏览器和网页文件桥尚未验收，浏览器保持锁定。本包不改变已有反向代理、域名、证书、系统信任库或其他业务服务。
