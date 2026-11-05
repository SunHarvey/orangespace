# Linux Node：受保护 profile、前台入口与独立 systemd 实例

这是 Linux/Python 开发运行包，不是安装程序；本目录不安装数据库、不启动服务、不修改现有 proxy/domain/cert/trust、防火墙、sysctl 或任何既有 service。需要 Python 3.12+ 和**已有 MySQL 8.4 / InnoDB / utf8mb4**。MySQL 客户端用于运维，不是 MySQL Server；不要在这台节点上安装 server 来替代专用 RDS。

## 1. 准备与身份保护

在已批准的独立 release 路径（下例 `/opt/orangespace`）建立 Python venv：

```sh
cd /opt/orangespace/server
python3 -I -m venv .venv
.venv/bin/python -I -m pip --isolated install -r requirements.lock -e .
```

管理员预先提供独立服务账号 `orangespace-node-a` / `orangespace-node-b`；不要重用公网旧节点账号。只有**全新目录**才按部署审批建立为对应账号拥有、0700。现存 files 不重新初始化、不递归 chown，不移动或清理：把 profile 的 `dataRoot` 指向原目录，并先验证其原有 UID/GID、0700 和每个用户 UUID 目录的归属。保留既有 node UUID 和用户 UUID；下面示例 UUID 只是全新实例占位，升级已有节点时必须替换为原 UUID，不能生成新身份覆盖旧身份。两个实例不得共享 files、数据库、tunnel lock/端口池。

将两份 `node-*.runtime.example.json` 复制到独立管理员保护目录 `/etc/orangespace-linux-node/{a,b}/runtime.json`，由对应服务账号拥有、0600（本模板以非 root 账号运行，不能读取 root:root 0600 文件）。配置父目录必须可信、不可被非管理员/非服务账号写入；入口拒绝最终 symlink、硬链接、多余键、重复键、非私密权限、相对路径、非法 UUID/端口及公开监听。profile 最多 64 KiB。不要把本仓库里可公开读取的 example 直接作为运行配置。

字段：`schema=1`、`nodeUUID`、绝对 `dataRoot`、绝对 `dbConfig`；可选绝对 `tunnelConfig` / `federationConfig`，`null` 明确关闭；默认 `listenHost=127.0.0.1`、`listenPort=19091`，B 示例使用 19092。不自动寻找空闲端口，不占用失败后换端口伪装成功：管理员需先确认选择的端口空闲。明文 HTTP 始终只允许回环；可按第 5 节显式增加独立 HTTPS 监听。

`dbConfig` 指向既有 `load_database_url()` 保护 JSON：0600、regular、单链接、root/运行账号所有，只有 `database_url` 键。由管理员通过安全编辑器/secret deployment 写入，不用 shell argv、环境变量、日志、工单或仓库传 DSN/密码。URL 使用 `mysql+pymysql`，RDS TCP 必须 `ssl_ca=/approved/path/rds-ca.pem` 且保持正常主机名校验；仅已有本机测试 MySQL 可用绝对 Unix socket。保留 socket/TLS URL query，不能从 SQLAlchemy engine.url 反向重建配置。禁止 `ORANGESPACE_DATABASE_URL`。

RDS 地址/版本/CA 未提供时本包**不能声称已接通 RDS**。请 DBA 预置 A/B 各自专用库、独立最小权限账号（应用 DML 与迁移 DDL 账号可分离），禁止指向中心库、其他业务库或旧公网节点库。管理员应先正常 TLS 查询 `VERSION()` / `@@default_storage_engine` / SQL mode。当前应用检查及实际验收覆盖 8.4.x、InnoDB、strict SQL mode；实际 RDS 若不是此版本，先按其能力适配应用，不要求更换 RDS，也不取消必要检查。

## 2. 显式迁移、前台启停和 CLI

先确认 database.json 的目标是已批准的专用库。启动只验证 Alembic head，不建表、不自动迁移。MySQL DDL 非事务；现存数据升级需先完成第 4 节专用演练。开发空白隔离库不以前置生产备份为门槛。

```sh
cd /opt/orangespace/server
.venv/bin/orangespace-node-migrate upgrade --database-config /etc/orangespace-linux-node/a/database.json
.venv/bin/orangespace-node-migrate verify --database-config /etc/orangespace-linux-node/a/database.json
# B 独立操作，不把 B 误指到 A：
.venv/bin/orangespace-node-migrate upgrade --database-config /etc/orangespace-linux-node/b/database.json
.venv/bin/orangespace-node-migrate verify --database-config /etc/orangespace-linux-node/b/database.json

# 对应服务账号终端，前台运行；Ctrl-C 或发送该确切 child 的 SIGTERM 正常关闭：
(ulimit -c 0; exec .venv/bin/python -m orangespace_node.runtime --profile /etc/orangespace-linux-node/a/runtime.json serve)
# 第二个终端，可独立启动 B：
(ulimit -c 0; exec .venv/bin/python -m orangespace_node.runtime --profile /etc/orangespace-linux-node/b/runtime.json serve)

curl --fail --silent http://127.0.0.1:19091/healthz
curl --fail --silent http://127.0.0.1:19092/healthz
# 预期 401，不是 200：
curl --silent --output /dev/null --write-out '%{http_code}\n' http://127.0.0.1:19091/v1/files

# 管理入口复用现有 CLI，数据库仍只通过受保护路径读取：
.venv/bin/python -m orangespace_node.runtime --profile /etc/orangespace-linux-node/a/runtime.json admin list-users
.venv/bin/python -m orangespace_node.runtime --profile /etc/orangespace-linux-node/a/runtime.json admin create-user alice
```

create-user 交互私下输入密码，不把密码作为参数；联邦模式禁止用本地密码登录绕过中心授权。不要用 `init-db` 替代迁移；不要 downgrade/base、drop schema 或清表来“修复”旧数据。迁移 head 当前 `node_0002`。healthz 是完成 lifespan 的进程 readiness，不是持续 DB liveness。

本入口单 worker、一次 `create_app`/lifespan/manager，禁用 access log 与代理头信任。startup/shutdown 异常固定脱敏并失败退出，不能因吞错呈现健康。前台启动不 fork、不写 PID、不按进程同名 kill；停止自己启动的确切 child 或使用下述 systemd cgroup。

## 3. 可选独立 systemd 模板（需审批后由管理员安装）

模板名是新 `orangespace-linux-node@.service`，不是覆盖既有服务。示例假设代码 `/opt/orangespace/server`、配置 `/etc/orangespace-linux-node/%i/runtime.json`、可写实例目录 `/var/lib/orangespace-node-%i`。若保留的旧 files 在别处，先修改**这个新实例**的 `ReadWritePaths` 对应现有路径，不递归改所有者、不放宽整个 host。`LimitCORE=0` 仅限本 unit 进程；没有改变 host 限制。

```sh
# 本包没有执行这些安装命令；先审查账号、路径、配置权限和目标实例：
sudo install -m 0644 /opt/orangespace/deploy/linux-node/orangespace-linux-node@.service /etc/systemd/system/orangespace-linux-node@.service
sudo systemctl daemon-reload
sudo systemctl start orangespace-linux-node@a.service
sudo systemctl status --no-pager orangespace-linux-node@a.service
sudo systemctl show -p MainPID -p ActiveState -p SubState orangespace-linux-node@a.service
sudo systemctl stop orangespace-linux-node@a.service
sudo systemctl is-active orangespace-linux-node@a.service # 预期 inactive，退出码非零
# B 完全独立；不使用 wildcard stop：
sudo systemctl start orangespace-linux-node@b.service
sudo systemctl status --no-pager orangespace-linux-node@b.service
sudo systemctl stop orangespace-linux-node@b.service
```

需要开机启动时另行批准后 `systemctl enable orangespace-linux-node@a.service`；默认示例不启用。SIGTERM 由 Uvicorn 正常完成 lifespan shutdown，再恢复信号语义，shell 可能返回 143 / subprocess -15，模板明确接受 SIGTERM。systemd `KillMode=mixed` 与超时作用于自己的 unit/cgroup，不按同名进程扫描。systemd 模板在本轮只做材料审查，不声称实际安装/启动通过。

## 4. 专用库备份、先恢复演练、再迁移/恢复

本节是运维步骤，**本轮没有连接或修改用户 RDS**。先获得准确 endpoint、实际引擎版本、专用 A/B 库名、CA 和 DBA 授权。客户端机器仅需与实际引擎兼容的 `mysql` / `mysqldump`（client，不是 server）；下列选项按已验证的 MySQL 8.4 客户端编写，版本不同时先核对。管理员用安全编辑器准备 0600 `/etc/orangespace-linux-node/backup-client.cnf`：

```ini
[client]
host=YOUR_APPROVED_RDS_HOST
user=DEDICATED_BACKUP_OPERATOR
password=ENTER_VIA_PROTECTED_EDITOR_ONLY
ssl-mode=VERIFY_IDENTITY
ssl-ca=/approved/path/rds-ca.pem
```

client 配置不是应用 database.json；禁止 `-pPASSWORD` / `MYSQL_PWD`。下面 `NODE_A_DB` / `NODE_A_REHEARSAL_DB` 必须替换为 DBA 批准的两个**不同**库；rehearsal 是 DBA 新建的唯一、空白、专用库，不是原库。B 各自重复，不能合库。SQL dump 不使用 `--databases`，避免夹带 `CREATE DATABASE` / `USE` 指回源库。

1. 为一致的 DB+files 截面，在批准窗口只停该新实例，等待写请求与 helper 完全结束；旧线上实例不能擅停。创建 0700 的新备份目录，`umask 077`。备份现有 runtime/db/tunnel/federation 配置、原 node UUID 记录与完整 files，保持 UID/GID、用户 UUID 路径、ACL/xattr。配置/数据库备份含秘密，要加密并访问控制，不向日志输出。

```sh
umask 077
# /approved/new-backup-dir 已是本次独占目录；拒绝覆盖旧备份。
mysqldump --defaults-extra-file=/etc/orangespace-linux-node/backup-client.cnf --single-transaction --no-tablespaces --set-gtid-purged=OFF --triggers NODE_A_DB > /approved/new-backup-dir/node-a.sql
# routines/events 若实际使用，需 DBA 授权后单独 --routines --events 一并备份；本应用不依赖它们。
tar --acls --xattrs --numeric-owner -cpf /approved/new-backup-dir/node-a-files.tar -C /var/lib/orangespace-node-a files
sha256sum /approved/new-backup-dir/node-a.sql /approved/new-backup-dir/node-a-files.tar > /approved/new-backup-dir/SHA256SUMS
sha256sum -c /approved/new-backup-dir/SHA256SUMS
```

检查 mysqldump 和 tar 的实际退出码，任何失败都停止，不以空文件当成功。实际保留的 files 不在示例目录时替换 `-C` 为原父目录，绝不移动原文件。生产优先同时留 RDS snapshot/PITR 点并记录其时间；不要由这个包创建/删除 RDS。

2. **先恢复演练，不在原库试 restore**：DBA 确认 rehearsal 库为空且账号只有其授权；使用同样 VERIFY_IDENTITY client 配置导入，再对 rehearsal 专用 database.json 显式 upgrade/verify。禁止清库和在已有 schema 上覆盖导入。

```sh
mysql --defaults-extra-file=/etc/orangespace-linux-node/backup-client.cnf NODE_A_REHEARSAL_DB < /approved/new-backup-dir/node-a.sql
# rehearsal-database.json 使用 rehearsal 专用凭据/库，保留正常 CA 校验：
/opt/orangespace/server/.venv/bin/orangespace-node-migrate upgrade --database-config /approved/rehearsal/rehearsal-database.json
/opt/orangespace/server/.venv/bin/orangespace-node-migrate verify --database-config /approved/rehearsal/rehearsal-database.json
# DBA/管理员在独立 0700 恢复目录解包，而不是覆盖原 files：
tar --acls --xattrs --numeric-owner -xpf /approved/new-backup-dir/node-a-files.tar -C /approved/rehearsal
```

演练 profile 指向恢复库和恢复 files、原 node UUID，另选空闲回环端口；不与真实节点同时对外发布相同 UUID。验证账号 UUID/行数、session/generation/tombstone 记录、文件数量/摘要和原 UID/GID，启动 health、未认证文件 401，使用专用演练账号完成允许的文件往返，正常停止。记录实际结果；不能仅凭导入退出 0 声称恢复成功。

3. 演练通过后才安排原专用库的显式升级。若需要恢复，优先 DBA 新建空白恢复库或 RDS PITR 新目标，按步骤 2 恢复+验证；只更新批准的实例 database.json 指向恢复目标，保留原库和原 files 只读回退。不要 DROP/TRUNCATE、不要 downgrade、不要在原库覆盖导入；失败时保持停止并交 DBA。文件恢复也先在新目录验证后切换 profile，保留原 UUID/所有者，不将账号名重新映射为新用户 UUID。

## 5. TLS / tunnel 限制与可复现证据

默认版本只启用回环 HTTP。受保护 profile 可显式增加 `tlsListenPort`、绝对 `tlsCertificate` / `tlsPrivateKey`，三者必须齐全；`tlsListenHost` 默认 `127.0.0.1`，只允许显式回环或私有接口，拒绝通配、公网、链路本地和多播监听。HTTPS 端口不能与 HTTP 端口相同。两个监听共享唯一 app/lifespan/manager，停止时一起关闭；明文 probe 仍只在回环。证书和私钥由该隔离环境提供，不能打包私钥或覆盖业务证书。客户端通过显式应用 CA 或正常系统根验证证书链和名称，不使用忽略验证，也不修改系统信任库。没有现有反向代理/域名改动；TLS 入口测试不等于联邦/Windows/TUIC 联合验收。

```json
{
  "tlsListenHost": "127.0.0.1",
  "tlsListenPort": 19094,
  "tlsCertificate": "/etc/orangespace-linux-node/a/tls/fullchain.pem",
  "tlsPrivateKey": "/etc/orangespace-linux-node/a/tls/private.key"
}
```

以上为需要合并到既有 profile 的附加字段，不是完整 profile。B 使用自己的证书/私钥与独立端口，例如 19095。应用私有开发 CA 仅供明确配置它的客户端，不导入系统根。新联邦配置可指定受保护 `ca_file` 来验证开发中心的 HTTPS；缺省仍使用正常系统根，不能填 false。

可把既有受保护 tunnel/federation config 的绝对路径填入 profile，沿用原加载器全部验证，不改授权。启用 tunnel 时其 `probe_port` 必须等于 profile `listenPort`：TUIC 内部探测访问同一 app 的 `127.0.0.1` HTTP，不创建第二次 manager、锁或 lifespan；不匹配就失败关闭。tunnel config 的已有可执行文件哈希、root-owned 路径/lock/证书和独立端口池要求仍然有效（见 `server/TUNNELS.md`）。null 示例只验证文件 API，不是可联网 tunnel 配置。

```sh
cd server
ORANGESPACE_TEST_MYSQL_CONFIG=/absolute/protected/authorized-test-source.json .venv/bin/python -m pytest tests/test_node_runtime_entry.py tests/test_node_runtime_tls.py --assert=plain --tb=short -q
```

测试源只能是批准的隔离 MySQL，不是用户 RDS。复用 conftest 创建 UUID 唯一 schema，保留连接 socket/TLS 选项，显式迁移，finally 精确删除/读回确认自己的 schema，不改变源库已有数据。真实 subprocess HTTP 测试核对 health=200、节点 UUID、文件 unauth=401、profile 管理 CLI、SIGTERM lifespan shutdown、端口关闭，并在失败路径回收确切 Popen child。
