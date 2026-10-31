# OrangeSpace Linux 节点文件服务

已实现可运行的个人文件 API、多用户本地账号、会话认证和文件系统隔离。新增默认关闭、管理员明确逐用户授权的短租约 TUIC 控制面和每租约独立 sing-box；设置、接口、部署前提及验证边界见 [TUNNELS.md](TUNNELS.md)。它不运行浏览器，不存储浏览器 Cookie；登录本身不授权联网。后续 Windows 文件面板及浏览器上传下载桥通过这里的文件 API 读写文件。

## 运行

服务端目标为 Linux、Python 3.12+、MySQL 8.4 LTS / InnoDB / utf8mb4；节点与中心使用 SQLAlchemy 和显式 Alembic 迁移。Windows 本机沙盒元数据仍用 SQLite。旧服务端 SQLite/PostgreSQL 只保留为受控迁移源，不提供运行时回退；Windows 不支持这里的 POSIX 文件操作。

```sh
cd server
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock -e '.[test]'
```

为专用的非 root 系统账号准备 `/var/lib/orangespace/files`（权限 0700），设置 `.env.example` 中的环境变量。程序不会自动读取 `.env` 文件；由部署工具或 systemd 的 `EnvironmentFile` 注入环境。不要将真实密码写进版本库。

```sh
.venv/bin/orangespace-node-migrate upgrade --database-config /etc/orangespace/database.json
.venv/bin/orangespace-node-migrate verify --database-config /etc/orangespace/database.json
.venv/bin/orangespace-node create-user alice
.venv/bin/uvicorn orangespace_node.app:create_app --factory --host 127.0.0.1 --port 8080 --workers 1
```

以上为非联邦本地密码模式的 CLI 示例。`create-user` 在终端私下读取密码并要求重复输入，没有公开注册接口。配置 `ORANGESPACE_FEDERATION_CONFIG` 后必须成功加载受保护联邦配置，否则启动失败；联邦模式关闭本地密码登录，旧本地会话不能绕过联邦验证。账号名为 3–64 位 ASCII 字母、数字、`_`、`.`、`-`，不区分大小写；密码为 12–1024 个字符。密码使用 Argon2id 哈希。

仅把 API 绑定到回环地址，由 Caddy 提供外部 HTTPS。API 不启用跨域访问，不使用浏览器 Cookie 认证。反向代理要限制连接、请求体大小、上传超时和登录频率。当前程序内登录限流属于单进程，并最多同时进行 4 个密码验证；部署示例使用一个 worker，多个实例必须额外使用共享限流设施。

`ORANGESPACE_DATABASE_CONFIG` 只指定受保护 JSON 文件路径；该文件仅包含 `database_url`，权限0600并属于运行账号/受信管理员，不将 DSN 或密码放入环境变量。连接必须使用本机绝对 Unix socket，或指定可信 CA 并正常校验名称的 TLS。运行时拒绝 SQLite/PostgreSQL URL；启动只校验迁移版本，不自动建表。保留旧库、原 UUID 和个人目录；开发不以前置备份/恢复演练或生产切换为门槛，不得用初始化替代迁移。

## API

除 `/healthz`、登录和独立授权的 loopback tunnel probe 外，接口要求 Bearer 认证，请求头格式为 `Authorization: Bearer <access-token>`。文件 owner 由已认证的节点身份确定，不能用调用者任填的用户 ID 替代。响应和 `X-OrangeSpace-Node` 头标识当前节点；客户端必须核对预期身份。

| 方法和地址 | 请求 | 返回 |
|---|---|---|
| `POST /v1/auth/login` | JSON：`username`、`password` | `access_token`、`token_type`、`expires_at`、`node_id` |
| `POST /v1/auth/logout` | 无 | 204，撤销该 token |
| `GET /v1/me` | 无 | `user_id`、`username`、`node_id` |
| `GET /v1/session` | 无 | `user_id`、`username`、`node_id`、实际 `expires_at` |
| `/v1/tunnels` 生命周期 | 单独管理员 grant；默认关闭 | 见 [短租约接口](TUNNELS.md) |
| `GET /v1/files?path=` | 空路径表示个人文件区根目录 | `node_id`、`path`、`entries` |
| `POST /v1/directories` | JSON：`path` | 201，目录元数据；父目录须存在 |
| `PUT /v1/files/{path}` | 原始文件字节，不是 multipart | 201，元数据和 SHA-256；只有成功提交才返回成功 |
| `GET /v1/files/{path}` | 可选单个 `Range: bytes=start-end` | 文件字节，支持 200/206/416 |
| `DELETE /v1/files/{path}` | 无 | 204；目录必须为空，不递归删除 |

上传默认拒绝覆盖，冲突返回 409。明确选择覆盖时使用 `?overwrite=true`，整个文件上传成功后才原子替换原文件。文件元数据包含 `name`、`kind`、`size`、`modified_at_ns`；目录的 `size` 为 `null`。上传响应另含内容的 `sha256`。

文件最大值默认为 1 GiB，可配置；即使未发送 `Content-Length`，仍在流式接收时计数。最多同时处理 8 个上传，其余返回 429。超过大小返回 413，存储空间不足返回 507。失败或取消不会发布半个文件。单文件上传尚不支持分片续传；下载支持单区间字节读取。

Windows 客户端必须把文件任务绑定到创建时的 `node_id`、认证账号及沙盒任务目录。浏览器完成写入 Windows 临时文件后，才流式提交至本接口；收到 201 并核对大小、摘要与节点后才可标记任务已完成。浏览器文件选择器选中的远端文件，也先由客户端下载到该沙盒的临时目录。这个客户端桥接流程尚未由本服务单独实现。

## 用户与文件隔离

认证用户的 UUID 决定其服务器目录：`<data_root>/<user_id>/`。同一账号在同一个节点的多个沙盒共享该目录，不同账号各有目录。API 不接受一个可改写身份的 `user_id` 字段。用户不能通过指定路径进入另一个用户的根目录。

访问路径逐段通过目录描述符打开，使用 `O_NOFOLLOW` 拒绝符号链接；下载拒绝管道、设备和额外硬链接。路径不接受绝对路径、`..`、反斜杠、控制字符，最多 64 层；目录描述符避免先校验路径再打开文件的常见竞态。上传临时文件与目标位于同一目录，提交前刷盘，创建文件时使用原子 create-if-absent，显式覆盖时使用原子替换。

这是应用层目录授权，不是每用户 Linux 容器或独立 Unix 账号。专用服务账号拥有整个文件树；不要把该账号的 SSH、其他进程执行权限或数据目录写权限交给 API 用户。配置的数据根目录及其上级必须由受信任管理员管理。数据根目录、个人根目录要求服务账号拥有且权限 0700。不要把 API 上传目录作为可执行的 Web 站点目录。

文件名以 `.orangespace-upload-` 开头保留给内部暂存。正常失败会立即清理；进程崩溃后暂存可能残留，可由服务账号定期执行：

```sh
.venv/bin/orangespace-node cleanup-uploads --older-than-hours 24
```

清理仅删除符合内部格式、已超过年龄阈值且没有活动文件锁的暂存文件，不会跟随符号链接。最短阈值为一小时；后台清理不是 API 用户可以调用的接口。

其他管理命令：`list-users`、`disable-user <name>`、`enable-user <name>`、`set-password <name>`、`revoke-sessions <name>`。禁用账号、重设密码会撤销已有会话。token 是 256 位随机不透明值，数据库只存 SHA-256 摘要，默认 8 小时过期。撤销和禁用阻止后续请求；已经开始的传输不会被强制中途打断。

## 验证与边界

```sh
.venv/bin/python -m pytest -q
```

测试覆盖不同账号互相隔离、同账号多会话共享、路径穿越、符号链接、特殊文件、上传中断/大小限制/竞态、原子覆盖、摘要、Range、token 摘要/失效/撤销、禁用账号、登录限流、崩溃暂存清理。

真实数据库测试设置 `ORANGESPACE_TEST_MYSQL_CONFIG=/private/node-test.json` 和 `ORANGESPACE_CONTROL_TEST_CONFIG=/private/control-test.json`（只传路径，不传 DSN）。测试使用专用 MySQL 8.4 实例；每例/模块创建唯一自有 schema、显式迁移，并精确删除自己的 schema；提供的源数据库不重建。测试账号需要相应临时 schema 创建权限。未配置真库明确跳过；部署/CI验收不得把跳过算通过。历史名称 `test_postgres.py` 当前内容已改为 MySQL 文件 API 验收，不再测试正式 PostgreSQL 运行。

当前源码仅支持 MySQL 正式运行，节点迁移 head 为 `node_0002`，中心为 `control_0006`。中心在 `server` 目录通过 `.venv/bin/alembic -c alembic-control.ini -x config=/etc/orangespace/control.json upgrade head` 显式迁移；节点 upgrade/verify 见上文。启动只检查版本，不自动迁移。

最新本地完整验证：真实 MySQL **8.4.13** 与已核验 sing-box **1.14.4**，**258 passed、0 skipped、0 failed、17 warnings，945.39 秒**。包含中心/节点 ASGI 与真实本地 TUIC 夹具，不能推断已部署、生产 HTTPS、Windows/WFP 或完整阶段验收。CI 必须在推送后按精确提交另查，不以本地通过替代。迁移边界见 [迁移说明](../docs/mysql-migration.md)，统一身份接口见 [控制面契约](../docs/control-plane-contract-v1.md)。
