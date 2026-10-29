# OrangeSpace Linux 节点文件服务

已实现可运行的个人文件 API、多用户本地账号、会话认证和文件系统隔离。它不运行浏览器，不存储浏览器 Cookie，也不负责 TUIC 数据转发。后续 Windows 文件面板及浏览器上传下载桥通过这里的 API 读写文件。

## 运行

生产目标为 Linux、Python 3.12+、PostgreSQL。macOS 可以运行文件服务测试；Windows 不支持这里的 POSIX 目录操作。

```sh
cd server
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock -e '.[test]'
```

为专用的非 root 系统账号准备 `/var/lib/orangespace/files`（权限 0700），设置 `.env.example` 中的环境变量。程序不会自动读取 `.env` 文件；由部署工具或 systemd 的 `EnvironmentFile` 注入环境。不要将真实密码写进版本库。

```sh
.venv/bin/orangespace-node init-db
.venv/bin/orangespace-node create-user alice
.venv/bin/uvicorn orangespace_node.app:create_app --factory --host 127.0.0.1 --port 8080 --workers 1
```

`create-user` 在终端私下读取密码并要求重复输入，没有公开注册接口。账号名为 3–64 位 ASCII 字母、数字、`_`、`.`、`-`，不区分大小写；密码为 12–1024 个字符。密码使用 Argon2id 哈希。

仅把 API 绑定到回环地址，由 Caddy 提供外部 HTTPS。API 不启用跨域访问，不使用浏览器 Cookie 认证。反向代理要限制连接、请求体大小、上传超时和登录频率。当前程序内登录限流属于单进程，并最多同时进行 4 个密码验证；部署示例使用一个 worker，多个实例必须额外使用共享限流设施。

开发时可将数据库设为 `sqlite:////absolute/path/node.sqlite3`，并使用位于本机私有目录内的数据根目录。SQLite 仅作为开发/测试选择。

## API

除 `/healthz` 和登录外，全部接口要求 `Authorization: Bearer <token>`。文件路径为用户根目录下的相对路径；不得传本机路径或其他用户 ID。接口响应和 `X-OrangeSpace-Node` 响应头都标识当前节点。客户端应核对预期节点身份，不能仅依赖显示名称。

| 方法和地址 | 请求 | 返回 |
|---|---|---|
| `POST /v1/auth/login` | JSON：`username`、`password` | `access_token`、`token_type`、`expires_at`、`node_id` |
| `POST /v1/auth/logout` | 无 | 204，撤销该 token |
| `GET /v1/me` | 无 | `user_id`、`username`、`node_id` |
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

设置 `ORANGESPACE_TEST_POSTGRES_URL=postgresql+psycopg://...` 后，`tests/test_postgres.py` 会额外验证 PostgreSQL 真库上的初始化、用户名唯一约束、登录与会话撤销、文件 API 用户隔离。未设置时明确跳过。测试账号需要创建 schema 的权限；测试为每次运行创建一个随机命名的独立 schema，通过连接 `search_path` 使用它，结束时仅删除该 schema。不会重置整个数据库或其他应用的表。CI 应使用专用测试实例，数据库凭据通过 CI 环境注入。

当前数据库初始化只创建首版表；更改已有数据库结构前需要增加版本化迁移。尚未包含总用户存储配额、集中身份管理、跨节点同步、断点上传或外部审计日志。PostgreSQL 的驱动和模型已就绪，是否完成 PostgreSQL 真库验证应以 CI/部署验证记录为准，不能由 SQLite 测试推断。
