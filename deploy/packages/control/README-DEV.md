# OrangeSpace 管理控制台开发运行包

干净源码重建命令、离线依赖 pin/cache 校验及 manifest v2 规范见仓库 `deploy/packages/README.md`；入口为 `python3 deploy/packages/build.py control --deps /absolute/reviewed-dependencies --output /absolute/output/control-dev.tar.gz`。历史 ACCEPTANCE 不会被继承到新构建。

这是 Linux 开发包：含实际前端构建、后端 wheel、锁定依赖清单和本项目启停脚本。不是 Windows 客户端、正式安装器或已接入 RDS 的证明。不安装 MySQL，不修改反向代理、域名、证书、系统信任库或其他服务。

## 1. 安装到独立目录

需要 Linux、Python 3.12+（本包在 Python 3.13 验证）、venv、procfs 和 pidfd 支持。先将归档解压到一个新目录，在该目录执行：

```sh
python3 -I -m venv .venv
.venv/bin/python -I -m pip --isolated install \
  -r server/requirements.lock server/orangespace_node-0.1.0-py3-none-any.whl
```

`-I` 和 pip `--isolated` 避免宿主 PYTHONPATH/用户 pip 配置让依赖误判为已安装。本包不含虚拟环境，不会修改 Hermes 或其他项目的 Python 环境。没有安装所需工具时先补充对应开发主机依赖，不运行自动系统安装器。

## 2. 配置专用数据库与显式迁移

复制 `examples/control.example.json` 到包目录之外的私有目录，目录 0700、配置普通文件 0600 且属于运行用户；修改为获准使用的中心 RDS 库。URL 中用户名和密码必须正确 URL 编码，不放 argv、环境或日志。默认 TCP 连接仍要求 `ssl_ca` 并正常验证证书链和主机名；只有管理员明确选择普通 MySQL 时，才在受保护的 `database_url` 查询中加入大小写精确的 `ssl_mode=DISABLED`。该选项不能与 `unix_socket`、`ssl_ca`、`ssl_cert` 或 `ssl_key` 混用；旧 `ssl_disabled=true` 查询参数仍被拒绝。普通连接只作用于数据库，不降低应用 HTTPS、Node 身份验证或 Windows 浏览器隔离。可单独使用 DDL 迁移账号，运行服务改用本项目专用 DML 账号。

**支持 MySQL 8.0.36 及更高的 8.0 补丁版、MySQL 8.4；仍要求 InnoDB、utf8mb4、严格 SQL 模式和 READ COMMITTED，连接字符比较使用 `utf8mb4_0900_bin`。** 拒绝 MariaDB、旧版及未经支持的版本分支，不能通过删除检查适配。实际 RDS 的连接、权限、已有数据和迁移结果须按准确源码及部署报告分别核验，不能把包构建成功当作已上线。不创建其他库、不修改 RDS 实例参数或安全组；有数据时先核对现有 revision、UUID、账号与授权归属，再执行经确认的中心迁移，不能清库重建，也不混跑 Node 迁移。

```sh
# CONFIG 只含文件路径，不含连接串或密码。
CONFIG=/your/private/control.json
.venv/bin/python -I -m alembic -c server/alembic-control.ini \
  -x config="$CONFIG" upgrade head
.venv/bin/python -I -m alembic -c server/alembic-control.ini \
  -x config="$CONFIG" current
# 预期 control_0006。启动只核验版本，不自动执行 DDL。
```

配置不在包中；示例 `mysql.example.invalid` 不是真实服务器。当前开发机使用独立本机测试 MySQL，不是用户 RDS。

## 3. 初始化管理员

```sh
.venv/bin/python -I -m orangespace_control.cli --config "$CONFIG" \
  bootstrap-admin --username your-admin-name
```

密码由私有交互提示读取，不放 argv、环境、脚本或日志。没有默认账号。已有管理员时拒绝重复初始化，不重置用户。开发环境自动生成的登录信息单独保存在该环境的受保护文件中，**不会进入此包**。

## 4. 启动、状态与停止

```sh
# 包外的独立私有运行目录；不要复用其他服务目录。
install -d -m 700 "$HOME/.local/state/orangespace"
export ORANGESPACE_CONSOLE_SCOPE="$HOME/.local/state/orangespace/console-dev"
env -u PYTHONPATH -u PYTHONHOME sh deploy/dev/start.sh \
  --python "$PWD/.venv/bin/python" --config "$CONFIG" \
  --dist "$PWD/apps/control-console/dist" --host 127.0.0.1 --port 19090
env -u PYTHONPATH -u PYTHONHOME sh deploy/dev/status.sh
curl --fail http://127.0.0.1:19090/healthz
# 本机浏览器打开 http://127.0.0.1:19090/#/login
env -u PYTHONPATH -u PYTHONHOME sh deploy/dev/stop.sh
```

默认只监听回环；不是公网入口。从其他电脑访问须建立获准的开发端口转发，或以后在独立管理服务器配置有效 HTTPS，不能直接把回环 URL 当远程地址。TLS 可显式传 `--ssl-certfile` 和 `--ssl-keyfile`，必须成对；客户端正常验证证书，不导入或修改系统信任库。本包无自动签发证书行为。

start/status 仅表明精确直属子进程存活，HTTP healthz 仅表明进程可服务，均不代表 RDS 持续活性或隧道转发。必须实际登录验证。scope/console.log 为私有日志；不得把受保护配置复制进去。控制 runner 被强杀或 scope 异常时保留现场，不按进程名/PID猜杀；生产部署使用包内 systemd 模板。

## 5. 当前可操作与未接通项

- 管理员登录、创建/禁用用户、密码重置；最后一个管理员保护由后端执行。
- 创建节点注册挑战、查看待核验节点、审核激活/停用；节点仍须通过自己的签名注册及独立部署核验，不能仅填 UUID 获得信任。
- 创建/修改/撤销用户节点授权；新账号仍需显式节点本地身份映射，不按用户名自动合并。
- 查看会话、审计和中心 permit 签发历史；普通用户不能读取他人记录。
- permit 的 issued/expired 不是 helper 实时状态或转发证明。中心精确单租约停止尚未接通，按钮明确禁用；Windows 通过自己的精确 Node 租约停止。
- 中心沙盒面板明确未接通；沙盒 SQLite/Profile 仍在 Windows，由 Windows 客户端管理。
- WFP/DNS、完整浏览器和文件桥未完成；不能据本包开启浏览器联网。

## 6. 未来独立管理服务器

使用 `deploy/dev/orangespace-control.service.in`，替换专用用户、release/venv、私有配置路径，先显式迁移/初始化，再安装本项目独立 unit。服务只连 RDS；不要在管理台主机安装数据库。模板不修改既有代理/域名/证书，不自动安装 unit。详细启停与范围见 `deploy/dev/README.md`。

`BUILD-MANIFEST.json` 的 `source_commit`、工具/依赖版本和 `SHA256SUMS` 标明这份包的准确来源；以该提交的实际 CI 和另行绑定程序哈希的运行报告为准，不借用较早提交或旧包的验收结果。构建清单默认为 build-only，不自动继承 GUI 或部署成功。
