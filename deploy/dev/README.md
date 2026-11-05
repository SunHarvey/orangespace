# Linux 开发控制台入口（不安装数据库、不改反代/Trust）

前提：已安装 `server` Python 包的 Python 3.12+ venv；现有 MySQL 8.4 配置与显式迁移到 control_0006；已构建 `apps/control-console/dist`。配置仅放 owner-only 0600 普通文件，父目录受保护，绝不能放进 dist。服务不会自动建库/迁移/创建账号。

## 前台（优先用于首次诊断）

```sh
/path/venv/bin/python -m orangespace_control.cli --config /private/control.json serve \
  --host 127.0.0.1 --port 19090 --dist /path/release/apps/control-console/dist
```

默认 host=127.0.0.1、port=8090；host/port 独立于数据库地址。首次管理员使用既有 `--config ... bootstrap-admin --username ...`，密码从交互终端/stdin 读取，不放 argv/env。TLS 可加 `--ssl-certfile /private/fullchain.pem --ssl-keyfile /private/key.pem`，必须成对；由 Uvicorn 正常校验证书/私钥，不生成证书、不关闭任何验证、不修改系统 Trust。客户端必须正常信任所配置证书。

## 开发 start / stop / status

Linux、procfs、Python pidfd 支持必需。固定只运行本项目 Control CLI，不接受任意命令，不使用 PID 文件、进程名、killall。

```sh
export ORANGESPACE_CONSOLE_SCOPE=/private/runtime/console-dev
sh deploy/dev/start.sh --python /path/venv/bin/python \
  --config /private/control.json --dist /path/release/apps/control-console/dist --port 19090
sh deploy/dev/status.sh
curl --fail http://127.0.0.1:19090/healthz
sh deploy/dev/stop.sh
```

scope 的父目录必须先存在，scope 必须当前账号所有、0700，不可 symlink；每个实例独占一个 scope。也可直接运行 `python3 deploy/dev/console.py --scope /private/runtime/console-dev start|status|stop ...`。日志在 scope/console.log，按私有文件保护；start/status 仅报告所拥有子进程存活，**不是 HTTP/DB 健康保证**，必须再检查 healthz 与登录 API。healthz 只返回 `{ "status": "ok" }`，代表迁移检查后进程提供服务，不查询 DB 活性、不返回配置/连接串。

后台极小 runner 保存唯一直属子进程及 pidfd，stop 仅向该稳定身份发送 TERM，8 秒后才向同一 pidfd KILL，wait 后返回 stopped；重复 start 拒绝已有 scope。不是 guardian、自动恢复或通用 Node runner。控制 socket 丢失/daemon 被杀意味着身份未知：失败不猜 PID、不扫描/杀同名进程、不自动删除 stale socket。保留 scope/log 后人工核对；生产用 systemd cgroup，而非依赖 dev daemon 承受 SIGKILL。不要把私有 scope 放在公共可写父目录。

同源 API 仍为 `/control/v1/...`。`/` 和已知 SPA 路由（login/nodes/users/enrollments/grants/sessions/sandboxes/leases/audit-events）返回 index；未知路径/API 不 fallback。仅 `/assets/` 下带构建 hash 的 js/css/png/svg/ico/woff 文件可访问；不提供任意文件、JSON、source map、目录列表或外部 symlink。前端目前是 hash router，可直接访问 `/#/users`。

## 未来 systemd 安装（本轮没有执行）

`orangespace-control.service.in` 仅模板。替换全部占位符，使用专用非 root 用户，将 release/venv 放 `/opt/...`、配置放该用户所有的 `/etc/...` 私有目录（ProtectHome 禁止 /root）。确认 MySQL/证书读取权限，独立显式迁移，验证模板后再由管理员安装 unit 到 `/etc/systemd/system/`、daemon-reload、enable --now。模板固定 loopback，不安装 DB、不配置 proxy/域名、不修改 Trust；TLS 参数按需显式追加。停止由 systemd 精确 cgroup 回收，不与 dev scope 混用。同一端口一次只能运行一种入口。

没有数据库、实际 dist 或可用证书时不要把启动成功解释成部署完成。此入口不证明 Windows/WFP/浏览器隔离。
