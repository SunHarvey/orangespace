# Linux Node 入口本轮验证（2026-10-31 UTC）

仅本轮 Linux 回环/隔离 MySQL 证据，不代表 RDS、systemd 实机、生产 TLS、联邦全链路、Windows 或 TUIC 验收。

## TDD 实际执行

- profile 首次测试：`ModuleNotFoundError: orangespace_node.runtime`，**1 failed**；加入最小 profile 解析后 **1 passed**。
- profile 安全边界：对 public/symlink/hardlink/directory/oversized/duplicate/unknown/relative/bad-schema/boolean-port/public-host/bad-uuid/embedded-secret，实际 **13 failed, 1 passed**；加入 fail-closed 保护后 **14 passed**。
- 前台 subprocess 与启动错误：入口尚无 main 时，实际 **2 failed, 14 passed**（原进程退出 0、未监听）；实现入口后 **16 passed**。
- 增加第二节点身份的真实 HTTP 覆盖后，最终独立文件 **17 passed, 1 warning in 12.91s**，未跳过。

测试命令（只传批准的本机测试 MySQL 配置路径，不含秘密）：

```sh
cd /root/projects/orangespace/server
ORANGESPACE_TEST_MYSQL_CONFIG=/var/lib/orangespace-dev-9648a84736d5/node-a/database.json .venv/bin/python -m pytest tests/test_node_runtime_entry.py -q -rP
```

真实 HTTP 输出：

```text
HTTP receipt node=4eef0765-2443-4879-badb-02967baac185: health=200 files_unauth=401 admin=0 shutdown=complete port=closed files_owner=preserved
HTTP receipt node=f6224bf7-a363-43fb-8c0b-417794c91b7a: health=200 files_unauth=401 admin=0 shutdown=complete port=closed files_owner=preserved
```

两次分别使用新 UUID schema，复用 `mysql_config_path` fixture 明确 upgrade，finally 精确 drop/查询确认自己 schema 消失。未更改源 node-a 库的已有数据。两次前台 Popen 均已停止/等待退出，监听关闭，原 marker 内容与 UID/GID 不变；未遗留 daemon。允许 Uvicorn 完成 shutdown 后重新抛 SIGTERM，因此退出 0 或 -15 均需同时满足 shutdown 日志和端口关闭，不把超时/强杀当正常停止。

## 邻接回归

```sh
ORANGESPACE_TEST_MYSQL_CONFIG=/var/lib/orangespace-dev-9648a84736d5/node-a/database.json .venv/bin/python -m pytest tests/test_node.py tests/test_mysql_node_runtime.py tests/test_identity_cli_errors.py tests/test_node_runtime_entry.py -q --tb=short
```

实际：**62 passed, 2 warnings in 148.80s**，无跳过；警告是已有 Starlette/httpx 弃用提示、Pydantic `schema` 字段覆盖属性提示。不是完整 server 258 项回归。

`compileall` 对新入口/测试通过。systemd 模板原路径 `/opt/orangespace/server/.venv/bin/python` 在本机未安装，直接 verify 诚实报告 executable missing；只在临时副本替换 release 路径为当前实际源码/venv 后 `systemd-analyze verify` **exit=0**，临时副本删除。没有安装 unit、daemon-reload 或启动 systemd service。

## 限制

- 只有 `127.0.0.1` HTTP；默认19091，B示例19092。不是自带 TLS 入口，不生成/修改 cert、trust、proxy、域名。
- null tunnel/federation 示例为文件 API 启动，不冒充 tunnel/联邦联合验收；启用既有 tunnel config 要求同一 app 的 HTTP probe 端口一致。
- 未连接 RDS、未备份/恢复用户库；提供专用库、正常 VERIFY_IDENTITY、备份/新空白库恢复演练与保留旧库/原 UUID/files 的具体运维步骤。
- 没有 commit。仅新建入口、测试、本目录部署材料；既有 app/tunnels/federation/control_identity 未修改。
