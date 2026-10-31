# MySQL 开发迁移与验收边界

状态：2026-10-31 开发中的迁移目标，不是生产切换完成声明。服务端业务数据库统一为 MySQL 8.4 LTS / InnoDB / utf8mb4，SQLAlchemy + Alembic；Windows 本机 SQLite、Profile/Cookie 和 Linux 个人目录的位置不变。

## 已识别的源与实际备份

- 旧文件 API SQLite 有 users/access_sessions 两表；两个 V2 测试节点各有五张业务表。备份时这些表均为零行，三个文件根也为空；不存在的表不能报告为零行。
- 三份 SQLite 均通过只读源的 online backup API 备份，再恢复至独立新文件，核验 integrity_check、foreign_key_check、结构和按主键排序的行摘要。独立远端读回验证了备份权限及哈希，传回本地后再次核对全部文件 SHA-256。
- PostgreSQL 17 候选库无用户表，已实际 pg_dump 自定义格式备份、在独立临时库 pg_restore，并比较数据库所有者、编码和规范化结构；精确临时恢复库清理已读回，源库保留。
- 备份包含敏感业务数据的可能性，不进入 Git。容器0700、备份0600；具体机器、源库路径、工具版本、哈希、PID/健康和恢复回执保存在受保护运维证据中。
- SQLite 数据库快照与文件区统计不是跨资源原子快照。本次运行实例没有停写/排空或切换，这里只记录历史事实，不据此启动新的运维计划。

## 目标连接与迁移

运行时仅接受 `mysql+pymysql`，拒绝 SQLite/PostgreSQL URL。通过受保护 JSON 的 `database_url` 加载秘密，环境变量只保存文件路径。使用本机 Unix socket，或显式可信 CA、正常名称验证的 TLS；不允许通过 URL 关闭校验。运行账号使用最小 DML 权限，迁移账号另有必要 DDL 权限。

会话隔离为 READ COMMITTED，参数隐藏；连接校验 MySQL 8.4 / InnoDB / 严格 SQL mode。表显式 utf8mb4_0900_bin，验证 NO PAD、大小写、重音、尾空格、唯一约束和外键。epoch/generation/时间为足够宽的整数，协议仍限制安全整数边界。generation 与 tombstone 不因删除账号级联清除。

节点显式操作：

```sh
orangespace-node-migrate upgrade --database-config /etc/orangespace/database.json
orangespace-node-migrate verify --database-config /etc/orangespace/database.json
```

节点 head 为 `node_0002`，中心 head 为 `control_0006`。在 `server` 目录执行 `alembic -c alembic-control.ini -x config=/etc/orangespace/control.json upgrade head`，中心配置只传受保护文件路径。服务启动只校验已迁移版本，不执行 create_all。MySQL DDL 有隐式提交，不能把失败 DDL 说成事务自动回滚。当前 schema downgrade 测试只在明确提供的可丢弃测试库执行，不是带业务数据的生产回滚方案。

## 必须保持的身份归属

1. 中心永久用户 UUID 与节点 legacy UUID 分开；不能按同名账号合并，不通过直接替换 UUID 迁移。
2. 离线导入必须逐节点保留原 user UUID、密码哈希、session 摘要/撤销状态、grant epoch、最大 generation、tombstone，以及原个人目录映射。新中心映射须显式审查。
3. Windows 旧 workspace owner、profile/cache/tasks 路径不改名；新增受审映射 sidecar，不足以证明归属的记录隔离处理。
4. 原库和原文件完整保留。当前备份/恢复完成不代表离线 SQLite/PG→MySQL 导入器、非空数据冲突处理和正式切换已经完成。

## 开发范围

保留原库、原 UUID 和文件归属；历史备份事实不变。用户已取消把备份/恢复演练、生产切换或回滚规划作为当前开发前置；此处不再安排这些运维工作。离线导入器未完成不能描述为已经迁移现有实例。

## 已实际执行与仍缺的验收

- 真实 MySQL 8.4.13：严格工厂、Node Alembic、InnoDB/NO PAD、唯一/FK、反重放历史保留及 schema 往返测试通过。
- 原节点认证、个人文件共享/隔离、目录/上传/下载/Range/撤销及描述符清理等38项，已在真实 MySQL 的独立 schema 通过。
- 中心管理员初始化、登录、用户增改、密码重置、会话失效/跨用户拒绝/分页与管理员审计初始测试通过。前端构建/单元测试不等于浏览器与 Windows 联合验收。
- 最新本地完整套件：真实 MySQL 8.4.13 + approved sing-box 1.14.4，258 passed、0 skipped、0 failed、17 warnings，945.39 秒；包括中心/节点 ASGI、联邦授权及真实本地 TUIC 撤销边界，详见 server/TUNNELS.md。不是已部署声明。
- 仍缺非空历史数据离线导入/冲突处理，以及 Windows 独立平台授权、WFP 与完整数据面联合验收；不以生产切换/回滚待办阻塞开发。
- CI 定义已改向 MySQL；只有推送后相同提交的真实 GitHub CI 成功才能认定发布验证，不使用历史 PostgreSQL CI 替代。

浏览器门禁保持关闭。控制面、文件 API 或 TUIC 通过都不构成 WFP、DNS、CEF sandbox 或完整文件桥证明。
