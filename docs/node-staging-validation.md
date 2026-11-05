# Linux 隔离测试节点验证

## 范围

这是用户授权机器上的**开发／测试节点**，不是生产 PostgreSQL 部署，也不是已对 Windows 开放的 HTTPS 节点。没有运行 Linux 浏览器、传输远程画面、打开公网文件 API 或改动 SSH/防火墙。真实地址、密钥和节点配置不进入仓库。

## 已部署及独立读回

- Rocky Linux 9.5 x86-64，官方系统包 Python 3.12.15。
- systemd 单元 `orangespace-node-test.service`，active/enabled；专用 `orangespace-test` nologin 用户。
- 仅 `127.0.0.1:8080`，一个 uvicorn worker，关闭访问日志，保留 systemd 限权。
- `/etc/orangespace-test/node.env` 为 root:root `0600`；状态及个人区由服务用户持有，`0700`；数据库 `0600`。
- 当前源代码基于 `d1b714b9d2b43fb4ef217cb734d9006712969483`，版本化发布目录后缀 `-pypi`。父流程核对 16 个 server 文件及依赖闭包测试，共 17 文件，均与该提交哈希一致。
- 单元文件 SHA-256：`a45e51a23feef6af5b06a4efe5e78783851a35f410ab6639f14bf98ed67bd1c2`。
- SQLite **仅用于此测试实例**。稳定节点 UUID、配置和数据库在重建时保留；当前用户、会话、个人区文件均为 0。
- `/healthz` 为 200，实际响应节点头与受保护配置一致；运行路径已读回到新发布目录。

## 来源修正

初次安装发现宿主机 pip 默认使用 HTTP 镜像，原 requirements.lock 还漏锁了 Linux SQLAlchemy 必需的 greenlet。这是来源验证缺口，**不是已发现入侵的证据**。

已新增平台条件的 `greenlet==3.5.6` 精确锁和运行时／测试依赖闭包回归，观察到缺锁 RED 后修正为 GREEN。节点使用系统 Python 重新创建全新 venv，禁用继承的 pip 配置、额外索引及不安全来源，只从官方 HTTPS PyPI 下载第三方 wheel。没有复制旧 venv。

安装报告中的 35 个唯一第三方发布资产（包含构建工具）均与官方 PyPI 发布 JSON 的 SHA-256 和 URL 匹配；父流程从独立机器重新请求官方元数据，逐项复核通过。旧的、已不被进程引用的 HTTP 安装 venv 已删除，旧源码保留。

这是**实际下载来源与摘要核验**，并非完整可复现构建：构建后端工具曾动态选择，Hatchling 为 1.33.0，editable 后端另需 editables 0.6；系统 ensurepip 提供 pip 23.2.1。requirements.lock 的运行时版本闭包检查也不等于每个平台的哈希锁或构建工具哈希锁。

## 实际测试

- 初次部署通过真实 HTTP 登录／身份、同用户多会话共享、两个账号隔离、1 MiB 二进制上传下载／摘要、Range、冲突和退出撤销检查。测试凭据仅在内存中生成，不借用 SSH 密码，不输出到日志。
- 父流程在重建后的新 venv、真实部署源码下重新以非 root 用户执行：`pip check` 通过；服务端测试 **37 passed / 1 skipped**；依赖闭包测试通过。
- 跳过的是未在此节点配置的 PostgreSQL 集成测试，不能声称该节点 PostgreSQL 已验收。CI 的独立 PostgreSQL 测试结果另记。
- 保留一个第三方 Starlette TestClient 弃用警告。测试 fixture 均在个人区之外，结束后检查清理；当前线上库用户／会话和个人文件计数读回为 0。

父流程调用 runuser 时使用可读的发布目录作为 cwd，避免从 `/root` 启动导致 pytest 结束时 chdir 权限失败。该问题属于验证命令环境，不修改服务授权来绕过。

## 证据与回滚边界

来源报告、官方元数据、单元／数据库备份和验证记录保存在节点 root-only 证据目录，不对外发布，不把数据库备份复制进仓库。重建只切换测试单元的精确运行路径并重启此单元，原有 SSH 和其他服务保持不变。初次安装 Python 时系统包管理器因依赖更新了 OpenSSL/sqlite 相关库；没有执行全系统升级，也不盲目回退这些系统依赖。

停止测试实例可使用：

```sh
systemctl disable --now orangespace-node-test.service
```

不要为“清理测试服务”而删除稳定配置、数据库或个人区；正式卸载／回滚必须先确认数据范围。

## 尚未完成

可信公网 HTTPS 入口、成功的 Windows HTTPS 登录、生产 PostgreSQL、Windows 服务与 helper 的完整授权链，以及 WFP/TUIC/DNS/抓包验收均不由此部署证明。文件 API 仍只监听回环；在可信入口确定前不暴露明文接口，不关闭客户端证书验证。
