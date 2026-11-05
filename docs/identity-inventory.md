# 节点库存证明与身份映射（开发入口）

本入口只证明本节点 MySQL 中存在指定本地用户主键，并将其提交给中心供管理员明确审批。它不自动创建用户、不按用户名合并、不更改 UUID 或个人目录，不签发浏览器/隧道授权。

## 前提

- 使用已经完成持钥注册且由管理员激活的节点机器身份。
- 在对应节点的操作系统服务身份下，加载其正常 `ORANGESPACE_NODE_ID`、`ORANGESPACE_DATABASE_CONFIG` 和数据根配置。数据库连接秘密仍只在受保护配置文件中。
- 机器配置文件是普通非符号链接文件、只有一个硬链接、所有者为当前执行身份，且无组/其他用户权限；最大 16 KiB。字段仅为 `origin`、`token`、`node_id`、`node_epoch`、`config_revision`。`origin` 为中心 HTTPS origin，`token` 为节点机器 Bearer，不能换用管理员/普通用户 token。
- 机器配置的 `node_id` 必须与节点运行配置一致。禁止把另一节点的机器配置与本节点数据库混用。

## 提交指定真实本地主键

在既有节点运行配置已经加载的环境中：

```sh
orangespace-node publish-identity-evidence \
  --machine-config /etc/orangespace/control-machine.json \
  --legacy-user-id '<本节点既有 canonical UUID>' \
  --request-id '<本次操作的 canonical UUID>'
```

尖括号内容是占位符，不能原样运行。命令行只接受配置路径及公开标识，不接受密码或 token。先在本地 MySQL 精确查询该主键；不存在则不发送 HTTP。生产 HTTP 客户端保持正常 TLS 校验、禁止重定向且不继承代理环境。

成功输出仅有 `schema`、`evidence_digest`、`expires_at`，不打印机器凭据。超时或失败时保留原 `request_id` 重试；中心返回原证明，不延长其原有效期，也不允许变更对应身份。过期证明不能用于新审批。

## 中心批准

1. 管理员创建映射提案，显式提供中心用户、节点、本地主键、中心已记录的证明摘要及理由。
2. 提案保持 `pending`；即使已有节点 grant，也不进入普通用户的获授权节点列表。
3. 管理员使用预期 `mapping_epoch` 和同一证据摘要批准。中心重查证明有效期以及节点 key/epoch/config 状态。
4. 批准后仍需有效 grant、启用用户及 active 节点，才会出现在用户目录。已有映射不能转让给另一中心用户。

## 验收边界

当前本机测试使用真实 MySQL，实际执行本地主键查询及节点提交模块；中心交互使用进程内 ASGI transport。CLI 的传输单元测试使用 HTTP 替身，验证配置读取、实际数据库查询和命令接线。这些不是远端 HTTPS 部署、自动心跳接入、Windows Service 授权或实际转发/撤销验收。
