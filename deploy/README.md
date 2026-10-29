# Linux 节点部署草案

目标系统 Ubuntu 24.04 LTS。以下配置是开发部署材料，不是已经验收的生产安装器；当前 Windows 浏览器防护和文件桥尚未完成。

## 文件服务

1. 创建独立非 root 服务账号 `orangespace`，将代码和 Python 虚拟环境安装到 `/opt/orangespace`；用 `server/requirements.lock` 固定依赖。
2. 为 PostgreSQL 创建独立数据库和账号；SQLite 仅用于本机开发/测试。配置 `server/.env.example` 为 `/etc/orangespace/node.env`，限制读取权限。**每个节点生成自己的 UUID，并在升级时保留。**
3. `/var/lib/orangespace` 和 `files` 目录归服务账号所有，权限 0700。运行同一环境下的 `orangespace-node init-db`，再交互式 `create-user`，密码不放命令行参数。
4. 安装 `orangespace-node.service`，先手工检查环境和账号权限；API 只监听 `127.0.0.1:8080`。本仓库不自动改动现有服务器。
5. Caddy 设置 `ORANGESPACE_API_DOMAIN`，使用有效 DNS 和证书提供 HTTPS。仅开启 TCP HTTP/1.1、HTTP/2，让 UDP 443 留给 TUIC。反向代理和应用均避免记录认证头和令牌。

个人根目录来自 token 中的认证用户，客户端不能指定其他用户根。文件权限隔离是应用认证和文件系统访问校验，不是给每个用户启动容器。

## TUIC 与 DNS

安装官方 **sing-box 1.14.4**，校验官方发布资产摘要；将其放到 `/usr/local/bin/sing-box`。
为隧道另建非 root 账号 `orangespace-tunnel`。它只读取隧道设置和证书，不读取个人文件目录。
有效 TLS 证书与私钥需由运维提供并续期，私钥仅隧道服务账号可读；不要用 `insecure=true` 绕过证书校验。

当前 File API 账号和 TUIC 凭据分别配置，尚无自动签发/撤销/分发联动。不要把“用户在 API 中禁用”误认为隧道凭据也已撤销。
每个 TUIC 账号使用独立 UUID 和至少 24 字符随机密码；凭据用私有 JSON 数组文件保存：

```json
[{"uuid":"REPLACE_WITH_UUID","password":"REPLACE_WITH_RANDOM_SECRET"}]
```

生成节点配置（输出必须尚不存在）：

```sh
python3 scripts/node_config.py --users /secure/path/tuic-users.json \
  --certificate /etc/orangespace/tls/fullchain.pem --key /etc/orangespace/tls/privkey.pem \
  --output /secure/path/tuic-new.json
sing-box check -c /secure/path/tuic-new.json
```

完成审阅后把配置安装为 `/etc/orangespace/tuic.json`，仅隧道账号可读，安装对应 service。
网关按目标网站协议向外建立 TCP/UDP。配置拒绝私有地址、链路本地和常见非公网范围；DNS 请求交给本节点 Unbound（127.0.0.1:5353）。这不等于已完成所有云环境的出口访问策略。
`unbound.conf` 需要合并到系统 Unbound 配置，使用软件包提供的 root trust anchor；不要覆盖已有配置。

对外开放 HTTPS TCP 443 和 TUIC UDP 443；Caddy 自动证书可能还需 TCP 80，按实际证书方式配置。文件 API、数据库、Unbound 不公开监听。

## 验证范围

`scripts/smoke_node.py` 可在临时本机目录启动真实 HTTP 服务做多用户文件测试：

```sh
server/.venv/bin/python scripts/smoke_node.py
```

`scripts/smoke_tuic.py` 对两套临时客户端/节点做真实 TCP/UDP 转发验证，不等于完成 Windows WFP 验收。
目前 PostgreSQL 真库测试已写入 CI，但本机无 PostgreSQL，尚未执行；systemd/Caddy/Unbound 的 Linux 实机部署也尚未执行。
