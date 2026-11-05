# 中心控制面契约 C1

状态：2026-10-31 冻结的实现目标，**不是已交付/已验收声明**。C++20/CEF、Rust、FastAPI、Vue 3/TypeScript 架构不变。浏览器启动继续拒绝；控制台、MySQL和TUIC测试均不能证明WFP/DNS隔离。既有 lease schema2 / Rust dispatch schema2 与 `docs/lease-protocol-v2.md` 的保守预算保持不变。

## 1. 身份与数据归属

- 中心维护永久 `central_user_id`；节点现有 `User.id` 明确命名为 `legacy_user_id`，仍是该节点数据库外键及个人目录名。新旧UUID不互相替换，不按username自动合并。
- 批准的 `identity_mappings` 唯一绑定 `(node_id, legacy_user_id) -> central_user_id`；同中心用户在同节点至多一个映射。映射须来自已核验节点的库存/新建结果，管理员明确批准并记录证据摘要和理由。旧映射不允许原地转让给另一中心用户。
- 老 Linux `<data_root>/<legacy_user_id>` 不重命名；Windows SQLite owner、沙盒/profile/cache/tasks路径不重写。新增有版本的ownership sidecar，显式区分local owner、central principal、remote legacy principal。已知OS所有者与经审映射均匹配才允许认领；来源不明或冲突的旧工作区隔离，不猜测归属。
- 新用户授权可触发受信节点的幂等provision命令：节点创建新的本地UUID并回报实际结果；只对本次新建身份建立新映射。既有账户必须走显式库存映射审批，不能借provision认领同名账户。
- 新联邦租约wire的 `user_id` 仍指**目标节点的本地身份**，保持原17字段/renew5字段不变。中心subject由Service和节点sidecar额外约束；Rust不被要求把两个UUID看作相同身份。
- 同中心用户、同节点共享映射的个人区；不同用户隔离，不同节点不自动同步。删除Windows沙盒不删除Linux个人文件。

## 2. 版本、认证与错误

中心路径 `/control/v1`，节点新增 `/federation/v1`，显式schema=1；旧 `/v1/tunnels` 仍要求恰好一个 `X-OrangeSpace-Lease-Schema: 2`。旧登录/me/session/envelope及租约响应不扩字段、不自动降级。

UUID必须是非零canonical小写连字符字符串，不修复错误输入；整数不能是bool/float/exponent，范围0..9007199254740991，epoch/generation从1起。JSON拒绝重复和未知成员；模型字段有明确上限。错误 `{schema:1,error:{code,request_id}}` 不含凭据、异常正文或数据库参数。身份/凭据响应 `Cache-Control: no-store`。无认证401、无权限403/隐藏对象404、CAS/重复消费409、已终止410、严格输入422、版本426、限流429、依赖失败503。

中心用户Bearer、一次性exchange、节点机器Bearer、节点用户Bearer、TUIC、probe、本地SOCKS分别独立生成/校验，不能跨域互用。API token为43字符base64url，数据库仅存SHA-256摘要；密码Argon2id；不把任何凭据放进argv、环境变量、日志或公开配置。配置秘密通过受保护文件加载。

所有HTTP正常验证TLS链/名称，禁止带凭据自动重定向。管理员保护的bootstrap固定中心origin；Service不信UI提供的origin。仅已批准节点注册表提供节点origin和TUIC TLS名称。

## 3. 最小中心数据模型

MySQL8.4/InnoDB是唯一正式服务端数据库；SQLAlchemy，版本化Alembic迁移；Windows SQLite保持。

- users：永久id、规范化username、Argon2密码、role=`admin|user`、enabled、user_epoch、created_at。
- sessions：id、user FK、独立token摘要、签发时user_epoch、expires_at/revoked_at。
- nodes：id、唯一alias、display_name、api_origin、TLS名称、已核对public_key/fingerprint、机器token摘要、state=`pending|active|suspended|revoked`、node_epoch/config_revision、last_seen_at。
- enrollments/challenges：绑定预期node/key/origin的一次性token、nonce、expiry、消费状态。
- mappings：node、legacy user、central user、state、mapping_epoch、evidence_digest、审批主体和理由。唯一(node,legacy)、唯一(node,central)。
- grants：唯一(user,node)、enabled、grant_epoch、scopes、valid_until；scopes取files.read/files.write/tunnel。
- exchanges/federation_sessions：绑定中心session、node、mapping、grant及epoch快照；exchange一次消费。
- permits/lease_registry：绑定node、federation、sandbox、generation、tunnel、operation/request_id、epoch和不可延长截止；状态区分issued/process_started/authenticated/forward_verified/revoked/expired/cleanup_pending/closed。没有实际证明不得报后两个建立状态。
- lease_revocations/outbox：精确租约撤销与持久通知；通知失败不恢复授权。
- audit_events：与用户/节点/映射/授权变更同事务，记录操作者、对象、前后revision、时间、理由和request_id；不记录秘密。

明确使用READ COMMITTED短事务，所有权威重查使用新事务/锁定读，不沿用ORM旧缓存。用户名先按明确ASCII规则规范化；UUID/token摘要用精确binary比较，展示文本utf8mb4；MySQL表默认utf8mb4_0900_bin，验证NO PAD、大小写、重音、尾空格和长度。保留节点generation/tombstone，不新增会删除抗重放历史的CASCADE。唯一键/FK、缺失行首次插入竞争、原子generation前进及固定锁序需真实MySQL并发测试。DDL隐式提交不能冒充事务回滚。

## 4. 用户及管理HTTP契约

固定DTO：
- User `{central_user_id,username,role,enabled,user_epoch,created_at}`。
- Epochs `{user_epoch,node_epoch,mapping_epoch,grant_epoch}`。
- NodeRef `{node_id,alias,display_name,api_origin,tls_server_name,node_epoch,config_revision,key_fingerprint,grant_id,grant_epoch,scopes,mapping_id,mapping_epoch,legacy_user_id}`。
- 列表 `{schema:1,items:[T],next_cursor:null|string}`，limit默认50最大100；授权列表不能漏读分页。
- Revocation `{schema:1,revocation_id,committed_at,enforcement_deadline,cleanup_state:"pending"|"complete"}`。commit+30秒是保守最大上界；complete只能来自实际清理读回，不能仅因DB已改状态。

用户接口：
- POST `/auth/login` `{schema:1,username,password}` -> `{schema:1,access_token,token_type:"bearer",central_session_id,expires_at,user:User,nodes:[NodeRef],nodes_next_cursor}`。session上限3600秒；一期不做refresh，需重新登录。
- GET `/session` -> `{schema:1,central_session_id,expires_at,user:User}`，权威校验账号/session/epoch。
- GET `/me/nodes` -> NodeRef列表，仅active节点、有效grant、approved映射的交集。
- POST `/node-exchanges` `{schema:1,node_id,expected_epochs:Epochs}` ->201 `{schema:1,exchange_id,exchange_token,node_id,expires_at}`，一次性、最多30秒、精确绑定节点/session/映射/grant。
- DELETE `/sessions/{id}` 本人或管理员 ->202 Revocation。
- GET `/sessions`、`/sandboxes`、`/leases`：普通用户仅本人，管理员可筛选；列表不包含任何token/TUIC/probe/SOCKS秘密。
- DELETE `/nodes/{node_id}/leases/{tunnel_id}` 本人或管理员 ->202 Revocation，只撤销精确lease，不抬升整个grant_epoch误伤B。

管理员接口，统一 `/admin` 前缀，全部后端RBAC：
- GET/POST `/users`；创建 `{schema:1,username,password,role}` ->201 `{schema:1,user:User}`。
- PATCH `/users/{id}` `{schema:1,expected_user_epoch,enabled,reason}` -> `{schema:1,user:User,revocation:null|Revocation}`；禁用先增epoch/撤销会话。
- POST `/users/{id}/reset-password` `{schema:1,expected_user_epoch,password,reason}`；更新密码+epoch+撤销旧会话，返回User和Revocation，不返回密码。
- POST `/users/{id}/revoke-sessions` `{schema:1,expected_user_epoch,reason}` ->202 Revocation。
- GET `/nodes`；POST `/node-enrollments` 见下节；GET `/node-enrollments`不返回秘密。
- POST `/nodes/{id}/activate` `{schema:1,expected_node_epoch,expected_config_revision,reason}`；POST `/nodes/{id}/suspend` `{schema:1,expected_node_epoch,reason}`。
- PATCH `/nodes/{id}` `{schema:1,expected_config_revision,api_origin,tls_server_name,display_name,reason}`；修改信任地址先停用并增epoch/revision，需重新核验再激活。
- GET `/grants`；PUT `/users/{user}/nodes/{node}/grant` `{schema:1,expected_grant_epoch,enabled,scopes,valid_until:null|int,reason}` -> `{schema:1,grant_id,grant_epoch,enabled,scopes,valid_until,revocation:null|Revocation}`；首次expected=0。禁用/收紧使旧epoch失效。
- GET/POST `/identity-mappings`；POST `/{id}/approve`、`/{id}/revoke`，输入schema/expected_mapping_epoch/evidence_digest/reason；禁止更换既有mapping的central_user_id。
- GET `/audit-events`，记录用户/节点/授权/映射变更，不接受前端提供actor身份。

登录使用持久、账号/来源有界限流；RBAC、scope、expiry、CAS均在后端执行。管理员bootstrap仅受保护配置/交互CLI，不公开默认密码。

## 5. 节点注册与机器身份

最小方案不用新增中心CA/24小时证书平台：管理员经独立可信通道核对Ed25519公钥指纹、node UUID、预期HTTPS origin；一次性enrollment和nonce持钥证明建立信任，成功后签发独立节点机器Bearer。节点机器Bearer仅用于internal路由且绑定已批准node/key/epoch，不能用于用户API或别的节点。正常TLS保护传输；私钥及机器Bearer仅节点受保护配置持有。不是任意UUID自注册、TOFU或硬件证明。

- POST `/control/v1/admin/node-enrollments` `{schema:1,node_id,alias,display_name,api_origin,tls_server_name,expected_key_fingerprint,reason}` ->201 `{schema:1,enrollment_id,enrollment_token,node_id,expires_at}`，最多600秒。
- POST `/control/v1/node-enrollments/{id}/challenge` `{schema:1,enrollment_token,node_id,public_key}` -> `{schema:1,challenge_id,nonce,expires_at}`，最多60秒、有界/限流。
- POST `.../{id}/complete` `{schema:1,enrollment_token,challenge_id,signature}` ->201 `{schema:1,node_id,node_epoch,node_access_token,config_revision}`。精确签名消息：ASCII `OrangeSpace-enroll-v1\n` 后依次enrollment_id/node_id/key_fingerprint/api_origin/challenge_id/nonce/challenge_expires_at，每项UTF8字节长度十进制+冒号+原字节。公钥raw32字节SHA256为fingerprint；严格base64url。事务一次消费nonce/enrollment；错key、过期、重放均拒绝。
- 成功仍pending；管理员核验真实TLS origin/持钥部署后activate。中心不为未知节点自动访问任意URL，避免SSRF；只提交UUID不获信任。
- POST `/control/v1/internal/heartbeat` 机器Bearer，body `{schema:1,node_id,node_epoch,config_revision,request_id,observed_at}` -> `{schema:1,server_time,commands:[]}`。node_id必须等于机器身份；在线状态由中心实际接收时间计算，不能自报online=true。命令/结果需精确schema、幂等command_id及节点绑定。
- key/地址变更或机器credential轮换必须明确审批并增epoch/撤销旧credential；停用节点的机器身份不能消费新exchange/permit。节点私钥被root盗取/已批准恶意节点不在可信计算保证内。

## 5a. 最窄库存证据与映射批准（实现目标）

机器 POST `/control/v1/internal/identity-evidence` DTO `{schema:1,node_id,node_epoch,config_revision,legacy_user_id,request_id}`，仅 active 注册机器 Bearer 可为自身节点提交。节点必须先从实际本地 MySQL User 按 canonical UUID 查存在，仅查询主键，不读密码或文件。生产 origin/机器秘密由 owner-only 常规文件加载，HTTPS 正常验证、禁重定向；注入 ASGI/Mock transport 仅本地测试，非远端部署证明。

中心保存原始 node/public key/fingerprint/epoch/config/legacy/request_id、服务端接收时间和120秒期限，计算域分离 SHA256 摘要。相同 node/request 重试只返回原摘要/期限，内容变化409。管理员 POST `/admin/identity-mappings` `{schema:1,central_user_id,node_id,legacy_user_id,evidence_digest,reason}` 必须引用中心已有未过期可信证据，只创建 pending；GET 按既有分页契约。POST `/{id}/approve` `{schema:1,expected_mapping_epoch,evidence_digest,reason}` 仅管理员，CAS并锁定重查 active node/key/epoch/config/证据期限，批准后递增mapping epoch；禁止转让既有映射。机器不能批准；pending不进入 `/me/nodes`，approved仍需有效grant。此纵切片不实现revoke消费者、provision、permit，不能声称已有转发停止。

## 6. 联邦会话、预算和撤销

Service独立核验OS SID/session/logon LUID，亲自用中心用户token核验session/获准节点/精确映射。中心origin来自受保护bootstrap，UI成功或其UUID不能授予权限。新增显式版本化平台IPC（OSP3，继承现有边界/ACK/所有权准备及清理保障）；不把新DTO塞进旧OSP2。auth cursor绑定OS peer和中心session/node/mapping；持久workspace ownership与活动cursor分开。

Service申请exchange，发送给可信节点 POST `/federation/v1/sessions/exchange` `{schema:1,exchange_id,exchange_token}`。节点以机器Bearer调用中心 `/control/v1/internal/node-exchanges/consume` `{schema:1,exchange_id,exchange_token,request_id}`，原子检查node/user/session/mapping/grant的状态和epoch。返回精确Federation `{federation_session_id,central_session_id,central_user_id,node_id,legacy_user_id,mapping_id,grant_id,epochs:Epochs,expires_at}`。节点生成独立节点用户token，保留本地User FK，回复 `{schema:1,federation:Federation,node_credential:{schema:1,node_id,api_origin,access_token,expires_at}}`。同request_id只读回原结果，不重新生成更长授权；未知完成结果保留精确清理责任。旧NodeSession可restore内层5字段envelope，user_id仍为legacy。

节点接入配置由受保护文件提供：`{origin,token,node_id,node_epoch,config_revision,node_api_origin}`，前两个分别是中心HTTPS origin与节点机器Bearer，最后一项是管理员核验的本节点API基址；不得从请求Host/URL或调用者提供的身份构造。配置存在但无效/不可读必须启动失败，不得自动回到本地密码模式。

节点 `/federation/v1/sessions/exchange` 只交付一次独立随机节点用户凭据，数据库仅存摘要及绑定sidecar；已交付exchange的重复请求返回409，不重发/重造秘密。内部中心consume仍按原request幂等。调用者在投递前保留精确node/exchange_id/exchange_token清理责任；节点 POST `/federation/v1/sessions/exchange-cleanup` 接受 `{schema:1,exchange_id,exchange_token}`，以本机存储的域分离摘要校验，只能撤销该exchange创建的本地session，回复 `{schema:1,local_session_state:"revoked"}`；这不是中心失权或helper实际停止的证明。失败/未知资源不得假报完成。

期限分层：exchange 的最多30秒仅是一次性消费窗口，不是中心身份会话时长。签发 ticket 时同时冻结联邦身份截止，取原中心 session 截止与当时 grant 截止的较早者；无 grant 截止时仍不超过原中心 session（上限3600秒）。首次消费及相同 request 重试均使用该原始身份截止，不因消费、读回、授权展期或重新校验延长。失权立即使在线核验失败。此处不放宽 helper/TUIC 租约：每次 create/renew 仍受原始 HTTP 单调锚点和最多30000ms约束，不能把身份会话截止当作转发授权截止。

节点每次创建/续租以机器Bearer POST `/control/v1/internal/lease-permits` `{schema:1,request_id,federation_session_id,tunnel_id,sandbox_id,generation,operation:"create"|"renew",expected_epochs:Epochs}` -> `{schema:1,permit_id,request_id,epochs:Epochs,expires_at,remaining_ttl_ms}`。中心在固定锁序的同事务内与revoke串行化；重试原request_id只能取原结果、剩余时间只减。节点在该HTTP开始前取单调锚点，permit D=min原锚点+remaining TTL、节点旧预算、中心session/grant有效余量、30000ms。中心故障拒绝新授权和续租，不用缓存positive/fallback；不能按响应接收或helper启动重新起30秒。

文件/me/session的联邦token同样在线核验 `/internal/federation-sessions/validate` `{schema:1,federation_session_id,expected_epochs,required_scope}` -> `{schema:1,federation:Federation,scopes:[...]}`。仅所属已核验节点机器身份可调用；`required_scope:null` 仅用于 `/me`、`/session` 的身份核验，仍要求有效、非空授权，不授予任何文件或隧道操作；具体业务操作必须要求对应的 files.read/files.write/tunnel scope。必须逐次重查当前权限，身份/节点/映射/grant失效返回终止，scope不足403、快照不符拒绝；不接受缓存positive。返回原Federation和原身份截止，不延长授权。本地User/grant为附加否决条件，不能绕过中心。文件路径从经批准mapping解析，API调用者不得指定owner。联邦切换时关闭旧本地密码登录签发新token并排空旧会话，不能保留绕过中心的正式入口。

中心撤销先持久失权、审计、outbox，再通知节点；丢通知最多等原短租约截止，不能把页面状态当实际停止。节点必须保持独立截止处理，不被中心HTTP或manager锁堵住。已有TCP/UDP也要失效，精确kill/wait与清理回执分离；用户态非硬实时，不伪造精确kernel截止保证。真实持续流量、阻塞/强杀/迟到/重启验收未通过前，不关闭该门禁。

## 7. 数据迁移与分批验收

只读清点已发现：旧8080 SQLite两表；A/B各五表，清点时均无行/个人文件；本机PG17候选库无业务表。不存在不等于COUNT=0。清点不能代替备份或迁移成功。

当前为开发阶段，按用户2026-10-31的纠偏，**不新增生产备份、恢复演练或切库前置**。开发顺序：新MySQL8.4真实迁移/非空归属与约束并发测试 -> 中心真实HTTP/RBAC/注册和授权 -> 节点联邦 -> Windows独立服务授权 -> 双沙盒与撤销持续流量 -> 跨OS/业务用户及不同节点/文件归属 -> 当前分支逐里程碑签名提交及精确SHA CI。源库和原目录保留，不清库、不改写旧UUID；旧SQLite/PG仅作为离线源，不作为新的正式运行方案。本轮不执行生产切换。

开发验证绑定实际源哈希、迁移版本、真实命令及输出；不因本节扩展生产备份/恢复或切库工作。不停止无关服务、不改现有RDP/Profile或默认信任库。未通过的旧guardian/updater/通用SYSTEM launcher不恢复。源码、开发构建、真实验收和签名发布分别报告。
