# Windows 开放浏览器前的验收

当前未达到开放条件。此列表是实现验收要求，不表示项目已通过。

1. VS2022/Windows SDK 原生编译、管理器实际操作、broker 的 OS 身份和 IPC ACL。
2. 与固定 CEF 版本匹配的现代 bootstrap/client.dll；Chromium sandbox 启用、API hash 校验、所有子进程身份归属可追踪。
3. Chrome-style 完整标签、新窗口、扩展、开发者工具、认证、WebRTC；所有浏览上下文继承原沙盒 Profile。
4. WFP 驱动签名和安装；BrowserHost 前默认阻断；TCP 重定向和原目标；UDP socket/association 回包；驱动/服务/helper 任一失效时关闭网络。
5. IPv4、IPv6、UDP、TCP、localhost 代理、局域网、WebRTC/STUN、扩展的直连尝试全部由抓包证明没有绕过。
6. 系统 DNS 服务代查、Chromium 内置解析和安全 DNS 均走已绑定节点；不能只检查网页出口 IP。
7. 深圳/广州并行、多个用户连接同节点、相同 Stream/Association 编号、旧回包、节点切换/断网/睡眠唤醒；不串流、不换节点、不直连。
8. 带登录认证、POST、blob 的浏览器下载；远端单文件/多文件上传；原网页读取文件期间临时区生命周期；中断后重试和原节点归属。
9. 删除一个沙盒只清其本机数据，其他 Profile 和 Linux 共享个人区保留；关闭/切换后重新打开登录状态仍在。

管理器编译通过、TUIC 能转发、WFP block-only 规则存在，都不能单独替代这些验收。
