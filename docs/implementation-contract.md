# 第一阶段集成约定

这是 OrangeSpace 新代码库，禁止复制 IdenGrid 的受限许可代码。可参考其架构并链接来源。

目录所有权：`server/` 为 Python FastAPI 节点服务；`crates/` 为 Rust 路由核心和 broker；`apps/windows-client/` 为 C++20 Windows 原生管理器和 CEF 主机；根目录、部署、文档由集成负责。

固定模型：user_id、sandbox_id、node_id 均为 UUID；tunnel generation 是单调递增的 u64。一个沙盒同时最多绑定一个节点，一个沙盒一个独立 TUIC helper；相同节点的不同沙盒也不共用隧道上下文。不得有系统级 current_node。节点的隧道地址为字面 IP，TLS server_name 独立设置；不向 Windows DNS 回退。

安全边界：未实现并验证 WFP TCP/UDP 接管、DNS 接管、进程身份跟踪、驱动签名之前，不允许启动联网浏览器。不提供 allow-unsafe / no-sandbox 绕过选项。guard 的占位/未支持状态必须返回失败，绝不能由配置声明 ready。当前阶段的 CEF 和 broker 不得宣传为可用的安全浏览产品。

客户端数据：`%LOCALAPPDATA%/OrangeSpace/users/<user_id>/sandboxes/<sandbox_id>/profile`、`cache`、`tasks`。关闭或切换节点保留 profile；删除沙盒才删除该沙盒的本地数据。Linux 文件区以认证用户划分，同节点同用户不同沙盒共用文件区。文件任务记录创建时 node_id，节点切换不能改写历史任务归属。

节点 API 前缀 `/v1`：`POST /auth/login`、`GET /me`、`GET /files?path=`、`POST /directories`、`PUT /files/{path:path}` 流式上传原子提交、`GET /files/{path:path}`、`DELETE /files/{path:path}`。用户身份只从认证上下文获取，不接受客户端 user_id/path 作为用户根目录。部署使用 PostgreSQL，测试可用 SQLite。每节点只对外公开 HTTPS API 和 UDP TUIC 端口。

第一阶段分清：已运行验证的后端/路由核心；可构建或待 Windows 构建的原生客户端；未完成的 WFP/DNS/CEF 下载上传桥。测试不能用桩造出“网络隔离已实现”的结论。
