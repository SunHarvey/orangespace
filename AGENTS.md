# OrangeSpace 开发约定

- 先读 `README.md`、`docs/architecture.md`、`docs/verification.md`，区分真实已实现能力与尚未完成部分。
- Windows 客户端用 C++20/CEF，路由核心和 broker 用 Rust，Linux 文件节点用 Python/FastAPI。不要改成远程浏览器或画面传输方案。
- 用户/沙盒/节点/连接代次必须显式绑定；不能引入全局 current_node，或跨沙盒共用会话。
- WFP/DNS/进程身份管控未完成时不得开放浏览器，不加入 no-sandbox、allow-unsafe 或本机直连回退。
- Linux 个人文件区按认证用户隔离，同用户同节点共享；删除本机沙盒不删除远端文件。
- 不复制 IdenGrid 源码。不要将用户凭据、私钥、Profile、临时文件纳入仓库。
- 修改路由或文件权限边界时运行相关测试；跨平台模型测试和 TUIC 回环测试不能宣称 Windows WFP 已通过。
- 当前工程没有对外分发许可证，未经用户决定不要替项目添加开源许可。
