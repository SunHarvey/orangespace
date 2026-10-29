# CEF 精确版本构建验证（不开放浏览器）

此目录现在有独立、显式选择的 Windows x64/MSVC **compile-only** 工程。它编译 `host_component.cc` 和 `bootstrap_client_win.cc`，链接 `client.dll`，并将同版本官方 `bootstrap.exe` 原样复制为 `client.exe`。默认管理器构建仍不包含 CEF；此目录不改动父级 `ORANGESPACE_WITH_CEF=OFF` 默认值。

`cef.lock.json` 固定 CEF **156.0.14+g4fa4ab5+chromium-156.0.8078.48**、Windows API **15600**、发行包校验和及 sandbox compatibility hash。来源、命令与验证范围见 [`docs/cef-build.md`](../../../docs/cef-build.md)。固定版本不代表该二进制已在 Windows 构建或运行通过。

## 明确不提供的能力

- `RunWinMain(HINSTANCE, LPWSTR, int, void*, cef_version_info_t*)` 使用官方现代 DLL ABI；拒绝空 sandbox 指针、错误结构体大小、版本、提交、sandbox hash 与 API hash。
- 即使兼容性完全匹配，也无条件拒绝启动。入口**不调用 `CefExecuteProcess`、`CefInitialize` 或消息循环**；没有开关或 JSON ready 值能授权。
- 构建输出不复制 CEF runtime、资源或 `chrome_elf.dll`，不是可运行/可分发的浏览器目录。不要直接启动它作为测试。
- 没有完成受保护服务授权、进程身份、WFP TCP/UDP、DNS、驱动签名或子进程 sandbox 实测。非空指针检查不等于 Chromium sandbox 已验收。

## 保留的完整浏览器接入边界

1. 共享 CEF 程序文件；每沙盒独立 BrowserHost 进程组，固定用户、沙盒、节点和连接代次。
2. 未来真正初始化 CEF 时，`root_cache_path` 为本沙盒 `profile`，RequestContext 的 `cache_path` 为其子目录 `Default`。所有标签、弹窗和扩展必须继承同一上下文，不能通过新建 Profile 绕过绑定。
3. `host_component.cc` 仅是单个 Chrome-style BrowserView/Window 的接入组件，**不是完整多标签 Chrome 浏览器**。完整标签、新窗口、扩展、DevTools、认证、WebRTC 和文件桥仍待实现/实测。
4. 在任何 `CefInitialize` 以及可能创建网络子进程的路径前，必须取得不可由配置伪造、与进程身份绑定的服务授权。当前代码根本没有初始化调用。
5. 浏览器文件桥需保留原网页 Cookie、POST/blob 会话与文件使用期，文件任务必须保留创建时节点归属；当前尚未接入。

不得加入禁用 Chromium sandbox、关闭证书验证、允许本机直连或跳过服务授权的调试入口。
