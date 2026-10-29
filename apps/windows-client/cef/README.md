# CEF 完整浏览器接入边界

`host_component.cc` 是 CEF Views / Chrome-style 宿主组件的初始源码，**未编译验证、未作为默认目标构建、不能启动浏览器**。它展示独立 RequestContext、每进程单沙盒 Profile 和 Chrome-style 窗口的接入位置，不能视为浏览器已交付。

当前 CMake 若收到 `-DORANGESPACE_WITH_CEF=ON` 会明确报错。不要删除门禁以便“先浏览起来”，也不要增加 `--no-sandbox`、`settings.no_sandbox = true` 或允许本机直连的调试入口。

## 固定接入方案

1. 一份共享 CEF 程序文件，多份沙盒 BrowserHost 进程组。每个进程组固定一个用户、沙盒、节点和隧道代次。
2. CEF 的 `root_cache_path` 固定为该沙盒 `profile`；RequestContext 的 `cache_path` 为其子目录 `Default`。所有新标签、弹窗、扩展页面必须继承此上下文。禁止用户切换/新建 Profile 使窗口绕过绑定。
3. 一个 Chrome-style CefWindow 只挂载一个 Chrome-style BrowserView。完整标签生命周期、扩展 UI、下载和文件面板共存需要真实 Windows PoC，不能把任意多个原生 BrowserView 当作 Chrome 标签页。
4. 使用与选定 CEF 版本严格匹配的现代 Windows `bootstrap.exe` / `client.dll` 启动方式，DLL 实现官方 `RunWinMain(..., sandbox_info, version_info)` 接口。先完成版本和 API hash 校验，并保持非空 Chromium `sandbox_info`。此仓库暂不锁定、下载或分发未经构建验证的 CEF 二进制。
5. **在 CefInitialize 之前**向受保护的 Windows Service 申请进程绑定的启动授权；WFP TCP、UDP、IPv4、IPv6、受管 DNS、进程树身份、驱动签名及失效关闭都就绪后才允许创建 BrowserHost。仅检查代理参数或读取一个 JSON `ready` 值不构成授权。
6. 浏览器下载由原会话写入隔离临时目录，再提交原节点的文件 API；上传文件选择先读取 Linux 个人文件区，再下载至沙盒临时目录交给原页面。需要保留请求会话、POST/blob 行为和页面对文件的使用期。桥接尚未实现。

## 必须补齐的验证

CEF bootstrap/client.dll 的 Windows 构建和 Chromium 子进程 sandbox；Chrome-style 标签与扩展；浏览器直接 TCP/UDP/DNS/IPv6/localhost 逃逸阻断；并发深圳/广州节点与同编号回包隔离；断线、重连、切换时失败关闭；认证下载、blob 下载、文件 input、多文件上传和任务原节点归属。

## 官方参考

- [CEF sandbox setup](https://chromiumembedded.github.io/cef/sandbox_setup)
- [CEF Windows bootstrap 入口](https://github.com/chromiumembedded/cef/blob/master/include/cef_sandbox_win.h)
- [CEF Runtime styles 与一个 Chrome-style BrowserView 的限制](https://github.com/chromiumembedded/cef/blob/master/include/internal/cef_types_runtime.h)
- [CEF Views BrowserView 接口](https://github.com/chromiumembedded/cef/blob/master/include/views/cef_browser_view.h)

本仓库代码独立编写；未复制 IdenGrid 的客户端代码。
