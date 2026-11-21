# 归档文档

这里是旧路线（内核级 WFP 重定向/UDP 回注，浏览器在此之前永久拒绝）期间的交付计划、验收要求和验证记录。它们记录了当时实际执行过的测试，但不再是现行约束；现行架构与计划见 `docs/architecture.md` 和 `docs/roadmap.md`。

文中提到的部分代码（`wfp-baseline`、`routing.rs`、只能编译的 CEF 宿主等）已在 P0 删除，可在 git 历史中查到。

2026-11-20 起改为 WSL2 Linux 桌面路线。原生 Windows CEF/WFP 方案（显式代理 + 每沙盒 WFP、每沙盒 BrowserHost 原生子窗口）的架构与路线图移到 `architecture-windows-native.md`、`roadmap-windows-native.md`，其中的实测结论（WFP 隔离、Chromium GPU 进程与窗口站 ACL 的问题等）仍可参考。

2026-11-21 旧路线代码从主线删除：`apps/browserhost`、`apps/windows-service`、CEF 组件、`tools/sandbox-devlaunch`、`drivers/wfp-prototype`、`orangespace-broker`、`orangespace-runtime`、Windows 开发包与 `OrangeSpaceLogin`。只描述这些代码的 `client-login.md`、`service-client.md` 一并移到此处；完整代码在 `p0-consolidation` 分支与 git 历史中。
