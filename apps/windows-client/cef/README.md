# CEF 版本锁与兼容性检查

- `cef.lock.json`：固定 CEF **156.0.14+g4fa4ab5+chromium-156.0.8078.48**、Windows API **15600**、发行包校验和及 sandbox compatibility hash。`scripts/cef_package.py` 用它校验并解包官方 minimal 包。
- `bootstrap_policy.hpp`：BrowserHost 入口在加载 CEF 前检查 bootstrap 与 runtime 的版本、API hash、sandbox hash 是否与锁一致；兼容不等于获准启动。
- `cef_pin.hpp.in`：由 CMake 根据锁文件生成编译期常量。

当前唯一使用这些文件的 CEF 程序是 `apps/windows-client/prototype` 中的显式代理 BrowserHost，P1 将其并入主构建（见 `docs/roadmap.md`）。不得加入禁用 Chromium sandbox、关闭证书验证或允许本机直连的入口。
