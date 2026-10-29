# CEF 精确版本 bootstrap / client.dll 构建验证

## 范围与状态

这是独立、手工选择的 **Windows x64/MSVC compile-only 验证路径**，不是可运行浏览器或发布包。父级管理器的 CEF 默认仍关闭，broker/UI 浏览器门禁不得解除。`host_component.cc` 只提供一个 Chrome-style BrowserView/Window 接入位置，不能当成完整标签浏览器。

实际已执行 Linux 离线包校验/安全解包测试、C++ 兼容性与无条件拒绝策略测试、官方索引/固定提交源码查询；接手集成时实际下载固定 minimal 包，核对官方 SHA-1、计算并锁定 SHA-256，完整解包和 header/layout 检查通过。使用该真实包完成 bootstrap/host 两个源文件的 MinGW 编译探针，修正 `CefRequestContextHandler` 缺少完整定义的编译错误。此探针不是 MSVC 链接或 CEF 运行验收。**尚未执行** CEF 启动、Chromium sandbox/LPAC、WFP/DNS 或浏览器功能验收。没有下载 Chromium 源码或运行浏览器；未改项目许可证。

**后续 Windows CI 已验证**：提交 `cc26506` 的 `windows-manager` 在 GitHub 托管 Windows/MSVC 环境通过完整 native 构建及独立 CEF compile-only 步骤，包括 wrapper 编译、`client.dll` 链接、`RunWinMain` 导出检查与 bootstrap 复制哈希一致性（run `40898175322`）。先前 VS 生成器硬编码、Windows 路径反斜杠进入 vendor macro 的错误已按真实 CI 输出修正。该结果不涉及 CEF 启动、Chromium sandbox 子进程或网络隔离。

## 固定依赖与可核对来源

2026-10-29 查询官方项目指向的 CEF Automated Builds 索引，选定已存在的 Windows64 minimal 包；没有使用 latest 别名或猜测未来版本。

| 字段 | 固定值 |
|---|---|
| CEF | `156.0.14+g4fa4ab5+chromium-156.0.8078.48` |
| Chromium | `156.0.8078.48` |
| CEF commit | `4fa4ab516dacf6c49fc7e6e70d2b7ebce29fa35f` |
| 包 | `cef_binary_156.0.14+g4fa4ab5+chromium-156.0.8078.48_windows64_minimal.tar.bz2` |
| 字节数 | `175051364` |
| 索引 SHA-1 | `72dc1dd1636acc2391609fa6f410aa09f09168d4` |
| 固定 API | `15600` |
| Windows API hash | `8f211699a44daedd96ae2a89bbf3a8f2abc229f3` |
| Sandbox compatibility | `3b66cadf26145637` |

机器可读权威值在 `apps/windows-client/cef/cef.lock.json`。官方索引仅公布 SHA-1；在验证该索引值与 HTTPS 下载包一致后，本项目实际计算并固定 SHA-256 `99f8a6dffd47417e0caee7845a98c549b41f1d4246cd715dec843ca4b699ee57`。此 SHA-256 是本项目对所取归档的固定值，不冒充独立官方签名或官方发布的 SHA-256。构建同时检查大小、SHA-1 和 SHA-256；无 SHA-256 锁或不匹配时在解包前拒绝。开发依赖固定策略不替代发行时完整文件清单、可信签名/签发者和更新审核。

官方参考（固定提交，不依赖 master 漂移）：

- [CEF 官方项目与 Downloads 链接](https://github.com/chromiumembedded/cef)
- [CEF Automated Builds](https://cef-builds.spotifycdn.com/index.html) 与 [JSON 索引](https://cef-builds.spotifycdn.com/index.json)
- [sandbox setup](https://chromiumembedded.github.io/cef/sandbox_setup)
- [现代 RunWinMain ABI](https://github.com/chromiumembedded/cef/blob/4fa4ab516dacf6c49fc7e6e70d2b7ebce29fa35f/include/cef_sandbox_win.h)
- [version_info 结构、大小及 sandbox hash](https://github.com/chromiumembedded/cef/blob/4fa4ab516dacf6c49fc7e6e70d2b7ebce29fa35f/include/cef_version_info.h)
- [API hash 入口与条目含义](https://github.com/chromiumembedded/cef/blob/4fa4ab516dacf6c49fc7e6e70d2b7ebce29fa35f/include/cef_api_hash.h) 和 [固定 API hashes](https://github.com/chromiumembedded/cef/blob/4fa4ab516dacf6c49fc7e6e70d2b7ebce29fa35f/cef_api_versions.json)
- [官方 DLL/复制 bootstrap 构建方式](https://github.com/chromiumembedded/cef/blob/4fa4ab516dacf6c49fc7e6e70d2b7ebce29fa35f/tests/cefsimple/CMakeLists.txt.in)
- [签名验证与延迟加载库接口](https://github.com/chromiumembedded/cef/blob/4fa4ab516dacf6c49fc7e6e70d2b7ebce29fa35f/include/wrapper/cef_library_loader.h)
- [当前 CMake sandbox/CRT/delay-load 配置](https://github.com/chromiumembedded/cef/blob/4fa4ab516dacf6c49fc7e6e70d2b7ebce29fa35f/cmake/cef_variables.cmake.in)
- [minimal 包包含头文件、wrapper 与 bootstrap 的生成逻辑](https://github.com/chromiumembedded/cef/blob/4fa4ab516dacf6c49fc7e6e70d2b7ebce29fa35f/tools/make_distrib.py)

## 复现：先只检查小型元数据

```sh
python3 scripts/cef_package.py --check-index
python3 -m unittest discover -s scripts -p 'test_cef_package.py' -v
cmake -S apps/windows-client/cef -B build/cef-policy -DORANGESPACE_CEF_POLICY_TESTS_ONLY=ON
cmake --build build/cef-policy
ctest --test-dir build/cef-policy --output-on-failure
```

`--check-index` 是显式的小型网络查询，只核对已固定版本/包的大小、SHA-1 与 sandbox hash，不更新锁、不下载运行时。其余命令离线。Python 用小型明确标注的 fixture 测试完整性、错误版本/API hash、空 bootstrap、路径穿越/链接拒绝、安全解包和不合并旧目录；fixture 不是 CEF 编译结果。C++ 用策略 fixture 测试空指针、版本/sandbox/API/commit 不匹配及无条件拒绝；fixture 指针不是 Chromium sandbox。

## 复现：Windows compile-only

环境：Windows 11 x64、VS2022 Desktop development with C++/Windows SDK、CMake 3.24+、Python 3.12+。从 x64 Native Tools 环境进入 PowerShell，确保 `dumpbin` 在 PATH。

**需要时由操作员显式下载一次**锁中 `archive_url` 对应的约 175 MB minimal 包，保存在仓库之外。不需要完整 Chromium checkout，也不需要 symbols/tools/client 额外包。下载不是脚本的隐含副作用：

```powershell
$Lock = Get-Content apps/windows-client/cef/cef.lock.json -Raw | ConvertFrom-Json
$Archive = Join-Path $env:USERPROFILE $Lock.archive
Invoke-WebRequest -Uri $Lock.archive_url -OutFile $Archive
# BuildDirectory 必须尚不存在，失败后也不要合并旧输出；选择新目录重跑。
./scripts/cef-build-windows.ps1 -Archive $Archive -BuildDirectory "$env:USERPROFILE/OrangeSpace-cef-compile-check"
```

脚本执行：

1. 在解包前检查完整包**大小、官方索引 SHA-1 及项目固定 SHA-256**；只允许预期顶层目录内的普通文件/目录，拒绝穿越、绝对路径、Windows 路径分隔/盘符、符号/硬链接；在临时目录验证后整体重命名，不合并旧运行时。
2. 检查精确 CEF version、commit、Windows API hash、sandbox compatibility hash 和非空 bootstrap/DLL/import lib/wrapper/CMake 文件。该 header/layout 检查本身不验证任意现存目录的所有字节；完整性来自前一步对原始归档的验证和全新解包。
3. 独立配置 `apps/windows-client/cef`，固定 `USE_SANDBOX=ON`、API 15600、静态 CRT `/MT`，拒绝禁用 sandbox、installer 或不同 API。通过分发包自己的 `FindCEF.cmake` 构建 wrapper；不编译官方 sample。
4. 编译/链接 `client.dll`，复制同版本官方 `Release/bootstrap.exe` 为 `client.exe`。sandbox 代码来自官方 bootstrap，不使用旧式 `cef_sandbox.lib` 或手写替代 WinMain。
5. 只运行不依赖 CEF 的策略测试，检查 DLL 的 `RunWinMain` 导出、输出非空及复制 bootstrap 的 SHA-256 与已校验原件相同。**绝不启动 client.exe。**

输出位于 `<BuildDirectory>/build/compile-only/Release/`。不复制 libcef/runtime/resources/chrome_elf，不修改 LPAC ACL，不提供 installer，因此不能将此目录宣传为浏览器包。复制比较产生的 SHA-256 仅证明复制相同，不冒充独立官方发布散列。

## 启动入口与门禁

入口严格为 CEF 头文件声明的 C linkage / cdecl `RunWinMain(HINSTANCE, LPWSTR, int, void*, cef_version_info_t*)`，不是 `WINAPI wWinMain`。构建时静态断言 version/commit/API/hash 固定值及函数指针类型；入口检查结构体大小、全部八项版本数字和 16 字节 sandbox hash，拒绝空 sandbox 指针。

供后续 Windows 验证的入口使用 upstream `CefScopedLibraryLoader` 和 early logging，只接受可执行文件相邻、有效签名的 libcef，不接受 bootstrap installer 的路径解析、不允许 unsigned、不做 PATH 或机器级运行时回退。它显式比对 `cef_api_hash(15600, 0/2/3)` 的平台 API、commit、sandbox hash，并检查完整 runtime version。当前 compile-only 输出没有该库，不能据此声称运行时检查已经执行或通过；签发者固定和正式签名策略仍待发行设计。

**兼容性匹配不等于启动授权。** 检查通过也返回 `launch_denied`（23）；无匹配则返回 20/21/22 或由 upstream loader 失败终止。入口没有 `CefExecuteProcess`、`CefInitialize`、消息循环、Profile 写入或创建浏览器的调用。没有 service-ready 布尔量、环境变量或命令行解锁路径。正式实现必须在新增任何初始化/子进程执行路径之前取得受保护 Windows Service 对 OS 进程身份及会话绑定的授权；当前策略不得因为 compile-only 通过而解除。

非空 opaque sandbox 指针只能证明调用参数存在，不能证明 sandbox broker/target services 有效、子进程已隔离或 LPAC ACL 正确。真实 Windows sandbox、子进程归属、TCP/UDP/DNS/IPv6/localhost 逃逸与所有 `docs/windows-validation.md` 条件仍必须验收。

## 给父级集成者

- 不改既有父级 CMake 和 `scripts/build-windows.ps1` 即可单独运行此路径；默认构建保持 CEF OFF。
- 若以后接入父级 option，`ORANGESPACE_WITH_CEF=OFF` 必须保留，仅 ON 时显式添加独立验证子工程/target；不要把它等同于浏览器 launch enable。优先用独立 `cmake -S apps/windows-client/cef` 隔离 wrapper 的 CMake 全局配置。
- 现有父级 ON 分支仍是 deliberate fatal；本交付没有修改它。若父级更新该错误说明，应明确指向 compile-only 脚本，不能假装是 WFP/DNS 已授权的可用浏览器。
- CI 可以先增加离线 Python 与 C++ policy 测试。Windows CEF compile job 应显式获取固定归档/校验、使用新的 build root，并保留真实 MSVC 日志；不能用 Linux policy 通过填充 Windows 构建/运行验收。
