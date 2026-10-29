# Windows 管理窗口：节点登录接入（第一阶段）

此增量替换管理窗口手输用户/节点 UUID 的路径。它接入真实
`TrustedCatalog::load` / `NodeSession::login`，不是伪造认证响应；**本次没有可用的真实
HTTPS 节点登录 fixture，不能将编译或控制器测试当作成功登录验收**。
浏览器仍无条件拒绝启动，不改变服务、WFP、DNS 或 CEF 门禁。

## 使用与身份规则

1. 在窗口填写管理员配置的清单绝对路径，点击“验证并载入”。目录、ACL、HTTPS
   地址及别名规则沿用 `docs/client-login.md`。只有受保护清单通过原生验证后，才将
   `TrustedCatalog::names()` 填入不可自由输入的下拉框。修改路径文本本身不重新加载；
   只有再次点击验证按钮才采用新清单，并先退出所有旧登录。
2. 选择别名，输入该节点的用户名和密码，点击“登录节点”。实际认证流程包含受信
   HTTPS 预检、登录和携带令牌的 `/v1/me`；身份仅来自认证结果。节点 UUID 只是
   只读文本，不接受用户编辑。密码控件使用 `ES_PASSWORD`。
3. 第一次成功登录的服务端用户 UUID 固定本轮工作区身份。使用“读取工作区”查看
   该用户已有本机沙盒，不迁移、不重命名、不自动删除任何现有元数据或 Profile。
4. 可以依次登录多个别名；每个别名保留独立的 `NodeSession`。选择别名只选择用于
   此次管理的认证会话，不更改任何沙盒的节点。清单本身保证节点 UUID 唯一。
5. 不同节点账号独立。**相同用户名不是相同账号**：另一个节点返回不同 UUID 时，
   会话可以独立保留，但界面用中文说明禁止与当前工作区混用。退出全部登录后，
   才能将另一个账号设为本轮工作区；不建立跨节点映射或统一认证体系。
6. 新建、读取要求当前登录 UUID 与工作区 UUID 完全相同。关闭、删除已绑定沙盒
   还要求所选节点等于该沙盒节点。首次绑定只使用当前认证节点；换绑要求原节点、
   目标节点同时存在未过期且用户 UUID 完全相同的独立认证会话。原节点未登录、
   登录过期或用户不匹配时均拒绝。未绑定沙盒可由其认证用户管理。
7. “退出全部登录”清除所有内存会话、用户名、工作区列表与身份显示；不删除本机
   沙盒，不触碰 Linux 个人区。仅本机销毁令牌，**未实现服务端撤销**。没有刷新、
   DPAPI 保存、自动恢复或登录持久化的完成声明。

现有 Rust CLI 仍只负责本机元数据操作，参数中只有 UUID、沙盒名称等非凭据。
窗口控制器不是恶意本机调用者的安全边界，也不把本机 CLI 的用户参数升级为服务端
认证或服务许可。受保护服务/helper 串联由集成方单独完成；此增量不发送密码/令牌
到 CLI、服务 IPC、命令行、环境或日志，更没有从登录跳转到浏览器的旁路。

## 异步、密码与迟到结果

- 清单 ACL/文件读取、WinHTTP 登录及本机 broker 调用都在后台线程执行。
  单次任务期间禁用重复提交，但退出登录和关闭窗口不等待网络线程、不 join。
- 工作线程只持有共享结果邮箱和自身输入，不访问 HWND 或 `Application`；100 ms
  UI 定时器取出结果。关闭直接销毁窗口，迟到结果随邮箱释放，不向可能复用的
  HWND 投递指针。当前 WinHTTP API 不提供中途取消；后台认证可能直到其超时结束。
- 密码提交时先复制到有作用域所有权的缓冲区，立即清空控件和 undo buffer，然后
  才验证输入、转换 UTF-8 或派发网络操作。宽字符及 UTF-8 缓冲区析构时进行
  volatile best-effort 清零；宽字符转换完也立即清零。异常路径由同一所有者清理。
  不保证清除 Windows edit/WinHTTP 内部副本、分页、崩溃转储或注入代码读到的内存。
- UI 代次拒绝退出/重载后的所有迟到结果；可移植控制器代次还拒绝被替代、重复、
  退出后、关闭后的登录结果，以及节点切换后的旧工作区结果。控制器只在 UI 线程
  使用；后台不解引用可被退出销毁的会话。
- 每次操作在派发前检查用户、节点及到期时间；后台开始调用 CLI 前再次检查取消位
  和到期时间，读取结果时再次检查完整操作票据。换绑票据的有效期取两端会话的
  较早值。删除确认框返回后重新检查，避免在确认期间过期后继续授权。
- 已经通过授权检查并提交给本机组件的操作不承诺回滚；退出与关闭会拒绝其 UI
  结果，不声称能够撤销已经开始的数据库操作。过期会话不能发起新操作；本机
  正在进行的操作可能在到期后结束，其结果不会作为有效认证结果发布。

## 可移植 TDD 与真实构建证据

仅新增 header-only `include/orangespace/workspace_auth.hpp`，生产实例为
`WorkspaceAuth<NodeSession>`；测试使用不含传输的假会话表示认证组件的输出，测的
是真实控制器策略，不伪称网络认证。策略包含独立节点会话、精确 UUID/节点检查、
原节点认证、过期边界（含换绑原节点）、登录代次、单次消费、切换、退出和关闭。

实际执行过 RED：缺少新头文件、缺少授权/管理/票据接口；另一个运行时 RED 为
`login completion accepted only once`，随后实现单次消费并转 GREEN。
实际执行过以下命令，均通过（模型回归和节点校验也重新运行）：

```sh
g++ -std=c++20 -Wall -Wextra -Werror -I apps/windows-client/include \
  apps/windows-client/tests/workspace_auth_tests.cpp \
  -o /root/.hermes/cache/scratch/workspace-auth-tests
/root/.hermes/cache/scratch/workspace-auth-tests
# workspace auth: login, isolation, expiry and race checks passed

g++ -std=c++20 -Wall -Wextra -Werror -I apps/windows-client/include \
  apps/windows-client/tests/model_tests.cpp -o /root/.hermes/cache/scratch/ui-model-tests
/root/.hermes/cache/scratch/ui-model-tests
# client model: identity isolation, response validation, quoting and guard checks passed

g++ -std=c++20 -Wall -Wextra -Werror -I apps/windows-client/include \
  apps/windows-client/tests/node_session_tests.cpp -o /root/.hermes/cache/scratch/ui-node-tests
/root/.hermes/cache/scratch/ui-node-tests
# node session: 95 checks passed

x86_64-w64-mingw32-g++ -std=c++20 -Wall -Wextra -Werror \
  -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -DNOMINMAX -D_WIN32_WINNT=0x0A00 \
  -I apps/windows-client/include apps/windows-client/src/main_win.cpp \
  apps/windows-client/src/broker_win.cpp apps/windows-client/src/node_session_win.cpp \
  -static -municode -mwindows -lcomctl32 -lshell32 -luser32 -lgdi32 -lwinhttp -ladvapi32 \
  -o /root/.hermes/cache/scratch/OrangeSpaceLoginUI.exe
```

额外单独以同样警告级别交叉编译 `main_win.cpp` 的 object 通过；可移植控制器测试
以 `-fsanitize=address,undefined -fno-omit-frame-pointer` 编译并执行也通过，无诊断。
上述手工链接是
诊断产物，不含资源/manifest，不替代 CMake 发布包或 Windows 实机验收。没有在
断开的 Windows 会话启动 GUI。

## CMake 统一集成

统一构建已在已有 `BUILD_TESTING` 块添加：

```cmake
add_executable(orangespace-workspace-auth-tests tests/workspace_auth_tests.cpp)
target_link_libraries(orangespace-workspace-auth-tests PRIVATE orangespace_client_model)
add_test(NAME workspace-auth COMMAND orangespace-workspace-auth-tests)
```

在已有 Windows `OrangeSpace` target 链接列表中增加 `orangespace_node_session`。
该库已携带 `winhttp` / `advapi32` 链接要求；保留既有 common controls、GUI 子系统、
Unicode、manifest、MSVC `/utf-8` 与资源设置。可将同样的 MSVC 警告选项应用到
新增可移植测试，不需要改动 `node_session.hpp/.cpp` API，也不需要令牌 getter。

## 待真实 Windows/节点验收

- MSVC/SDK、带 manifest 的正式 CMake 链接与安装产物；交互密码遮蔽、立即清空、
  Tab/键盘、窗口缩放和高 DPI 布局。当前保持橙色主题和自适应双栏，未执行视觉验收。
- 管理员清单在真实窗口的成功/失败路径及别名列表；真实 HTTPS 用户名/密码登录、
  错误密码、429、证书/主机名/节点不匹配、不可达和缓慢响应；需要真实 TLS fixture。
- 两节点相同用户名但不同 UUID 的中文拒绝；独立会话选择、原节点未登录/过期时
  换绑拒绝、两端 UUID 相同且分别认证后的显式换绑。测试值不是生产身份映射。
- 登录/列表在途时退出或关闭、到期后按钮禁用、删除确认框停留跨过期、旧响应
  不恢复身份和工作区；已有沙盒/Profile 在登录/退出/换节点后仍存在。
- 服务 IPC/helper 集成和真实 Windows 保护链另行验收。本窗口集成不证明 CEF/WFP/
  DNS 安全，任何登录成功都不能使浏览器可启动。
