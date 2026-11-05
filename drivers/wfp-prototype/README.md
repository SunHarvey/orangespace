# 单实例 WFP 网络策略库（源代码候选，默认仍阻断）

独立 `orangespace::wfp_prototype::NetworkPolicy`，不改旧 baseline，不含 runner、驱动、浏览器启动或授权旁路。根及**全部 CEF 子进程必须使用同一个受保护的绝对 `client.exe` 路径**；AppId 是路径身份，不是 PID、实例、哈希或授权身份。

## API

```cpp
NetworkPolicy();
~NetworkPolicy();
void installOffline(const std::wstring& exactProtectedExecutable);
void switchToProxyOnly(std::uint16_t port);
void restoreOffline();
std::vector<VerifiedFilter> verifyExactPolicy(Mode expected, std::uint16_t port = 0);
void cleanupAfterExactTreeExit();
```

`installOffline` 持有普通单链接 EXE 的 `GENERIC_READ / FILE_SHARE_READ` 非继承句柄，不共享写入或删除；拒绝相对路径、UNC/device、ADS、点段、尾点/空格、叶 reparse 和不一致的最终规范路径。调用者必须使用与最终路径完全相同的规范大小写路径。

**受保护安装前提由可信调用者负责**：安装目录、所有祖先、EXE/DLL/resources 的 owner/DACL 防非特权写入/改名/替换；调用者须验证安装来源和单实例授权。本库没有实现完整 ACL reader，不能声称完成 admission。只有叶句柄不能替代祖先 ACL。其他 EXE 路径不会自动继承保护。

首次安装在一个事务内建立持久 sublayer 与四个 AppId 全阻断（CONNECT v4/v6，RECV_ACCEPT v4/v6）。采用独立 GUID；不创建 provider 对象，避免无对应自动启动服务的 provider 重启启用语义。固定的七个潜在 filter keys 与独立 sublayer 构成所有权命名空间。

ProxyOnly 仅事务替换自有 CONNECT_V4：AppId AND 非 TCP；AppId AND TCP AND remoteIP != 127.0.0.1；AppId AND TCP AND remotePort != P。其余 v6/incoming 全拒绝原 ID 保留。没有 PERMIT；所有浏览器 UDP 拒绝。端口必须非零。

每次变更之前、事务内、提交之后都精确枚举校验；返回实际 filterId 及已验证 Rule。校验 key、provider 无绑定、sublayer、layer、BLOCK、persistent flags、weight、rawContext、providerData、所有条件的字段/类型/比较/值（含完整 AppId bytes/主机序 IP/port），不是只看数量。任何命名空间内额外、缺失、重复或范围不符规则均拒绝；绝不删外部 filter。重复相同策略不新增 filter。重启接管仅接受精确 Offline 或精确 ProxyOnly，然后恢复 Offline。

析构及错误路径只关闭句柄，不撤销持久策略。事务失败保持之前已提交策略；**如果之前是 ProxyOnly，失败不会凭空变成 Offline**。所有失败都必须阻止启动/后续联网并由父级关闭精确浏览器树；restoreOffline 失败不能当成已恢复。安装失败后的对象不可用于联网转换，须保留持久状态并重新构造接管。Windows API 错误仅包含固定 operation 与 DWORD，不含路径/凭据。不得以 lifecycle enum 或返回成功代替真实授权。

`cleanupAfterExactTreeExit` 是唯一撤销操作：调用者必须先凭保留的真实 OS 进程句柄观察整个精确 CEF 树退出；本库不自行证明该前提。先验证全部自有策略，再事务删除精确 IDs/subLayer；提交后逐 key 读回不存在。析构不调用它。清理后对象不可再次安装。

## 实际验证及未验证边界

小型 portable condition/transition 测试先 RED（缺 header），再 GREEN；增加 Offline 错配 port 的断言先 RED（assert），再 GREEN。无新框架。它不模拟 WFP 安装，也不证明网络隔离。

Linux：
```
cmake -S drivers/wfp-prototype -B "$OWN_SCRATCH_BUILD" -DORANGESPACE_WFP_PROTOTYPE_POLICY_TESTS=ON
cmake --build "$OWN_SCRATCH_BUILD" --parallel 1
ctest --test-dir "$OWN_SCRATCH_BUILD" --output-on-failure
```
Windows/MSVC 兼容构建：此目录已使用私有 clang-cl/LLD 与 Microsoft CRT/Windows SDK 实际编译、链接原生验证 EXE；未安装全局工具链。旧 MinGW SDK 缺 WFP GUID 的限制不再代表当前构建状态。链接 fwpuclnt/rpcrt4/ole32/uuid；验证 EXE 另链接 ws2_32。

Windows 11 的隔离 API 验证已实际通过：新命名空间预检、持久 Offline 安装与精确读回、ProxyOnly 事务与精确读回、恢复 Offline、空浏览器树前提下精确清理和重新打开引擎确认命名空间不存在。该机初始读回 flags 为 `PERSISTENT | INDEXED`，已显式声明两者并保留完整相等比较；没有忽略未知标志。验证结束已清理测试规则，不表示当前已安装真实浏览器策略。

真实 socket 阻断矩阵、幂等/崩溃/重启、规则生效期间的外部应用正控、全树身份与 CEF sandbox 兼容仍待完成。持久不等于 boot-time 阻断。AppId 不能解决 DNS Client 代查；本库不禁止或证明 requester-scoped DNS RPC。127.0.0.1:P 不是 listener 身份：父级须独占绑定、独立认证 HTTP/CONNECT、租约与实例授权、停止与端口复用防护；服务崩溃后残留 ProxyOnly 仍允许该地址/端口，不能作为 crash-safe admission 证明。**DNS/OS/CEF 未通过前浏览器门禁保持关闭**；隔离 API 实验不授权真实浏览器启动。
