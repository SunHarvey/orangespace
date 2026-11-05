# WFP 阻断基础组件

这是用户态 WFP 策略工具，不是内核 TCP/UDP 接管驱动。只为指定的
`OrangeSpace.BrowserHost.exe` 安装 IPv4/IPv6 的连接与接收阻断规则；不创建任何放行规则。
规则在事务中提交并持久化，工具退出后保留。它不会修改系统代理或其他软件的规则。

管理员终端中手动使用（当前管理器不自动安装）：

```powershell
orangespace-wfp-baseline.exe install 'C:\OrangeSpace\OrangeSpace.BrowserHost.exe'
orangespace-wfp-baseline.exe status
orangespace-wfp-baseline.exe remove
```

`remove` 仅删除 OrangeSpace 专用 sublayer 下的规则。重复 install 可能增加重复阻断规则，
全部可由 remove 删除。该工具只供 Windows 开发验证，不应替代服务安装器。

**无论安装了多少条阻断规则，browsing_allowed 均为 false。**
未实现受限身份/子进程跟踪、ALE TCP 重定向、UDP 捕获和回注、系统 DNS 代查治理、
受保护 IPC、驱动签名和启动时保护。按 EXE 路径阻断也不等于按沙盒 SID 隔离。
不能以这个工具作为完整网络防护验收通过的证明。

实现依据：[FwpmFilterAdd0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilteradd0)、
[FWPM_FILTER0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0)。
