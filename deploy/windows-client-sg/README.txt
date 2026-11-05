OrangeSpace SG Windows 安装说明

1. 核对交付方提供的 ZIP SHA-256；清单校验仅证明文件闭合，不代替发行签名或可信来源。
2. 将整个 ZIP 解压到本机普通目录，不要在压缩文件预览里直接运行。
3. 双击 Install.cmd。仅安装/卸载需要管理员 UAC；服务从受保护的 Program Files 启动，不从桌面启动。
4. 回到普通用户桌面，双击 OrangeSpace 快捷方式显示登录页；Install.cmd 的原普通用户调用会自动打开 GUI。
   如果直接以管理员身份运行安装器，安装后请自行从普通桌面打开；不要以管理员运行 GUI。
   也可以双击 Start.cmd。它不启停服务，不接收或打印登录凭据。
5. 配置已经由构建方注入，不需要输入 UUID、端口、源站或 helper 密码；登录凭据仅在实际 GUI 本机输入。
   使用真实授权列表中的 SG；香港浏览、本轮未验证的功能不因脚本安装成功而自动获得验收。

唯一安装位置：C:\Program Files\OrangeSpace-SinglePrototype-SG-v25-20261104
唯一服务：OrangeSpaceSinglePrototype.SG.v25（LocalSystem，开机自动启动）
私有代次账本：C:\Program Files\OrangeSpace-SinglePrototype-SG-v25-State
实际使用系统 Program Files 已知目录，不信任环境变量覆盖路径。

卸载：先正常关闭 OrangeSpace，再双击 Uninstall.cmd 并确认 UAC。
卸载只处理此服务、受闭合清单约束的安装目录、指向本安装的同名桌面快捷方式。
默认永久保留用户 AppData / SQLite / 浏览器 Profile、Cookie 和私有代次账本；不删除 Linux 个人文件。
安装不会覆盖已有安装；先按上述步骤卸载。重新安装时已有账本必须通过原权限和格式校验，绝不重置。
如果服务、文件或进程归属不明，脚本失败并保留现场，不按同名进程批量终止。
本安装器不修改系统 TLS 信任、全局防火墙、其他服务或任务。
当前没有独立产品级持久 WFP 清理命令；服务正常 stop 做其自身清理，可能保留本路径的持久 deny。
安装器绝不全局重置 WFP；这不影响其他应用的网络，但最终卸载清理仍需原产品接口验证。

脚本使用 Windows PowerShell 5.1，仅本进程 RemoteSigned，不修改强制策略、不使用 PolicyBypass。
若下载标记/组织策略拒绝脚本，请先核对来源与哈希，在 ZIP 属性中按组织流程解除来源阻止后重新解压；
强制签名策略环境需要交付方签署脚本，不要通过降低策略绕过。
失败时仅输出固定阶段标签，不显示原始异常、配置或凭据；保留文件供管理员核查。

构建方说明（源码仓库 deploy/windows-client-sg/README.md）：
输入已经核验的完整 CEF runtime 与 fresh Service/GUI/broker 路径，以及受保护、无密配置目录；
assemble.py 会生成包含所有文件的 runtime.inventory.tsv、安装根脚本、中文说明和 ZIP，并逐成员读回核对。
如果是在本轮同一 namespace 恢复桌面候选 State，构建方必须传 --state-dir，不得用 fresh 空账本代替旧账本。
包内 State 只在 Program Files 私有 State 不存在时按固定 hash 恢复；已有 State 始终优先验证保留。
本说明不是 Windows 原生安装、普通用户登录、CEF 浏览或 WFP 隔离已经通过的声明。
