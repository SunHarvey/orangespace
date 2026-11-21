# Rust 组件

仓库最低 Rust 为 **1.89**，两个 crate 都是根工作区成员，构建与测试从仓库根目录执行（`cargo test --workspace --locked`）。

## orangespace-https

Windows 客户端的应用私有 HTTPS：C ABI 静态库（`include/orangespace_https.h`，`os_https_request_v1` 与节点文件传输用的 `os_https_transfer_v1`），rustls 只信任客户端传入的钉住 CA，不用系统根证书、不读代理环境、不跟随重定向。客户端的中心与节点会话（`apps/windows-client` 的 `node_session`）链接它；`scripts/build-windows.ps1` 先构建它再构建客户端。接口约束见 [orangespace-https/README.md](orangespace-https/README.md)。

## orangespace-core

绑定与代次模型（用户/沙盒/节点/代次/隧道显式绑定）、文件任务的节点归属、sing-box TUIC 配置生成，以及 helper 子进程监督（配置只经 stdin，Windows 上每个绑定一个 kill-on-close Job）。这些是旧原生路线的 Rust 部分，路线图列为可复用；WSL 桌面路线目前没有调用它（每沙盒网关的 TUIC 配置由 `linux-desktop/network/gateway.py` 生成）。真实 sing-box 生命周期测试需 `ORANGESPACE_TEST_SING_BOX` 指向官方 1.14.4 程序：

```sh
ORANGESPACE_TEST_SING_BOX=/absolute/path/to/sing-box cargo test -p orangespace-core --locked --test helper_runtime -- --ignored
```

本地 broker CLI 与 Windows 服务用的 `orangespace-runtime` 已随旧路线删除，见 git 历史与 [docs/archive](../docs/archive/README.md)。
