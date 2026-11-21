# 参考与第三方组件

- IdenGrid：[SunHarvey/idengrid](https://github.com/SunHarvey/idengrid)，参考身份、节点和隧道组织思路。审阅参考提交 `733bda384e123efd226716e2b3afbd7d5be80a4a`，未复制其源码。
- sing-box：[SagerNet/sing-box](https://github.com/SagerNet/sing-box)，固定 1.14.4（GPL-3.0-or-later）。本仓库不内置该二进制；构建发行版时下载官方 Linux amd64 发行包并校验摘要，随安装包分发，源码获取方式写在 `deploy/windows/SOURCES.md`。
- Debian 软件包：发行版根文件系统与桌面镜像都由 Debian 13 软件包组成，构建时分别生成完整软件包清单（`*.packages.tsv`），随安装包放在 `licenses` 文件夹。
- 桌面容器 seccomp 配置以 Moby v25.0.5 默认配置为基础（Apache-2.0）。
- Rust 与 Python 的实际依赖版本分别记录在 `Cargo.lock` 和 `server/requirements.lock`，第三方许可仍归其权利人。客户端静态链接的 Rust 库由 `scripts/rust_notices.py` 汇总许可，随安装包分发。
- Logo 来自用户已确认的设计原图，保存在 `assets/brand/`；尚未制作 ICO 或矢量版。

本项目自身的对外分发许可证尚未确定，没有替用户选择开源许可。
