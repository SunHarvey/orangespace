# 橙域随附的第三方软件与源码获取方式

橙域安装包里除了橙域自己的程序，还包含下列第三方软件。它们的权利归各自作者，按各自的许可分发。本文件所在的 `licenses` 文件夹里有完整清单。

## Linux 系统（WSL 发行版 `OrangeSpace`）

- **Debian 13（trixie）软件包**：完整清单见 `rootfs-packages.tsv`。每行依次是包名、版本、源码包名、源码包版本。
  - 每个包的版权与许可文件在发行版内的 `/usr/share/doc/<包名>/copyright`。
  - 源码可从 Debian 存档获取，例如 `apt-get source <源码包>=<版本>`，或在 <https://snapshot.debian.org/> 按源码包名和版本下载。
- **sing-box 1.14.4**：官方发布的 Linux amd64 二进制，位于 `/usr/local/bin/sing-box`，许可为 GPL-3.0-or-later。
  - 对应源码：<https://github.com/SagerNet/sing-box/tree/v1.14.4>。
- **桌面容器 seccomp 配置**：以 Moby v25.0.5 的默认配置为基础，并为 Chromium 自身沙盒做了扩展，位于 `/etc/orangespace/desktop-seccomp.json`，许可为 Apache-2.0。
  - 来源：<https://github.com/moby/moby/blob/v25.0.5/profiles/seccomp/default.json>。

## 桌面环境（每个沙盒的容器镜像）

- **基础镜像**：Debian 13 slim 官方镜像，摘要见 `desktop-image-base.txt`。
- **镜像内的 Debian 软件包**：清单见 `desktop-image-packages.tsv`，格式同上，包括 Chromium、LXQt、fcitx5 等。
  - 源码获取方式同上。
  - 镜像内的版权文件在容器的 `/usr/share/doc/<包名>/copyright`。

## Windows 客户端

- `OrangeSpace.exe` 静态链接了若干 Rust 库，清单、许可和来源见 `rust-crates.txt`。

## 橙域自身

橙域自己的程序与脚本不在上述第三方许可之内。
