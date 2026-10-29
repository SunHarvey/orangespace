# 参考与第三方组件

- IdenGrid：[SunHarvey/idengrid](https://github.com/SunHarvey/idengrid)，参考身份、节点和隧道组织思路。审阅参考提交 `733bda384e123efd226716e2b3afbd7d5be80a4a`，未复制其源码。
- CEF：[chromiumembedded/cef](https://github.com/chromiumembedded/cef)，当前仅接入组件源码，不分发 CEF/Chromium 二进制。真正打包时须包含所用发行包的许可和 notices。
- sing-box：[SagerNet/sing-box](https://github.com/SagerNet/sing-box)，测试与配置目标固定 1.14.4；本仓库不内置该二进制。其分发条款以官方发行包 LICENSE 为准。
- Rust 与 Python 的实际依赖版本分别记录在 `Cargo.lock` 和 `server/requirements.lock`，第三方许可仍归其权利人。
- Logo 来自用户已确认的设计原图，保存在 `assets/brand/`；尚未制作 ICO 或矢量版。

本项目自身的对外分发许可证尚未确定，没有替用户选择开源许可。
