# 干净源码开发包构建（不执行安装/服务）

必须从**包含完整交付源码和本入口、已提交且干净的 checkout** 运行；允许父任务创建的本地私有验证 commit，不要求 push/remote。入口拒绝 WIP，以 `git archive HEAD` 导出新源树，不读取 ignored dist、venv、node_modules、target 或历史 PE。三个角色每次分别全新构建。

```sh
export TMPDIR=/var/tmp/hermes-runtime/tmp
# DEPS/输出均在 checkout 外；输出及 receipt 必须不存在。
python3 deploy/packages/build.py control --deps "$DEPS" --output /absolute/output/control-dev.tar.gz
python3 deploy/packages/build.py node --deps "$DEPS" --output /absolute/output/node-dev.tar.gz
python3 deploy/packages/build.py windows --windows-builder gnu --deps "$DEPS" --output /absolute/output/windows-dev.zip
```

Windows 默认 `gnu`：Linux 上已安装的 Windows GNU Rust target、MinGW POSIX C++/gcc/windres/objdump、make、CMake；**不新增 WSL、VS 或 MSVC 前置条件**。Cargo `--locked --offline --jobs 1` 从源码重建 runtime 静态库和 broker；现有根 CMake 通过 `ORANGESPACE_RUNTIME_LIBRARY` 链接新库，构建 OrangeSpace、OrangeSpaceLogin、OrangeSpaceService，`--parallel 1`。C++ EXE `-static -static-libgcc -static-libstdc++`，Rust GNU `+crt-static`；objdump 拒绝 libgcc/libstdc++/libwinpthread/VC redist 动态依赖，允许 Windows 系统 DLL。helper 唯一例外：从固定官方 Windows ZIP 核对归档 SHA-256，再提取唯一 sing-box.exe 并核对二进制 SHA-256；不接收裸缓存 EXE、不重建 helper、不复用旧生产 PE。最后复用 `deploy/windows-dev/package.py create/verify` 精确五文件协议。

保留可选 `--windows-builder wsl-native` 调用既有 `Build.ps1 -Offline`；只有选这条路线才需要 WSL 互操作、Windows cargo.exe/cmake.exe/powershell.exe 和 VS/SDK。该路径未实测，不代表 GNU 必须安装它。交叉构建成功不等于 Windows 原生、签名、GUI 或业务验收。

入口持有 `flock(2)` `/var/tmp/hermes-runtime/tmp/orangespace-build.lock` 直到归档读回结束，**不要外套同一锁**；工作目录/TMPDIR 固定该盘，所有编译单任务。构建不下载、不操作 DB/服务；失败不转发可能含凭据的子进程诊断。

## 最小依赖库存准备（单独授权后执行，本轮没有执行网络）

Linux Python 3.12+、venv/pip；Node `>=26 <27`，npm `>=11 <13`。兼容用户宿主 v26.7.0/npm12.0.2，亦兼容本次 PATH 探测的 v26.11.1/npm11.20.0；manifest 总是记录实际值，不捏造精确 pin。Rust/Cargo/CMake/MinGW 的实际版本和 PE imports 也写入 manifest。现有 approved helper、Python build pins 保留在 dependencies.json。

以下在父已整合的干净源码仓库执行，`DEPS` 是新的 checkout 外绝对目录；不需要复制旧 node_modules/venv/PE。网络只用于**按现有锁从官方源准备库存**，不是离线 builder 的回退：

```sh
export TMPDIR=/var/tmp/hermes-runtime/tmp
export DEPS=/absolute/reviewed-dependencies
mkdir -p "$DEPS/wheels" "$DEPS/npm-cache"
python3 - <<'PY'
import json, os
from pathlib import Path
pins=json.loads(Path('deploy/packages/dependencies.json').read_text())
(Path(os.environ['DEPS'])/'build-requirements.lock').write_text(''.join(f'{n}=={v}\n' for n,v in pins['python_build'].items()))
PY
python3 -m pip --isolated download --index-url https://pypi.org/simple --only-binary=:all: --no-deps \
  --dest "$DEPS/wheels" -r server/requirements.lock -r "$DEPS/build-requirements.lock"
# 将每个 wheel 与 PyPI 官方版本元数据里的 filename/SHA-256 比对后生成 inventory，
# 不把未知 cache 的自算 digest 当成信任依据。
python3 - <<'PY'
import email, hashlib, json, os, urllib.request, zipfile
from pathlib import Path
root=Path(os.environ['DEPS']); inventory={}
for path in sorted((root/'wheels').glob('*.whl')):
    with zipfile.ZipFile(path) as z:
        names=[n for n in z.namelist() if n.endswith('.dist-info/METADATA')]
        assert len(names)==1
        meta=email.message_from_bytes(z.read(names[0]))
    url='https://pypi.org/pypi/'+meta['Name']+'/'+meta['Version']+'/json'
    with urllib.request.urlopen(url) as response: release=json.load(response)
    matches=[r['digests']['sha256'] for r in release['urls'] if r['filename']==path.name]
    actual=hashlib.sha256(path.read_bytes()).hexdigest()
    assert matches==[actual], path.name
    inventory[path.name]=actual
(root/'wheels.sha256.json').write_text(json.dumps(inventory,indent=2)+'\n')
PY
# 新建、仅含锁定 frontend 源码的目录；不运行 install scripts。
FRONTEND=$(mktemp -d "$TMPDIR/orangespace-npm-input.XXXXXX")
git archive HEAD apps/control-console | tar -x -C "$FRONTEND"
(cd "$FRONTEND/apps/control-console" && npm ci --ignore-scripts --no-audit --no-fund \
  --registry=https://registry.npmjs.org --cache "$DEPS/npm-cache")
# 沿用本机 Cargo cache，不新增 vendor/framework；只取 Windows 目标锁定依赖。
cargo fetch --locked --target x86_64-pc-windows-gnu
```

上述 Python inventory 是官方 PyPI HTTPS 元数据核对，inventory 的审核/保管仍由调用者负责；不是独立签名证明。一个解释器/平台准备一份兼容 wheelhouse，入口复核全部 hash、METADATA 名称和 approved exact pins，拒绝缺项/漂移。

node/windows 另需 helper 库存（可复用**经以下固定 hash 复核的依赖输入**，不是旧生产程序）：

```sh
curl --fail --location --proto '=https' --tlsv1.2 \
  https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-linux-amd64.tar.gz \
  --output "$DEPS/sing-box-1.14.4-linux-amd64.tar.gz"
curl --fail --location --proto '=https' --tlsv1.2 \
  https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-windows-amd64.zip \
  --output "$DEPS/sing-box-1.14.4-windows-amd64.zip"
curl --fail --location --proto '=https' --tlsv1.2 \
  https://codeload.github.com/SagerNet/sing-box/tar.gz/refs/tags/v1.14.4 \
  --output "$DEPS/sing-box-v1.14.4-source.tar.gz"
```

`DEPS/LICENSE.sing-box`、`DEPS/COPYING.GPL-3.0` 从已批准依赖输入取得；Windows 使用上述官方 ZIP，不使用裸 EXE。准确 SHA-256 均在 dependencies.json。最少复制/复核命令（`APPROVED` 指明确审核的依赖目录，允许从历史包仅取这两个许可证，绝不取四个生产 PE）：

```sh
cp "$APPROVED/LICENSE.sing-box" "$DEPS/LICENSE.sing-box"
cp "$APPROVED/COPYING.GPL-3.0" "$DEPS/COPYING.GPL-3.0"

python3 - <<'PY'
import hashlib, json, os
from pathlib import Path
root=Path(os.environ['DEPS'])
pin=json.loads(Path('deploy/packages/dependencies.json').read_text())['helper']
expected=dict(pin['files'])
expected[pin['linux_archive']]=pin['linux_archive_sha256']
expected[pin['windows_archive']]=pin['windows_archive_sha256']
for name, sha in expected.items():
    assert hashlib.sha256((root/name).read_bytes()).hexdigest()==sha, name
print('approved helper inputs verified')
PY
```

2026-10-31 父任务已核对官方 SagerNet GitHub release asset.digest 与下载的 Windows ZIP SHA-256 一致（`99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df`），其中唯一 sing-box.exe 与 approved binary SHA-256 一致（`8f30682ee198855440d2a7fe070d5d3653793b2d01bb8c85eea88f93bbe7c8b9`）；这是发布者 HTTPS 元数据核对，不是代码签名证明。**仅取得这些依赖输入即可，不能复制旧 OrangeSpace/登录/Service/broker PE。** builder 在打包前核对 source/license/Linux archive+binary/Windows ZIP+binary 固定 hash；GNU 与可选 WSL 分支复用同一个验证提取函数，WSL 在调用 Build.ps1 前把验证后的字节写入自有临时 helper 路径。没有符合 approved hash 的 helper 输入时停止。

## 包内容与边界

control/node 复用统一 server wheel，control 执行离线 npm ci、typecheck、build；node 含 `examples/database.example.json`、两个 `deploy/linux-node/*.runtime.example.json`、`server/alembic-node.ini`，以及现有部署说明和固定 helper。数据库示例仅保留占位用户名/密码、保留名称验证的 TLS CA 路径，部署者在包外准备受保护配置。

Windows `payload/` 仍严格只有五个 EXE 与原协议 manifest，`examples/` 在 payload 外，复用旧包已许可的 platform/nodes/fresh-only state 非秘密样例。示例不能连接，不携带账号、token、私钥、旧 ACCEPTANCE；fresh-only state 不得覆盖已有账本。部署脚本照旧校验精确 payload。

`BUILD-MANIFEST.json` v2 记录真实 source_commit/clean、实际工具版本、锁/input hash、payload 路径/size/SHA-256、扫描策略和 build-only 范围。`SHA256SUMS` 不自引用；旁置 receipt 记录归档 SHA-256、成员总数及逐成员读回核验。普通文件/链接/路径/私钥/非示例 DSN 扫描是有限规则，不是完整秘密检测，不承诺 bit-for-bit reproducibility。

## 本次验证 / 尚未验证

```sh
TMPDIR=/var/tmp/hermes-runtime/tmp PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s deploy/packages/tests -v
```

本次仅必要定点测试及 Python/JSON 语法核对；没有大编译、下载、DB、服务、stage/commit/push/remote。**新 GNU 分支尚未实际编译，不称 ready 或已重建三包。** 父任务需提交完整 overlay 后实际执行三次干净构建与后续授权验收；历史 frozen-inputs/build metadata 只用于确认 GNU 路线、静态链接及 helper pin，不继承旧字节验收。
