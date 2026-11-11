# `livekit_sdk@1.13.0` 构建与 BCR 平台拆分

本文说明上游 `livekit_sdk@1.13.0` 的官方发布包、Rust FFI 补丁，以及 BCR 修订
`1.13.0.bcr.4` 如何按 Linux 架构选择 SDK。上游 `1.13.0` 版本目录保持不变；
BCR 平台拆分通过追加修订发布。

---

## 1. 组成结构说明

`@livekit_sdk//:livekit_sdk` 由两部分组成：

1. **官方预编译 C++ SDK 基础包（`include/livekit/*.h` + `lib/liblivekit.so`）**
   - 来源：`https://github.com/livekit/client-sdk-cpp/releases/download/v1.13.0/livekit-sdk-ubuntu-22.04-x64-1.13.0.tar.gz`
   - SHA256：`60712578e14350689beeff36675088c8b91c1050b906441f71db312089fe8fa8`
   - SRI Integrity：`sha256-YHEleOFDUGib7v82Z1CIyLkcEFC5BkQfcdsxIIn+j6g=`
   - ARM64 来源：`https://github.com/livekit/client-sdk-cpp/releases/download/v1.13.0/livekit-sdk-ubuntu-22.04-arm64-1.13.0.tar.gz`
   - ARM64 SHA256：`6c8a028fadce09e31fca33c862877150697e1086ed601b676fa960aca2bdffa4`

2. **修复了纯 DataChannel 发送方身份识别的 Rust FFI（Overlay 覆盖）**
   - x86_64 文件：`lib/liblivekit_ffi.so`
   - ARM64 文件：`lib/liblivekit_ffi_arm64.so`
   - **为什么需要补丁**：
     在 LiveKit SFU 中，远程驾驶前端（浏览器控制端）仅通过 DataChannel 发送控制包（不发布音视频 Track）。SFU 会对非媒体发布者的 `ParticipantUpdate` 信令做批处理延迟下发；当首个 `vehicle.control.v2` 数据包到达车端时，`livekit-ffi`（Rust 层 `RoomInner::handle_data`）若尚未在本地 `participants` 表中查到该远端参与者，会将 `event.participant` 置为 `None`，导致车端 `ControlReceiver` 无法校验 `event.participant->identity() == expected_sender_id`。
   - **补丁内容**：
     基于 `livekit-sdk-cpp v1.13.0` 对应的 `livekit/rust-sdks` 提交 `ede8ac53843a8fb91d6f4fb5629f5245f1758e38`，应用本目录下的：
     - `livekit-data-sender.patch`
     - `livekit_sender.rs`
     当收到带有 SFU 认证元数据（`participant_identity` 非空且 `participant_sid` 以 `"PA_"` 开头）的数据包但本地尚未注册该参与者时，立即用 SFU 认证的 `identity/sid` 注册远端参与者并填充 `event.participant`。

---

## 2. 编译生成补丁版 `liblivekit_ffi.so` 的完整步骤

### 2.1 环境依赖
- Ubuntu 22.04 x86_64 或 AArch64 原生构建环境
- Rust 工具链（`cargo` / `rustc`）
- `cmake >= 3.20`、`patch`、`tar`、`protobuf-compiler` (`protoc`)、`clang`/`llvm-dev`

### 2.2 一键复现编译命令
直接调用本目录下的 `LiveKitFFIPatch.cmake` 脚本即可自动下载固定 commit 的源码、校验 SHA256、打补丁并编译出当前主机架构的 `liblivekit_ffi.so`。分别在 x86_64 和 AArch64 原生环境构建，产物放入 BCR overlay 时分别命名为 `liblivekit_ffi.so` 和 `liblivekit_ffi_arm64.so`。

```bash
WORK_DIR=/tmp/livekit-ffi-build
SCRIPT_DIR=/home/wfh/01code/apollo-base/data/sdk-kit/livekit/livekit_ffi

cmake \
  -DEDGE_FFI_WORK="${WORK_DIR}" \
  -DEDGE_FFI_PATCH="${SCRIPT_DIR}/livekit-data-sender.patch" \
  -DEDGE_FFI_SENDER="${SCRIPT_DIR}/livekit_sender.rs" \
  -DEDGE_FFI_LIBRARY="${WORK_DIR}/liblivekit_ffi.so" \
  -DEDGE_CARGO="$(command -v cargo)" \
  -DEDGE_PATCH="$(command -v patch)" \
  -P "${SCRIPT_DIR}/LiveKitFFIPatch.cmake"
```

该脚本内部执行的固定版本与校验值如下：
1. 下载 `https://codeload.github.com/livekit/rust-sdks/tar.gz/ede8ac53843a8fb91d6f4fb5629f5245f1758e38`
   - 校验 SHA256：`9b9266fa6dd061f138f6386658e9082e46eca2c5c745d588653ad4968d3c6cfa`
2. 下载子模块 `livekit/protocol`（`3fbe509850cb24aa90a0bc20134936698333dceb`）
   - 校验 SHA256：`56ab5173ba657ec84037a69679dfa8f1d7ec275913669ac5f5c5ddb878ba375a`
3. 下载子模块 `libyuv`（`917276084a49be726c90292ff0a6b0a3d571a6af`）
   - 校验 SHA256：`eaf0d447eb2ce4a5eab6e4a9af53a81f551bd36bca06e9441e28e6cb54b28e8d`
4. 应用 `livekit-data-sender.patch` 并拷入 `livekit/src/room/data_sender.rs`。
5. 执行 `cargo build --locked --release -p livekit-ffi` 产出 `${WORK_DIR}/liblivekit_ffi.so`。

---

## 3. BCR 平台选择与修订文件

修订位于 `data/bazel-central-registry/modules/livekit_sdk/1.13.0.bcr.4`。它为 x86_64
和 AArch64 声明对称的 `livekit_linux_<arch>` 外部仓库，分别固定官方归档 URL、SHA256
和匹配架构的补丁 FFI。两边均导出 `livekit_sdk` 与 `runtime_libs`，模块顶层再按
`@platforms//cpu` 和 `@platforms//os:linux` 自动选择；其他平台标记为不兼容。

两个补丁 FFI 文件放在该修订的 `overlay/lib/` 目录。重建后，将各架构产物放入对应文件，
再计算每个 overlay 文件的 SRI（`sha256-<base64>`）并同步写入 `source.json`：

```bash
BCR_MOD=/home/wfh/01code/apollo-base/data/bazel-central-registry/modules/livekit_sdk/1.13.0.bcr.4

# 1. 将两种架构的补丁产物放入 overlay/lib/
mkdir -p "${BCR_MOD}/overlay/lib"
cp -f /tmp/livekit-ffi-build-x86_64/liblivekit_ffi.so "${BCR_MOD}/overlay/lib/liblivekit_ffi.so"
cp -f /tmp/livekit-ffi-build-aarch64/liblivekit_ffi.so "${BCR_MOD}/overlay/lib/liblivekit_ffi_arm64.so"

# 2. 计算各文件的 SRI 哈希 (sha256-<base64>)
sri_hash() {
  echo "sha256-$(openssl dgst -sha256 -binary "$1" | openssl base64 -A)"
}

echo "BUILD.bazel:                    $(sri_hash "${BCR_MOD}/overlay/BUILD.bazel")"
echo "MODULE.bazel:                   $(sri_hash "${BCR_MOD}/overlay/MODULE.bazel")"
echo "lib/liblivekit_ffi.so:          $(sri_hash "${BCR_MOD}/overlay/lib/liblivekit_ffi.so")"
echo "lib/liblivekit_ffi_arm64.so:    $(sri_hash "${BCR_MOD}/overlay/lib/liblivekit_ffi_arm64.so")"
```

最终的 `modules/livekit_sdk/1.13.0.bcr.4/source.json` 记录 x86_64 主归档和所有 overlay
文件的完整性值；ARM64 归档则由固定 SHA256 的平台仓库规则获取。不要改写已发布版本目录，
应通过新的 `.bcr.N` 修订更新。

构建时，`@livekit_sdk//:livekit_sdk` 和 `@livekit_sdk//:runtime_libs` 根据目标平台自动选择
`livekit_linux_x86_64` 或 `livekit_linux_aarch64`。对应仓库下载固定校验的官方归档，并替换
归档中的官方 FFI 为同架构的补丁版；其他操作系统和 CPU 架构不兼容。
