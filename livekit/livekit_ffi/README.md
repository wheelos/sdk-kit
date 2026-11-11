# `livekit_sdk@1.13.0` 构建与 BCR 平台拆分

本文说明 `livekit_sdk@1.13.0` 的 Rust FFI 补丁，以及本地 BCR 中按 Linux 架构选择 SDK 的实现。
本地 BCR 的 `1.13.0` 由 WheelOS 平台归档提供 x86_64 和 AArch64 SDK。

---

## 1. 组成结构说明

`@livekit_sdk//:livekit_sdk` 由两部分组成：

1. **按平台发布的 SDK 归档（包含头文件及补丁版 `.so`）**
   - x86_64：`https://dl.wheelos.cn/release/public/livekit_sdk/1.13.0/linux-x86_64/livekit-sdk-1.13.0-linux-x86_64.tar.gz`
   - x86_64 SHA256：`c713ebc7f67e40a85baeaa0acc19e4e96d10042a0f7bd6639f3db1bff53f795a`
   - AArch64：`https://dl.wheelos.cn/release/public/livekit_sdk/1.13.0/linux-aarch64/livekit-sdk-1.13.0-linux-aarch64.tar.gz`
   - AArch64 SHA256：`a5edbd476a4ca4f7c34a682c22e9b7b901a008400adb596fc4c89d4614ad50b5`
   - 两个归档均包含 `include/livekit/`、`lib/liblivekit.so` 和补丁版 `lib/liblivekit_ffi.so`。BCR 只保存带校验值的下载规则，不再保存 FFI `.so` 文件。

2. **补丁版 Rust FFI 的来源**
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
直接调用本目录下的 `LiveKitFFIPatch.cmake` 脚本即可自动下载固定 commit 的源码、校验 SHA256、打补丁并编译出当前主机架构的 `liblivekit_ffi.so`。分别在 x86_64 和 AArch64 原生环境构建，将匹配架构的 SDK 归档发布到 WheelOS 下载服务；不要把 `.so` 放入 BCR 仓库。

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

规则位于 `data/bazel-central-registry/modules/livekit_sdk/1.13.0`。它为 x86_64
和 AArch64 声明对称的 `livekit_linux_<arch>` 外部仓库，分别固定归档 URL、SHA256。
两边均导出 `livekit_sdk` 与 `runtime_libs`，模块顶层再按
`@platforms//cpu` 和 `@platforms//os:linux` 自动选择；其他平台标记为不兼容。

LiveKit 二进制归档由 WheelOS 发布服务托管，BCR overlay 中不存放 `.so`。如需更新 Bazel
规则，计算 overlay 文件的 SRI（`sha256-<base64>`）并同步写入 `source.json`：

```bash
BCR_MOD=/home/wfh/01code/apollo-base/data/bazel-central-registry/modules/livekit_sdk/1.13.0

# 计算各 overlay 文件的 SRI 哈希 (sha256-<base64>)
sri_hash() {
  echo "sha256-$(openssl dgst -sha256 -binary "$1" | openssl base64 -A)"
}

for file in BUILD.bazel MODULE.bazel livekit_repositories.bzl sdk.BUILD.bazel; do
  echo "${file}: $(sri_hash "${BCR_MOD}/overlay/${file}")"
done
```

最终的 `modules/livekit_sdk/1.13.0/source.json` 记录 BCR 基础归档及 overlay
文件的完整性值；平台 SDK 归档则由固定 SHA256 的外部仓库规则获取。不要改写已发布版本目录，
该本地开发注册表按要求直接将平台选择规则放入 `1.13.0`。

构建时，`@livekit_sdk//:livekit_sdk` 和 `@livekit_sdk//:runtime_libs` 根据目标平台自动选择
`livekit_linux_x86_64` 或 `livekit_linux_aarch64`。对应仓库下载固定校验的远程归档；
其他操作系统和 CPU 架构不兼容。
