# `livekit_sdk@1.13.0` 构建与 BCR 模块生成文档

`data/bazel-central-registry/modules/livekit_sdk/1.13.0` 是如何从官方发布包与 Rust FFI 补丁构建生成的完整说明。

---

## 1. 组成结构说明

`@livekit_sdk//:livekit_sdk` 由两部分组成：

1. **官方预编译 C++ SDK 基础包（`include/livekit/*.h` + `lib/liblivekit.so`）**
   - 来源：`https://github.com/livekit/client-sdk-cpp/releases/download/v1.13.0/livekit-sdk-ubuntu-22.04-x64-1.13.0.tar.gz`
   - SHA256：`60712578e14350689beeff36675088c8b91c1050b906441f71db312089fe8fa8`
   - SRI Integrity：`sha256-YHEleOFDUGib7v82Z1CIyLkcEFC5BkQfcdsxIIn+j6g=`

2. **修复了纯 DataChannel 发送方身份识别的 `lib/liblivekit_ffi.so`（Overlay 覆盖）**
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
- Ubuntu 22.04 x86_64
- Rust 工具链（`cargo` / `rustc`）
- `cmake >= 3.20`、`patch`、`tar`、`protobuf-compiler` (`protoc`)、`clang`/`llvm-dev`

### 2.2 一键复现编译命令
直接调用本目录下的 `LiveKitFFIPatch.cmake` 脚本即可自动下载固定 commit 的源码、校验 SHA256、打补丁并编译出 `liblivekit_ffi.so`：

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

## 3. 生成 `data/bazel-central-registry/modules/livekit_sdk/1.13.0` 的步骤

将编译好的 `liblivekit_ffi.so` 放入 BCR 模块的 `overlay/lib/` 目录，并计算 SRI（`sha256-<base64>`）写入 `source.json`：

```bash
BCR_MOD=/home/wfh/01code/apollo-base/data/bazel-central-registry/modules/livekit_sdk/1.13.0

# 1. 拷贝补丁后的 liblivekit_ffi.so 到 overlay/lib/
mkdir -p "${BCR_MOD}/overlay/lib"
cp -f /tmp/livekit-ffi-build/liblivekit_ffi.so "${BCR_MOD}/overlay/lib/liblivekit_ffi.so"

# 2. 计算各文件的 SRI 哈希 (sha256-<base64>)
sri_hash() {
  echo "sha256-$(openssl dgst -sha256 -binary "$1" | openssl base64 -A)"
}

echo "BUILD.bazel:        $(sri_hash "${BCR_MOD}/overlay/BUILD.bazel")"
echo "MODULE.bazel:       $(sri_hash "${BCR_MOD}/overlay/MODULE.bazel")"
echo "liblivekit_ffi.so:  $(sri_hash "${BCR_MOD}/overlay/lib/liblivekit_ffi.so")"
```

最终生成的 `modules/livekit_sdk/1.13.0/source.json` 结构如下：

```json
{
    "url": "https://github.com/livekit/client-sdk-cpp/releases/download/v1.13.0/livekit-sdk-ubuntu-22.04-x64-1.13.0.tar.gz",
    "integrity": "sha256-YHEleOFDUGib7v82Z1CIyLkcEFC5BkQfcdsxIIn+j6g=",
    "strip_prefix": "livekit-sdk-ubuntu-22.04-x64-1.13.0",
    "overlay": {
        "BUILD.bazel": "sha256-Rd2t/lxhcOOcMdYgu7gSJBlvrnhyKNtT3uvxTgWcpQ8=",
        "MODULE.bazel": "sha256-tX4rdeyqPvngwgg/vDq3ppqCENDc61XlKpW2KgXty6g=",
        "lib/liblivekit_ffi.so": "sha256-kzWLcHPXG8nDcI064Ezgx85HyClEmeihu9GRLr1wgLg="
    }
}
```

当 Bazel 拉取 `@livekit_sdk` 时：
1. 自动下载并解压官方 `livekit-sdk-ubuntu-22.04-x64-1.13.0.tar.gz`（提供 `include/livekit/**` 与 `lib/liblivekit.so`）。
2. 自动用 `overlay/` 中的 `BUILD.bazel`、`MODULE.bazel` 和补丁版 `lib/liblivekit_ffi.so` 覆盖解压目录中的同名文件。
