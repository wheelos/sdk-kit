# WheelOS Vehicle SDK Kit (`wheelos_sdk_kit`)

`sdk-kit` is the standalone Bzlmod C++ repository hosting **only** the two standalone third-party SDK wrappers (`//auth` and `//livekit`) with zero dependency on Apollo Cyber (`//cyber`) or `//modules/teleop` domain services.

## Architecture & Module Responsibilities

```text
data/sdk-kit/
├── auth/           # [SDK 1] Vehicle Authentication, Enrollment & HTTP SDK (libcurl + jsoncpp + libcrypto)
│   ├── include/vehicle_edge/{auth_config.h,http_client.h,auth_client.h,diagnostics.h,bootstrap.h}
│   └── {auth_config.cc,http_client.cc,auth_client.cc,vehicle_auth_diagnostics.cc,vehicle_auth_check.cc,bootstrap.cc,bootstrap_crypto.cc,bootstrap_http.cc,bootstrap_storage.cc,vehicle_bootstrap.cc}
├── livekit/        # [SDK 2] LiveKit WebRTC Media & Control Transport SDK (@livekit_sdk)
│   ├── include/vehicle_edge/{encoded_video.h,media_backend.h}
│   ├── {encoded_video.cc,media_backend.cc,media_worker.cc}
│   └── livekit_ffi/{livekit-data-sender.patch,livekit_sender.rs,LiveKitSDK.cmake,LiveKitFFIPatch.cmake}
└── tests/          # Standalone SDK unit tests
    └── {auth_diagnostics_test.cc,bootstrap_test.cc,encoded_video_test.cc}
```

## Public Bazel Targets

- **SDK 1 — Authentication (`//auth`)**:
  - `@sdk_kit//auth:vehicle_auth_sdk` (alias `@sdk_kit//:vehicle_auth_sdk`)
  - `@sdk_kit//auth:auth_diagnostics` (alias `@sdk_kit//:auth_diagnostics`)
  - `@sdk_kit//auth:vehicle_auth_check` (alias `@sdk_kit//:vehicle_auth_check`)
  - `@sdk_kit//auth:bootstrap` (alias `@sdk_kit//:bootstrap`)
  - `@sdk_kit//auth:vehicle_bootstrap` (alias `@sdk_kit//:vehicle_bootstrap`)
- **SDK 2 — LiveKit Transport & Worker (`//livekit`)**:
  - `@sdk_kit//livekit:encoded_video` (alias `@sdk_kit//:encoded_video`)
  - `@sdk_kit//livekit:worker_runtime` (alias `@sdk_kit//:worker_runtime`)
  - `@sdk_kit//livekit:vehicle_media_worker` (alias `@sdk_kit//:vehicle_media_worker`)
  - `@sdk_kit//livekit:runtime_files` (alias `@sdk_kit//:media_worker_runtime_files`)

All Apollo Teleop domain services (`common`, `data`, `control`, `media`) and Cyber/GStreamer hardware adapters reside in `/apollo/modules/teleop`.

## Build & Test Commands

```bash
bazel build //...
bazel test //...
```

