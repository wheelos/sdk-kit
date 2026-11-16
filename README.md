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
    └── {auth_diagnostics_test.cc,bootstrap_test.cc,encoded_video_test.cc,media_config_test.cc}
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

## Bzlmod publication

The BCR module entry is `wheelos_sdk_kit@0.1.0`, sourced from
`https://github.com/wheelos/sdk-kit/releases/download/v0.1.0/sdk-kit-0.1.0.tar.gz`
and registered in the local Bazel Central Registry under
`modules/wheelos_sdk_kit/0.1.0`. Its BCR overlay pins the LiveKit SDK platform
revision. After the registry update is published and synced, Apollo's normal
Bazel configuration can resolve the module from the WheelOS registry without
`--config=dev`; the local registry and module override are only needed while
testing unpublished local changes.

## Build & Test Commands

```bash
bazel build //...
bazel test //...
```

## Enrollment configuration

Normal `vehicle_bootstrap` configuration needs only `gateway_url`. Use a manual
foreground run: `vehicle_bootstrap --gateway-url HTTPS_URL`; it configures the
address, provisions protected storage and begins enrollment in one invocation.
Gateway returns the configured console URL when creating the enrollment. Device
metadata is assigned during manual console approval; there is no automatic
authorization or systemd requirement. The device key is generated locally and
never transmitted. The displayed SHA-256 public-key fingerprint matches the
console and must be compared over a trusted channel. Configuration writes take
the enrollment lock.

Enrollment no longer reads a runtime template. Redeemed credentials are staged
inside `enrollment.json`, validated for exact `token_url`/`issuer` origin plus
OAuth and Gateway `device-auth-check`, and only then committed to
`/etc/teleop/credentials.json` (without `allow_insecure_localhost` in
production) and complete runtime defaults in `/etc/teleop/device.json`
(`credentials_file` reference). Optional, unconfigured runtime fields are
explicit JSON `null`, except `data_store_path`, which defaults to
`/var/lib/teleop/data/data.sqlite3`. Media, control and tasks remain disabled.
Explicit `data_store_path: null` still disables durable storage.
`DefaultRuntimeConfiguration` defines the generated fields. Existing files gain
only missing keys: explicit values, including `false` and optional `null`, are
preserved. A repeated authentication with no missing fields does not rewrite
the runtime file. If valid credentials are already on disk after a
lost acknowledgment, `vehicle_bootstrap` verifies `device-auth-check` and
completes `installation-complete` idempotently without re-redeeming. There is no
old configuration migration or inline runtime-authentication fallback. Retired
and unknown bootstrap fields are rejected, including `console_url` and the
removed `allow_legacy_complete_404` flag. Installation acknowledgment must
return `204`. Rotation preserves existing runtime settings while backfilling
missing defaults.
`LoadDeviceConfigJSON` resolves the reference for Apollo, authentication
diagnostics and the media worker; `ResolveDeviceConfig` rejects mixed file
responsibilities. `LoadAuthConfig` also accepts an authentication-only file for
standalone SDK diagnostics, not a mixed runtime file. Local simulation can use
authentication-only debug credentials; runtime files still need a separate
credentials reference. Split production files support root-owned `0600`, or
root-owned dedicated-group `0640` under a protected `0750` directory; atomic
root rotation preserves existing group and mode. Non-root manual enrollment
uses `--config PATH` with explicit account-owned `0600` files and `0700` paths.
Database-directory preparation belongs to the runtime account. For the root
runtime, the Apollo enrollment wrapper calls
`vehicle_bootstrap --prepare-data-directory --gateway-url HTTPS_URL` before
enrollment. This offline command reads the protected bootstrap/runtime files,
uses the same missing-key defaults as installation, preserves custom paths and
skips explicit null. It prepares the runtime configuration parent if absent and
the private database parent (`0700`), but does not write configuration, create
SQLite files, generate keys or start services. Existing data directories with
incorrect owners/permissions, symlinks, parent traversal and paths inside the
bootstrap state directory are rejected; existing permissions are never changed.
When using bootstrap directly, prepare storage explicitly. A non-root runtime
must use its own data directory and run
`vehicle_bootstrap --prepare-data-directory --config PATH` as that account
with its protected bootstrap config. The root wrapper must not be used to
provision its database. SQLite files and tables
are created by the Apollo runtime on startup, not by enrollment. Persist the
data directory outside the container writable layer if containers are replaced.
Consumers must support nullable runtime fields before enrollment backfills the
expanded configuration. Older minimal runtime files remain valid; loading a
file without `data_store_path` still disables storage until enrollment backfills
the missing field. Existing explicit null is preserved during backfill. The media
worker treats an unset camera source as disabled and requires an explicit
source when media is enabled; it never infers simulation from `null`.
`SharedTokenProvider` reloads the protected credentials file once
on OAuth `invalid_client` when vehicle/client/endpoint identities are unchanged.
Credential changes also persist a maintenance notice until authentication and
installation acknowledgment succeed; neither enrollment nor renewal restarts a
runtime.

HTTPS uses the operating system CA bundle and verifies hostnames. Publicly
trusted endpoint certificates (including proxied Cloudflare Universal SSL
certificates) avoid private CA distribution. Private deployments must provision
their verified public CA into the actual runtime environment. Cloudflare Origin
CA certificates are for the proxy-to-origin hop, not direct vehicle trust.

Before networking, bootstrap checks kernel `adjtimex` readiness (no
`TIME_ERROR`/`STA_UNSYNC`, uncertainty <=1 second), plus the epoch sanity floor;
telemetry uses the same evidence. Containers inherit host time discipline.
Chrony/NTP or PTP must discipline the system clock, not only a hardware PHC.
There is no systemd dependency; unqueryable/unsynchronized/uncertain clocks fail
closed. Trusted host/servo evidence is not independent proof of UTC.
Bootstrap then gates `/api/v1/version` on `ok`, version `1` and
`teleop-enrollment-v1`, including restarts with existing credentials.
Gateway delegates to an exact HTTPS issuer origin (persisted as `issuer`);
absent an issuer, only the exact Gateway origin is accepted. Effective ports
matter; shared suffixes such as `co.uk` or `github.io` confer no trust. This is
not protection against a fully compromised trusted Gateway.

Compatibility: original six-field credentials without `issuer` still work
only when token and Gateway have the exact same origin. Existing cross-subdomain
or cross-port credentials are intentionally rejected by runtime. To upgrade,
stop runtime at a safe maintenance point and rerun the same canonical bootstrap
with the trusted Gateway. It preserves old files/key and requests manual
same-key recovery approval without sending the old secret to that token URL;
only Gateway-delivered issuer-bound credentials passing OAuth/device checks
replace them. This also applies if saved enrollment is pending and a poll says
active: that state is not evidence of local issuer trust; bootstrap starts a
new signed same-key recovery requiring approval/maintenance drain. After the
issuer-bound credentials are verified and persisted, restart runtime manually:
adding/changing issuer is an identity change and is deliberately not hot-reloaded.
Do not guess/edit issuer or client secrets manually.
