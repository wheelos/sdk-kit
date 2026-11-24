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

## Runtime HTTP diagnostics

`HTTPResponse::diagnostics` carries a redacted transport summary: fixed request
category, method, host, curl code, HTTP status, cumulative DNS/TCP/TLS/first-byte
timings and total elapsed milliseconds. URL paths, request/response bodies,
headers and credentials are excluded. `HTTPTransportError` preserves the curl
code and this summary; OAuth transport errors retain it rather than discarding
the underlying cause. Callers can append the summary when rejecting an HTTP
status without logging the response body.

Transport-completed requests taking at least 1000 ms emit a slow-request log,
limited to one message per HTTP client per 30 seconds. Zero phase timings can
mean a phase was not reached or the connection was reused; `new_connections`
helps distinguish reuse.

`HTTPClient` and `AuthenticatedClient` accept an optional per-request
`HTTPTimeouts{connect_ms, total_ms}` argument. Both values must be positive;
the default is 1000/2000 ms. OAuth token acquisition through
`SharedTokenProvider` uses 5000/10000 ms. Apollo Teleop data uploads explicitly
select 3000/5000 ms. Media token acquisition at /api/token/vehicle also uses
3000/5000 ms in the Teleop client, media worker and auth diagnostic. Media demand,
control context and other callers retain the default unless they supply an
override. Diagnostics report the actual
`connect_timeout_ms` and `timeout_ms` selected for each transfer.

The total HTTP timeout includes connection setup but excludes waiting for the
shared token lock or a separate OAuth request. Shared-token locking, retries,
media authorization expiry checks and bootstrap HTTP timeouts are unchanged.

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
explicit JSON `null`, except `data_store_path` and `camera_capture_config`,
which default to `/var/lib/teleop/data/data.sqlite3` and
`/etc/teleop/cameras.json`, respectively. Media, control and tasks remain disabled.
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

Root-managed enrollment accepts `--runtime-user USER`, resolved inside the
container to an existing non-root UID and non-root primary GID. Selection is
explicit option, saved `runtime_user` in the protected bootstrap config, then
non-root `SUDO_USER` for Gateway-address commands. Direct root invocation without
a saved account must supply the option. A different saved account is rejected;
identity/data migration is a separate offline operation. The account is not a
runtime `device.json` field or part of the server enrollment payload.
The Apollo wrapper validates first, saves the account with `--configure`, prepares
data and camera paths, then enrolls. Root-managed enrollment also performs these
preparations when invoked directly. Existing runtime values and device keys are
preserved. Bootstrap config, key/state and lock remain private to root. Runtime
config, credentials and cameras are root-owned `0640` with the runtime's primary
group, under dedicated protected `0750` parents. New files and atomic replacements
use the same policy. Compatible existing root-owned `0600` runtime files are
shared without replacing their contents; unrelated groups are rejected.

The Apollo wrapper calls `vehicle_bootstrap --prepare-data-directory
--gateway-url HTTPS_URL --runtime-user USER` before enrollment. This offline
command reads the protected bootstrap/runtime files,
uses the same missing-key defaults as installation, preserves custom paths and
skips explicit null. It prepares the runtime configuration parent if absent and
the private database parent (`0700`, owned by the selected runtime account), but
does not write configuration, create
SQLite files, generate keys or start services. Existing data directories with
incorrect owners/permissions, symlinks, parent traversal and paths inside the
bootstrap state directory are rejected. Existing data ownership is never
changed. Existing database, lock, WAL and SHM files must belong to the runtime
account and primary group with mode `0600`; otherwise offline migration is
required. Only the named root-owned shared configuration/data parents are
prepared as `0750`; no recursive ownership changes are performed.
When using bootstrap directly, prepare storage explicitly. A non-root runtime
must use its own data directory and run
`vehicle_bootstrap --prepare-data-directory --config PATH` as that account
with its protected bootstrap config. Fully non-root enrollment remains supported
without the root-managed `runtime_user` field. SQLite files and tables
are created by the Apollo runtime on startup, not by enrollment. Persist the
data directory outside the container writable layer if containers are replaced.
The wrapper also calls `vehicle_bootstrap --prepare-camera-config --gateway-url
HTTPS_URL --runtime-user USER`. `DefaultCameraCaptureConfiguration` supplies three devices
(`/dev/video0`, `/dev/video1`, `/dev/video2`), 1920x1080 at 30 fps, 1280x720
output, 2000000 bps and keyframe interval 30. The command creates a missing
protected camera JSON as root-owned runtime-group `0640` in root-managed mode
(`0600` for fully non-root mode), preserves existing contents and custom paths, and
skips explicit null. It performs no camera or network operations and changes
no runtime switches. Non-root preparation accepts `--prepare-camera-config
--config PATH` with a protected bootstrap config. Use the matching Apollo
runtime: a prepared capture path is inactive with disabled media or simulation;
physical capture requires enabled H264 media, the camera build option and a
layout matching the file's device count. The generated runtime retains its
existing `single` layout; select `three` to activate the three-device file.

For enabled H264 camera capture, the media worker reads the same protected
`camera_capture_config` file. It initializes each encoded video source with
`output_width`/`output_height` and explicitly publishes with `bitrate_bps` and
`fps` as per-track limits. This prevents LiveKit's initial-resolution defaults
from silently limiting a 720p camera to a VGA publication budget. These are
ceilings; congestion feedback may still lower the encoder bitrate. Each track
logs its publication settings as `[teleop_video_publish]`. Changes take effect
when the capture pipeline and media worker are restarted. Disabled media and
simulation do not load the camera file. Encoded integrations with a missing or
null capture path retain their existing publication behavior.

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
