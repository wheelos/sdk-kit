// Copyright 2026 WheelOS. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "vehicle_edge/bootstrap.h"

#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <stdexcept>
#include <utility>

#include <openssl/rand.h>
#include <openssl/sha.h>

#include "vehicle_edge/auth_config.h"
#include "vehicle_edge/http_client.h"

namespace vehicle_edge {
namespace enrollment {
namespace {
std::string Text(const Json::Value& value, const char* name, std::size_t max,
                 bool empty = false) {
  if (!value[name].isString()) throw std::runtime_error("missing text field");
  auto text = value[name].asString();
  if ((!empty && text.empty()) || text.size() > max ||
      std::any_of(text.begin(), text.end(),
                  [](unsigned char c) { return c < 32 || c == 127; }))
    throw std::runtime_error("invalid text field");
  return text;
}
bool IsUUID(const std::string& text) {
  if (text.size() != 36) return false;
  for (unsigned i = 0; i < text.size(); ++i) {
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      if (text[i] != '-') return false;
    } else if (!((text[i] >= '0' && text[i] <= '9') ||
                 (text[i] >= 'a' && text[i] <= 'f')))
      return false;
  }
  return true;
}
bool SecretCode(const std::string& code) {
  return code.size() == 43 &&
         std::all_of(code.begin(), code.end(), [](unsigned char c) {
           return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '-' || c == '_';
         });
}
bool UserCode(const std::string& code) {
  if (code.size() != 9 || code[4] != '-') return false;
  for (unsigned i = 0; i < code.size(); ++i) {
    if (i == 4) continue;
    if (!((code[i] >= 'A' && code[i] <= 'Z') ||
          (code[i] >= '0' && code[i] <= '9')))
      return false;
  }
  return true;
}
std::string JSON(const Json::Value& value) {
  Json::StreamWriterBuilder writer;
  writer["indentation"] = "";
  return Json::writeString(writer, value);
}
std::string Fingerprint(const std::string& private_key) {
  const auto raw = DecodeBase64URL(PublicKey(private_key), 32);
  unsigned char digest[SHA256_DIGEST_LENGTH];
  if (!SHA256(reinterpret_cast<const unsigned char*>(raw.data()), raw.size(),
              digest))
    throw std::runtime_error("cannot compute device fingerprint");
  const char* hex = "0123456789abcdef";
  std::string result = "SHA256:";
  for (const auto byte : digest) {
    result += hex[byte >> 4];
    result += hex[byte & 15];
  }
  return result;
}
std::string FormattedFingerprint(const std::string& private_key) {
  const auto full = Fingerprint(private_key);
  const auto hex = full.substr(7);
  std::string short_fp;
  for (std::size_t i = 0; i < 16 && i < hex.size(); ++i) {
    if (i > 0 && i % 4 == 0) short_fp += '-';
    short_fp +=
        static_cast<char>(std::toupper(static_cast<unsigned char>(hex[i])));
  }
  return short_fp + " (" + full + ")";
}
std::int64_t Expiry(const Json::Value& value, const char* field) {
  auto text = Text(value, field, 32);
  std::tm time{};
  auto* end = strptime(text.c_str(), "%Y-%m-%dT%H:%M:%S", &time);
  if (!end) throw std::runtime_error("invalid expiration");
  if (*end == '.') {
    ++end;
    while (*end >= '0' && *end <= '9') ++end;
  }
  if (std::string(end) != "Z")
    throw std::runtime_error("expiration must be UTC");
  return timegm(&time);
}
unsigned Interval(const Json::Value& value) {
  if (!value["interval"].isUInt() || value["interval"].asUInt() < 5 ||
      value["interval"].asUInt() > 86400)
    throw std::runtime_error("invalid poll interval");
  return value["interval"].asUInt();
}
bool Transient(const Response& response) {
  return response.status == 408 || response.status == 429 ||
         (response.status >= 500 && response.status <= 599);
}
bool HasCredentials(const Json::Value& device) {
  return device["client_id"].isString() &&
         !device["client_id"].asString().empty() &&
         device["client_secret"].isString() &&
         !device["client_secret"].asString().empty();
}
bool SafeErrorCode(const std::string& code) {
  if (code.size() < 2 || code.size() > 64) return false;
  bool upper = false, lower = false;
  for (unsigned char c : code) {
    if (c >= 'A' && c <= 'Z')
      upper = true;
    else if (c >= 'a' && c <= 'z')
      lower = true;
    else if (!((c >= '0' && c <= '9') || c == '_'))
      return false;
  }
  return upper != lower;
}
std::string ResponseErrorCode(const Response& response,
                              const std::string& fallback) {
  try {
    auto body = ParseHTTPJSON(response.body);
    if (body.isObject()) {
      for (const auto* field : {"code", "error_code", "error"}) {
        if (body[field].isString() && SafeErrorCode(body[field].asString()))
          return body[field].asString();
      }
    }
  } catch (...) {
  }
  return fallback;
}
std::string TransientHint(long status) {
  if (status == 429)
    return "request or polling rate limited; waiting for Retry-After window";
  if (status == 408)
    return "request timed out; check network quality and retrying with backoff";
  return "remote service temporarily unavailable; retrying with backoff";
}
std::string CredentialDigest(const Json::Value& device) {
  Json::Value auth(Json::objectValue);
  for (const auto* field :
       {"vehicle_id", "client_id", "client_secret", "token_url", "gateway_url",
        "issuer"})
    auth[field] = device[field];
  const auto text = JSON(auth);
  std::string digest(SHA256_DIGEST_LENGTH, '\0');
  SHA256(reinterpret_cast<const unsigned char*>(text.data()), text.size(),
         reinterpret_cast<unsigned char*>(&digest[0]));
  return Base64URL(digest);
}
}  // namespace

bool InvalidCredentials(const Response& response) {
  // OAuth's explicit invalid_client is proof of rejection, unlike a Gateway 403
  // (mapping/permission) or an issuer's generic HTTP error.
  if (response.status != 400 && response.status != 401) return false;
  try {
    return ParseHTTPJSON(response.body)["error"] == "invalid_client";
  } catch (...) {
    return false;
  }
}

Json::Value MergeCredentials(const Json::Value& existing,
                             const Json::Value& credentials, bool local_test) {
  if (!existing.isNull() && !existing.isObject())
    throw std::runtime_error("invalid existing credentials");
  Json::Value merged(Json::objectValue);
  if (existing.isObject()) {
    if (existing["vehicle_id"].isString() &&
        !existing["vehicle_id"].asString().empty() &&
        existing["vehicle_id"] != credentials["vehicle_id"])
      throw std::runtime_error("recovery must retain vehicle identity");
  }
  merged["auth_mode"] = "required";
  for (const auto* field : {"vehicle_id", "client_id", "client_secret",
                            "token_url", "gateway_url"}) {
    merged[field] = Text(credentials, field,
                         field == std::string("client_secret") ? 4096 : 2048);
  }
  auto gateway_url = merged["gateway_url"].asString();
  while (gateway_url.size() > 1 && gateway_url.back() == '/')
    gateway_url.pop_back();
  merged["gateway_url"] = gateway_url;
  const std::string issuer =
      credentials["issuer"].isString() ? Text(credentials, "issuer", 2048) : "";
  if (!TrustedTokenEndpoint(merged["token_url"].asString(), gateway_url, issuer,
                            local_test)) {
    throw std::runtime_error(
        "untrusted token_url or issuer domain in redeemed credentials");
  }
  if (!issuer.empty() && !local_test) merged["issuer"] = issuer;
  if (local_test) {
    merged["allow_insecure_localhost"] = true;
  }
  (void)ParseAuthConfig(merged);
  Json::StreamWriterBuilder writer;
  writer["indentation"] = "  ";
  if (Json::writeString(writer, merged).size() + 1 > 16384)
    throw std::runtime_error("credentials exceed 16 KiB");
  return merged;
}

Json::Value ParseBootstrapConfig(Json::Value config) {
  if (!config.isObject())
    throw std::runtime_error("bootstrap config must be an object");
  for (const auto& name : config.getMemberNames()) {
    if (name != "gateway_url" && name != "state_directory" && name != "device_config" &&
        name != "credentials_config" && name != "allow_insecure_localhost")
      throw std::runtime_error("unsupported bootstrap field; remove " + name);
  }
  if (config.isMember("allow_insecure_localhost")) {
#ifdef TELEOP_PRODUCTION_BUILD
    throw std::runtime_error(
        "allow_insecure_localhost is disabled in production builds");
#endif
    if (!config["allow_insecure_localhost"].isBool())
      throw std::runtime_error("bootstrap flags must be boolean");
  }
  const bool local_test =
      config.get("allow_insecure_localhost", false).asBool();
  auto url = Text(config, "gateway_url", 2048);
  if (local_test && !LoopbackURL(url))
    throw std::runtime_error(
        "allow_insecure_localhost requires a loopback gateway_url");
  if (!AllowedURL(url, local_test))
    throw std::runtime_error("HTTPS required");
  while (url.back() == '/') url.pop_back();
  config["gateway_url"] = url;
  if (!config.isMember("state_directory"))
    config["state_directory"] = "/var/lib/teleop/bootstrap";
  if (!config.isMember("device_config"))
    config["device_config"] = "/etc/teleop/device.json";
  if (!config.isMember("credentials_config"))
    config["credentials_config"] = "/etc/teleop/credentials.json";
  for (const auto* field :
       {"state_directory", "device_config", "credentials_config"})
    Text(config, field, 4096);
  if (config["device_config"] == config["credentials_config"])
    throw std::runtime_error("runtime and credentials paths must differ");
  return config;
}

Bootstrap::Bootstrap(Json::Value config, Hooks hooks, Storage storage)
    : config_(ParseBootstrapConfig(std::move(config))),
      hooks_(std::move(hooks)),
      storage_(storage) {
  if (!hooks_.now)
    hooks_.now = [] {
      return std::chrono::duration_cast<std::chrono::seconds>(
                 std::chrono::system_clock::now().time_since_epoch())
          .count();
    };
  if (!hooks_.notice) hooks_.notice = [](const std::string&) {};
  if (!hooks_.clock_readiness) hooks_.clock_readiness = ClockReadinessError;
  local_test_ = config_.get("allow_insecure_localhost", false).asBool();
  const auto runtime =
      storage_.Read(config_["device_config"].asString(), true, 16384);
  if (!runtime.isNull()) {
    if (runtime["credentials_file"] !=
        std::filesystem::absolute(config_["credentials_config"].asString())
            .lexically_normal()
            .string())
      throw std::runtime_error(
          "runtime requires the managed credentials file reference");
    for (const auto& name : runtime.getMemberNames())
      if (IsAuthConfigField(name))
        throw std::runtime_error(
            "runtime must not contain inline authentication");
  }
  (void)storage_.Read(config_["credentials_config"].asString(), true, 16384);
  const auto dir = config_["state_directory"].asString();
  lock_ = storage_.Lock(dir);
  try {
    auto key = storage_.Read(dir + "/key.json", true);
    if (key.isNull()) {
      std::string seed(32, '\0');
      if (RAND_bytes(reinterpret_cast<unsigned char*>(&seed[0]), seed.size()) !=
          1)
        throw std::runtime_error("cannot generate device key");
      key["private_key"] = Base64URL(seed);
      storage_.Write(dir + "/key.json", key);
    }
    private_key_ = DecodeBase64URL(Text(key, "private_key", 43), 32);
    state_ = storage_.Read(dir + "/enrollment.json", true);
    if (state_.isNull()) state_ = Json::Value(Json::objectValue);
    for (const auto* field : {"name", "serial", "platform"})
      if (state_.isMember(field))
        throw std::runtime_error("retired enrollment metadata is not supported");
    if (state_.isMember("request_id") &&
        (!IsUUID(Text(state_, "request_id", 36)) ||
         state_["public_key"] != PublicKey(private_key_)))
      throw std::runtime_error("enrollment key binding mismatch");
    failures_ = state_.get("failures", 0).asUInt();
    const auto status = state_.get("status", "").asString();
    if (state_.isMember("user_code") && status != "denied" &&
        status != "failed" && status != "installed") {
      const auto code = Text(state_, "user_code", 9);
      if (!UserCode(code)) throw std::runtime_error("invalid saved user code");
      hooks_.notice(
          "Enrollment code: " + code + "\nDevice fingerprint: " +
          FormattedFingerprint(private_key_) + "\nOpen " +
          state_.get("console_url", config_["gateway_url"]).asString() +
          "/#/admin; in vehicle management enter this code for approval.");
    }
  } catch (...) {
    close(lock_);
    lock_ = -1;
    throw;
  }
}
Bootstrap::~Bootstrap() {
  if (lock_ >= 0) close(lock_);
}

void Bootstrap::Save() {
  storage_.Write(config_["state_directory"].asString() + "/enrollment.json",
                 state_);
}
void Bootstrap::ClearError() {
  state_.removeMember("last_error_code");
  state_.removeMember("last_error_hint");
  state_.removeMember("last_http_status");
  last_diagnostic_key_.clear();
}
void Bootstrap::NotifyOnce(const std::string& key, const std::string& message) {
  if (last_diagnostic_key_ == key) return;
  last_diagnostic_key_ = key;
  hooks_.notice(message);
}
void Bootstrap::NewEnrollment() {
  // Do not reset the key or touch the runtime configuration during recovery.
  state_ = Json::Value(Json::objectValue);
  state_["request_id"] = UUID();
  state_["public_key"] = PublicKey(private_key_);
  state_["status"] = "creating";
  state_["stage"] = "enroll_create";
  last_diagnostic_key_.clear();
  Save();
}
Result Bootstrap::Wait(unsigned seconds, bool polling_jitter) {
  if (seconds >= 5 && polling_jitter) {
    unsigned jitter = 0;
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&jitter), sizeof(jitter)) !=
        1)
      throw std::runtime_error("random generator failed");
    seconds += jitter % 3;
  }
  state_["next_attempt_at"] = Json::Int64(hooks_.now() + seconds);
  Save();
  return {Status::Waiting,
          seconds,
          state_.get("stage", current_stage_).asString(),
          state_.get("last_error_code", "").asString(),
          state_.get("last_error_hint", "").asString(),
          state_.get("last_http_status", 0).asInt64()};
}
Result Bootstrap::Retry(unsigned minimum, const std::string& code,
                        const std::string& hint, long http_status) {
  failures_ = std::min(failures_ + 1, 7u);
  state_["failures"] = failures_;
  const auto stage = current_stage_.empty() ? "bootstrap" : current_stage_;
  const auto resolved_code = code.empty() ? "TRANSIENT_FAILURE" : code;
  const auto resolved_hint =
      hint.empty() ? "temporary failure; retrying with backoff" : hint;
  state_["stage"] = stage;
  state_["last_error_code"] = resolved_code;
  state_["last_error_hint"] = resolved_hint;
  if (http_status > 0)
    state_["last_http_status"] = Json::Int64(http_status);
  else
    state_.removeMember("last_http_status");
  unsigned bound = std::min(300u, 5u << failures_);
  unsigned random = 0;
  if (RAND_bytes(reinterpret_cast<unsigned char*>(&random), sizeof(random)) !=
      1)
    throw std::runtime_error("random generator failed");
  // Retry already chooses jitter within its backoff bound; do not add the
  // normal polling jitter a second time.
  auto result = Wait(std::max(minimum, bound / 2 + random % (bound / 2 + 1)),
                     false);
  NotifyOnce(stage + ":" + resolved_code + ":" + std::to_string(http_status),
             "Bootstrap retry [" + stage + "]: code=" + resolved_code +
                 (http_status > 0 ? " http=" + std::to_string(http_status)
                                  : "") +
                 " retry_in=" + std::to_string(result.delay) + "s (" +
                 resolved_hint + ").");
  return result;
}
Result Bootstrap::Block(const std::string& stage, const std::string& code,
                        const std::string& hint, long http_status) {
  state_["stage"] = stage;
  state_["last_error_code"] = code;
  state_["last_error_hint"] = hint;
  if (http_status > 0)
    state_["last_http_status"] = Json::Int64(http_status);
  else
    state_.removeMember("last_http_status");
  Save();
  NotifyOnce(stage + ":" + code + ":" + std::to_string(http_status),
             "Bootstrap blocked [" + stage + "]: code=" + code +
                 (http_status > 0 ? " http=" + std::to_string(http_status)
                                  : "") +
                 " (" + hint + ").");
  return {Status::Blocked, 0, stage, code, hint, http_status};
}
Response Bootstrap::Call(const std::string& method, const std::string& url,
                         const std::string& body, const std::string& bearer,
                         const std::string& type) {
  if (!AllowedURL(url, local_test_))
    throw std::runtime_error("invalid endpoint");
  return hooks_.request({method, url, type, body, bearer, local_test_});
}
Response Bootstrap::Enrollment(const std::string& action) {
  Json::Value envelope(Json::objectValue);
  envelope["request_id"] = state_["request_id"];
  envelope["public_key"] = PublicKey(private_key_);
  envelope["device_code"] =
      action == "create" ? "" : state_.get("device_code", "").asString();
  envelope["ticket"] =
      action == "complete" ? state_.get("ticket", "").asString() : "";
  envelope["timestamp"] = Json::Int64(hooks_.now());
  envelope["nonce"] = UUID();
  const std::string suffix = action == "create" ? ""
                             : action == "poll" ? "/token"
                                                : "/complete";
  return Call(
      "POST",
      config_["gateway_url"].asString() + "/api/v1/device-enrollments" + suffix,
      JSON(Sign(action, envelope, private_key_)));
}

Result Bootstrap::Authenticate(const Json::Value& device) {
  auto auth = ParseAuthConfig(device);
  if (auth.IsLocalSimDebug())
    throw std::runtime_error("bootstrap requires OAuth");
  current_stage_ = "oauth_token";
  HTTPClient escape;
  auto token = Call("POST", auth.token_url,
                    "grant_type=client_credentials&client_id=" +
                        escape.Escape(auth.client_id) +
                        "&client_secret=" + escape.Escape(auth.client_secret) +
                        "&scope=teleop%3Avehicle",
                    "", "application/x-www-form-urlencoded");
  if (Transient(token)) {
    return Retry(
        std::max(5u, token.retry_after),
        ResponseErrorCode(token, token.status == 429 ? "OAUTH_RATE_LIMITED"
                                                     : "OAUTH_UNAVAILABLE"),
        TransientHint(token.status), token.status);
  }
  if (InvalidCredentials(token)) {
    hooks_.notice(
        "Vehicle OAuth credentials rejected [oauth_token]: code=invalid_client "
        "http=" +
        std::to_string(token.status) +
        " (requesting same-vehicle recovery enrollment).");
    const auto rejected_digest = CredentialDigest(device);
    NewEnrollment();
    state_["rejected_credential_digest"] = rejected_digest;
    Save();
    return Wait(5);
  }
  if (token.status != 200) {
    return Block(
        "oauth_token", ResponseErrorCode(token, "OAUTH_TOKEN_REJECTED"),
        "check OAuth issuer token_url, client grant configuration, and "
        "teleop:vehicle scope",
        token.status);
  }
  auto body = ParseHTTPJSON(token.body);
  auto bearer = Text(body, "access_token", 16384);
  if (!ValidBearerToken(bearer) || !body["expires_in"].isNumeric() ||
      body["expires_in"].asDouble() < 5)
    throw std::runtime_error("invalid OAuth response");
  current_stage_ = "device_auth_check";
  auto mapping = Call("GET",
                      auth.gateway_url + "/api/vehicles/" + auth.vehicle_id +
                          "/device-auth-check",
                      "", bearer);
  if (Transient(mapping)) {
    return Retry(std::max(5u, mapping.retry_after),
                 ResponseErrorCode(mapping, "GATEWAY_UNAVAILABLE"),
                 TransientHint(mapping.status), mapping.status);
  }
  if (mapping.status != 204) {
    return Block(
        "device_auth_check",
        ResponseErrorCode(mapping, mapping.status == 401
                                       ? "GATEWAY_TOKEN_REJECTED"
                                       : "VEHICLE_MAPPING_DENIED"),
        mapping.status == 401
            ? "Gateway rejected vehicle access token; check OAuth issuer, "
              "audience, and teleop:vehicle scope"
            : "Gateway rejected vehicle binding; check vehicle_id mapping and "
              "active vehicle lifecycle in console",
        mapping.status);
  }
  InstallConfiguration(MergeCredentials(device, device, local_test_));
  current_stage_ = "installation_complete";
  auto completed = Call("POST",
                        auth.gateway_url + "/api/vehicles/" + auth.vehicle_id +
                            "/installation-complete",
                        "{}", bearer);
  if (Transient(completed)) {
    return Retry(std::max(5u, completed.retry_after),
                 ResponseErrorCode(completed, "GATEWAY_UNAVAILABLE"),
                 TransientHint(completed.status), completed.status);
  }
  if (completed.status != 204) {
    return Block(
        "installation_complete",
        ResponseErrorCode(completed, "INSTALLATION_COMPLETE_REJECTED"),
        "Gateway rejected installation acknowledgment; check onboarding "
        "operation state for this vehicle",
        completed.status);
  }
  failures_ = 0;
  state_["failures"] = 0;
  state_["status"] = "installed";
  state_["stage"] = "installed";
  ClearError();
  state_.removeMember("device_code");
  state_.removeMember("ticket");
  state_.removeMember("ticket_expires_at");
  state_.removeMember("next_attempt_at");
  state_.removeMember("pending_credentials");
  state_.removeMember("rejected_credential_digest");
  if (state_.get("credentials_updated", false).asBool()) {
    hooks_.notice(
        "Authentication acknowledged; credentials changed. A running runtime "
        "reloads a changed secret only after explicit OAuth invalid_client. "
        "If a restart is needed, do it manually at a safe maintenance stop; "
        "no runtime was started or restarted.");
    state_.removeMember("credentials_updated");
  }
  Save();
  return {Status::Ready, 0, "installed", "",
          "vehicle authentication and installation acknowledged",
          completed.status};
}

Result Bootstrap::Step() {
  if (state_.get("status", "").asString() == "denied") {
    return {Status::Denied,
            0,
            state_.get("stage", "enroll_poll").asString(),
            state_.get("last_error_code", "ENROLLMENT_DENIED").asString(),
            state_
                .get("last_error_hint",
                     "administrator rejected enrollment; operator action "
                     "required before retrying")
                .asString(),
            state_.get("last_http_status", 0).asInt64()};
  }
  if (hooks_.now() < 1700000000) {
    return Block(
        "clock_check", "CLOCK_NOT_SYNCHRONIZED",
        "system clock is not synchronized (before 2023-11); synchronize "
        "NTP/PTP before enrollment",
        0);
  }
  const auto clock_error = hooks_.clock_readiness();
  if (!clock_error.empty())
    return Block("clock_check", "CLOCK_NOT_SYNCHRONIZED", clock_error, 0);
  auto next = state_.get("next_attempt_at", Json::Int64(0)).asInt64();
  if (next > hooks_.now())
    return {Status::Waiting,
            static_cast<unsigned>(
                std::min<std::int64_t>(next - hooks_.now(), 86400)),
            state_.get("stage", "").asString(),
            state_.get("last_error_code", "").asString(),
            state_.get("last_error_hint", "").asString(),
            state_.get("last_http_status", 0).asInt64()};
  // Persist a minimum pacing deadline even if killed during an HTTP attempt.
  state_["next_attempt_at"] = Json::Int64(hooks_.now() + 5);
  Save();
  try {
    return Advance();
  } catch (const TransportError&) {
    return Retry(
        5, "TRANSPORT_UNAVAILABLE",
        "check network connectivity, DNS, and HTTPS/TLS trust store; retrying "
        "with backoff",
        0);
  }
}

Result Bootstrap::Advance() {
  if (!version_checked_) {
    current_stage_ = "version_check";
    const auto response = Call("GET", config_["gateway_url"].asString() +
                                         "/api/v1/version");
    if (Transient(response))
      return Retry(5, "VERSION_CHECK_UNAVAILABLE",
                   "Gateway compatibility check temporarily unavailable",
                   response.status);
    if (response.status != 200)
      return Block("version_check", "GATEWAY_PROTOCOL_INCOMPATIBLE",
                   "Gateway must expose enrollment protocol version 1",
                   response.status);
    Json::Value version;
    try {
      version = ParseHTTPJSON(response.body);
    } catch (...) {
      return Block("version_check", "GATEWAY_PROTOCOL_INCOMPATIBLE",
                   "Gateway version response must be valid protocol metadata",
                   response.status);
    }
    if (version["status"] != "ok" || version["protocol_version"] != "1" ||
        version["enrollment_protocol"] != "teleop-enrollment-v1")
      return Block("version_check", "GATEWAY_PROTOCOL_INCOMPATIBLE",
                   "Gateway enrollment protocol does not match this SDK", 200);
    version_checked_ = true;
  }
  const auto path = config_["credentials_config"].asString();
  auto device = storage_.Read(path, true, 16384);
  const bool legacy_cross_origin =
      HasCredentials(device) && !device.isMember("issuer") &&
      !local_test_ &&
      !TrustedTokenEndpoint(device["token_url"].asString(),
                            config_["gateway_url"].asString(), "", false);
  if (!device.isNull() && !legacy_cross_origin) {
    Json::Value runtime(Json::objectValue);
    runtime["credentials_file"] =
        std::filesystem::absolute(path).lexically_normal().string();
    (void)ResolveDeviceConfig(runtime, device);
  }
  auto status = state_.get("status", "").asString();
  if (status == "validating" && state_["pending_credentials"].isObject() &&
      state_["credential_digest"] ==
          CredentialDigest(state_["pending_credentials"])) {
    return Authenticate(state_["pending_credentials"]);
  }
  if (HasCredentials(device) && !legacy_cross_origin &&
      CredentialDigest(device) !=
          state_.get("rejected_credential_digest", "").asString() &&
      (status.empty() || status == "installed" || status == "installing" ||
       status == "active" ||
       state_["credential_digest"] == CredentialDigest(device)))
    return Authenticate(device);
  if (!state_.isMember("request_id") || status == "expired" ||
      (status == "installed" &&
       (!HasCredentials(device) || legacy_cross_origin))) {
    NewEnrollment();
    status = "creating";
  }
  std::string action = state_.isMember("device_code") ? "poll" : "create";
  if (state_.isMember("ticket")) {
    if (state_["ticket_expires_at"].asInt64() > hooks_.now())
      action = "complete";
    else {
      hooks_.notice(
          "Installation ticket expired [ticket_redeem]; polling the approved "
          "enrollment for a fresh ticket.");
      state_.removeMember("ticket");
      state_.removeMember("ticket_expires_at");
      state_["stage"] = "enroll_poll";
      Save();
    }
  }
  current_stage_ = action == "complete" ? "ticket_redeem" : "enroll_" + action;
  auto response = Enrollment(action);
  if (Transient(response)) {
    return Retry(
        std::max(5u, response.retry_after),
        ResponseErrorCode(response, response.status == 429
                                        ? "ENROLLMENT_SLOW_DOWN"
                                        : "UPSTREAM_UNAVAILABLE"),
        TransientHint(response.status), response.status);
  }
  if (action != "create" && response.status == 404) {
    hooks_.notice("Enrollment expired or unavailable [" + current_stage_ +
                  "]; requesting a new enrollment code with the same device "
                  "key.");
    NewEnrollment();
    return Wait(5);
  }
  if (action == "complete" &&
      (response.status == 400 || response.status == 410)) {
    // Ticket expiry can race the HTTP attempt. Re-poll with the same request,
    // code and key; only an explicit enrollment-expired response changes code.
    hooks_.notice(
        "Installation ticket expired [ticket_redeem]; polling the approved "
        "enrollment for a fresh ticket.");
    state_.removeMember("ticket");
    state_.removeMember("ticket_expires_at");
    state_["stage"] = "enroll_poll";
    Save();
    return Wait(5);
  }
  if (response.status != 200 && !(action == "create" && response.status == 201)) {
    const std::string fallback =
        response.status == 401
            ? "ENROLLMENT_PROOF_INVALID"
            : (action == "create" && response.status == 404
                   ? "ENROLLMENT_ENDPOINT_UNAVAILABLE"
                   : "ENROLLMENT_REQUEST_REJECTED");
    const std::string hint =
        response.status == 401
            ? "verify system NTP clock synchronization (within 120s) and "
              "device key integrity"
            : (action == "create" && response.status == 404
                   ? "verify gateway_url points to a managed Gateway with "
                     "device enrollment enabled"
                   : "check enrollment parameters, clock synchronization, or "
                     "Gateway logs");
    return Block(current_stage_, ResponseErrorCode(response, fallback), hint,
                 response.status);
  }
  auto value = ParseHTTPJSON(response.body);
  failures_ = 0;
  state_["failures"] = 0;
  if (action == "complete") {
    Text(value, "issuer", 2048);
    auto merged = MergeCredentials(device, value, local_test_);
    if (merged["gateway_url"] != config_["gateway_url"])
      throw std::runtime_error(
          "redeemed gateway_url does not match configured gateway_url");
    // Validating is durable inside enrollment.json before replacing active
    // credentials; active credentials are written only after OAuth and Gateway
    // device-auth-check succeed.
    state_["status"] = "validating";
    state_["stage"] = "candidate_validation";
    ClearError();
    state_["credential_digest"] = CredentialDigest(merged);
    state_["pending_credentials"] = merged;
    Save();
    return Wait(0);
  }
  if (!IsUUID(Text(value, "id", 36)))
    throw std::runtime_error("invalid enrollment response id");
  if (state_.isMember("id") && state_["id"] != value["id"])
    throw std::runtime_error("enrollment response id changed");
  state_["id"] = value["id"];
  const auto remote = Text(value, "status", 32);
  if (remote != "pending" && remote != "approved" && remote != "provisioning" &&
      remote != "awaiting_install" && remote != "active" &&
      remote != "denied" && remote != "expired" && remote != "failed")
    throw std::runtime_error("unknown enrollment status");
  state_["status"] = remote;
  state_["stage"] = current_stage_;
  state_["expires_at"] = Json::Int64(Expiry(value, "expires_at"));
  auto interval = Interval(value);
  if (action == "create" && remote != "active") {
    auto code = Text(value, "device_code", 43);
    auto user = Text(value, "user_code", 9);
    if (!SecretCode(code) || !UserCode(user))
      throw std::runtime_error("invalid enrollment codes");
    state_["device_code"] = code;
    state_["user_code"] = user;
    auto console = Text(value, "console_url", 2048);
    if (!AllowedURL(console, local_test_))
      throw std::runtime_error("invalid enrollment console endpoint");
    while (console.size() > 1 && console.back() == '/') console.pop_back();
    state_["console_url"] = console;
  }
  if (remote == "denied") {
    const std::string hint =
        "administrator rejected enrollment; operator action required before "
        "retrying";
    state_["last_error_code"] = "ENROLLMENT_DENIED";
    state_["last_error_hint"] = hint;
    state_["last_http_status"] = Json::Int64(response.status);
    Save();
    NotifyOnce(current_stage_ + ":ENROLLMENT_DENIED",
               "Enrollment denied [" + current_stage_ +
                   "]: code=ENROLLMENT_DENIED (" + hint + ").");
    return {Status::Denied, 0, current_stage_, "ENROLLMENT_DENIED", hint,
            response.status};
  }
  if (remote == "failed") {
    const std::string code =
        value["error_code"].isString() &&
                SafeErrorCode(value["error_code"].asString())
            ? value["error_code"].asString()
            : "ONBOARDING_PROVISION_FAILED";
    const std::string hint =
        "cloud onboarding provisioning failed; ask administrator to retry "
        "operation in console";
    state_["last_error_code"] = code;
    state_["last_error_hint"] = hint;
    state_["last_http_status"] = Json::Int64(response.status);
    Save();
    NotifyOnce("enroll_poll:" + code,
               "Enrollment provisioning failed [enroll_poll]: code=" + code +
                   " (" + hint + ").");
    return Wait(interval);
  }
  ClearError();
  Save();
  if (remote == "expired") {
    hooks_.notice("Enrollment expired [" + current_stage_ +
                  "]; requesting a new enrollment code with the same device "
                  "key.");
    NewEnrollment();
    return Wait(5);
  }
  if (remote == "active") {
    // Active is not evidence that this machine has credentials. Missing local
    // secrets require human-approved same-key recovery on the original vehicle.
    if (HasCredentials(device) && !legacy_cross_origin &&
        CredentialDigest(device) !=
            state_.get("rejected_credential_digest", "").asString()) {
      state_["status"] = "installing";
      state_["stage"] = "installing";
      Save();
      return Authenticate(device);
    }
    hooks_.notice(
        "Enrollment is marked active on server but local credentials are "
        "missing or require issuer-bound upgrade; requesting same-vehicle "
        "recovery enrollment with administrator approval.");
    NewEnrollment();
    return Wait(5);
  }
  if (remote == "awaiting_install") {
    auto ticket = Text(value, "ticket", 43);
    if (!SecretCode(ticket))
      throw std::runtime_error("invalid installation ticket");
    state_["ticket"] = ticket;
    state_["ticket_expires_at"] =
        Json::Int64(Expiry(value, "ticket_expires_at"));
    Save();
  }
  if (action == "create" && state_.isMember("user_code"))
    hooks_.notice(
        "Enrollment code: " + state_["user_code"].asString() +
        "\nDevice fingerprint: " + FormattedFingerprint(private_key_) +
        "\nOpen " + state_["console_url"].asString() +
        "/#/admin; in vehicle management enter this code for approval.");
  if (remote == "awaiting_install" &&
      state_["ticket_expires_at"].asInt64() > hooks_.now()) {
    return Wait(0);
  }
  return Wait(interval);
}

void Bootstrap::InstallConfiguration(const Json::Value& credentials) {
  const auto path = config_["device_config"].asString();
  const auto auth_path = config_["credentials_config"].asString();
  const auto reference =
      std::filesystem::absolute(auth_path).lexically_normal().string();
  auto existing = storage_.Read(path, true, 16384);
  Json::Value runtime = existing;
  if (runtime.isNull()) {
    runtime = Json::Value(Json::objectValue);
    runtime["control_mode"] = "disabled";
    runtime["media_enabled"] = false;
    runtime["task_mode"] = "disabled";
  }
  if (!existing.isNull()) {
    if (runtime["credentials_file"] != reference)
      throw std::runtime_error(
          "runtime credentials file does not match bootstrap");
    for (const auto& name : runtime.getMemberNames())
      if (IsAuthConfigField(name))
        throw std::runtime_error(
            "runtime must not contain inline authentication");
  }
  runtime["credentials_file"] = reference;
  (void)ResolveDeviceConfig(runtime, credentials);
  if (JSON(runtime).size() + 1 > 16384)
    throw std::runtime_error("runtime device configuration exceeds 16 KiB");
  // Credentials precede the reference. A crash between writes is repaired by
  // the next self-check, before acknowledging installation.
  const auto previous_credentials = storage_.Read(auth_path, true, 16384);
  if (previous_credentials != credentials) {
    if (!previous_credentials.isNull()) {
      state_["credentials_updated"] = true;
      Save();
    }
    storage_.Write(auth_path, credentials);
  }
  if (runtime != existing) {
    storage_.Write(path, runtime);
    hooks_.notice("Created safe runtime defaults; control remains disabled.");
  }
  state_.removeMember("pending_credentials");
  state_.removeMember("rejected_credential_digest");
  state_["status"] = "installing";
  state_["stage"] = "installation_complete";
  state_["credential_digest"] = CredentialDigest(credentials);
  Save();
}
}  // namespace enrollment
}  // namespace vehicle_edge
