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

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <filesystem>
#include <iostream>
#include <set>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

#include <openssl/evp.h>

#include "vehicle_edge/http_client.h"

namespace e = vehicle_edge::enrollment;
namespace {
struct SuiteDirectory {
  std::filesystem::path previous = std::filesystem::current_path();
  std::filesystem::path directory = previous / ("bootstrap-suite-" + e::UUID());
  SuiteDirectory() {
    std::filesystem::create_directory(directory);
    chmod(directory.c_str(), 0700);
    std::filesystem::current_path(directory);
  }
  ~SuiteDirectory() {
    std::filesystem::current_path(previous);
    std::filesystem::remove_all(directory);
  }
};
void Require(bool okay, const char* message) {
  if (!okay) throw std::runtime_error(message);
}
template <class F>
void Reject(F action) {
  bool rejected = false;
  try {
    action();
  } catch (...) {
    rejected = true;
  }
  Require(rejected, "unsafe operation accepted");
}
std::string JSON(const Json::Value& value) {
  Json::StreamWriterBuilder writer;
  return Json::writeString(writer, value);
}
const std::string kID = "123e4567-e89b-42d3-a456-426614174000";
const std::string kCode = e::Base64URL(std::string(32, 'd'));
const std::string kTicket = e::Base64URL(std::string(32, 't'));

Json::Value Enrollment(const std::string& status) {
  Json::Value value(Json::objectValue);
  value["id"] = kID;
  value["status"] = status;
  value["device_code"] = kCode;
  value["user_code"] = "ABCD-1234";
  value["interval"] = 5;
  value["expires_in"] = 600;
  value["expires_at"] = "2030-01-01T00:00:00Z";
  if (status == "awaiting_install") {
    value["ticket"] = kTicket;
    value["ticket_expires_at"] = "2030-01-01T00:00:00Z";
  }
  return value;
}
Json::Value Credentials() {
  Json::Value value(Json::objectValue);
  value["vehicle_id"] = "veh-001";
  value["client_id"] = "client-new";
  value["client_secret"] = "protected-secret";
  value["gateway_url"] = "http://127.0.0.1:9999";
  value["token_url"] = "http://127.0.0.1:9999/oauth";
  value["issuer"] = "https://issuer.example.com";
  return value;
}

struct Fixture {
  std::string directory = "bootstrap-test-" + e::UUID();
  e::Storage storage{geteuid()};
  Json::Value config{Json::objectValue};
  std::int64_t now = 1700000000;
  std::vector<e::Request> requests;
  std::set<std::string> nonces;
  std::vector<std::string> notices;
  std::function<e::Response(const e::Request&)> server;
  Fixture() {
    std::filesystem::create_directory(directory);
    chmod(directory.c_str(), 0700);
    config["gateway_url"] = "http://127.0.0.1:9999";
    config["console_url"] = "http://localhost:9998";
    config["state_directory"] = directory;
    config["device_template"] = directory + "/template.json";
    config["device_config"] = directory + "/device.json";
    config["allow_insecure_localhost"] = true;
    Json::Value base(Json::objectValue);
    base["control_mode"] = "cyber";
    base["node_name"] = "vehicle_telemetry";
    base["map_id"] = "template-map";
    storage.Write(directory + "/template.json", base);
    server = [](const e::Request&) {
      return e::Response{200, JSON(Enrollment("pending"))};
    };
  }
  ~Fixture() { std::filesystem::remove_all(directory); }
  e::Hooks Hooks() {
    e::Hooks hooks;
    hooks.now = [this] { return now; };
    hooks.notice = [this](const std::string& value) {
      Require(value.find(kCode) == std::string::npos &&
                  value.find(kTicket) == std::string::npos &&
                  value.find("protected-secret") == std::string::npos,
              "notice leaked secret");
      notices.push_back(value);
    };
    hooks.request = [this](const e::Request& request) {
      Require(request.url.find(kCode) == std::string::npos &&
                  request.url.find(kTicket) == std::string::npos &&
                  request.url.find("protected-secret") == std::string::npos,
              "URL leaked secret");
      if (request.url.find("/oauth") != std::string::npos)
        Require(request.body.find("&scope=teleop%3Avehicle") != std::string::npos,
                "vehicle OAuth grant omitted its required scope");
      if (request.url.find("device-enrollments") != std::string::npos) {
        auto value = vehicle_edge::ParseHTTPJSON(request.body);
        auto action = request.url.find("/token") != std::string::npos ? "poll"
                      : request.url.find("/complete") != std::string::npos
                          ? "complete"
                          : "create";
        unsigned legacy_fields = 0;
        for (const auto* field : {"name", "serial", "platform"}) {
          if (value.isMember(field)) {
            Require(std::string(action) == "create" &&
                        State().isMember(field) && value[field] == State()[field],
                    "metadata not bound to a legacy create retry");
            ++legacy_fields;
          }
        }
        Require(value.size() == 7 + legacy_fields, "envelope not flat/exact");
        Require(nonces.insert(value["nonce"].asString()).second,
                "nonce reused");
        Require(value["timestamp"].asInt64() == now, "wrong timestamp");
        auto key = e::DecodeBase64URL(value["public_key"].asString(), 32);
        auto signature = e::DecodeBase64URL(value["signature"].asString(), 64);
        EVP_PKEY* public_key = EVP_PKEY_new_raw_public_key(
            EVP_PKEY_ED25519, nullptr,
            reinterpret_cast<const unsigned char*>(key.data()), key.size());
        EVP_MD_CTX* context = EVP_MD_CTX_new();
        auto canonical = e::Canonical(action, value);
        bool verified =
            public_key && context &&
            EVP_DigestVerifyInit(context, nullptr, nullptr, nullptr,
                                 public_key) == 1 &&
            EVP_DigestVerify(
                context,
                reinterpret_cast<const unsigned char*>(signature.data()),
                signature.size(),
                reinterpret_cast<const unsigned char*>(canonical.data()),
                canonical.size()) == 1;
        EVP_MD_CTX_free(context);
        EVP_PKEY_free(public_key);
        Require(verified, "invalid real enrollment signature");
      }
      requests.push_back(request);
      return server(request);
    };
    return hooks;
  }
  e::Result Tick(e::Bootstrap& bootstrap) {
    auto result = bootstrap.Step();
    now += result.delay;
    return result;
  }
  Json::Value State() { return storage.Read(directory + "/enrollment.json"); }
  void Existing() {
    auto device = Credentials();
    device.removeMember("issuer");
    device["control_mode"] = "cyber";
    device["map_id"] = "do-not-overwrite";
    device["media_enabled"] = false;
    device["allow_insecure_localhost"] = true;
    storage.Write(directory + "/device.json", device);
  }
};

void SignatureVector() {
  const unsigned char bytes[] = {
      0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a,
      0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32,
      0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60};
  std::string seed(reinterpret_cast<const char*>(bytes), sizeof(bytes));
  Require(e::PublicKey(seed) == "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
          "RFC8032 public key mismatch");
  Json::Value envelope(Json::objectValue);
  envelope["request_id"] = kID;
  envelope["public_key"] = e::PublicKey(seed);
  envelope["name"] = "Vehicle";
  envelope["serial"] = "serial";
  envelope["platform"] = "apollo";
  envelope["device_code"] = "";
  envelope["ticket"] = "";
  envelope["timestamp"] = Json::Int64(1700000000);
  envelope["nonce"] = "123e4567-e89b-42d3-a456-426614174001";
  Require(
      e::Canonical("create", envelope) ==
          "teleop-enrollment-v1\ncreate\n123e4567-e89b-42d3-a456-426614174000\n"
          "11qYAYKxCrfVS_"
          "7TyWQHOg7hcvPapiMlrwIaaPcHURo\nVehicle\nserial\napollo\n\n\n"
          "1700000000\n123e4567-e89b-42d3-a456-426614174001",
      "canonical mismatch");
  // Independently generated using Python cryptography, not this implementation.
  Require(e::Sign("create", envelope, seed)["signature"] ==
              "7Tjt-"
              "XbWubxuS1CK8LLqyjGIjgQ4q3sTavIhoU90oM40emSFELsNpy0pPgkgxWx2AJyQQ"
              "rTJ5bkSBg-8-eRgBg",
          "enrollment signature vector mismatch");
  Reject([&] { e::DecodeBase64URL(e::PublicKey(seed) + "=", 32); });
  for (const auto* field : {"name", "serial", "platform"})
    envelope.removeMember(field);
  Require(e::Canonical("create", envelope) ==
              "teleop-enrollment-v1\ncreate\n123e4567-e89b-42d3-a456-426614174000\n"
              "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\n\n\n\n\n\n"
              "1700000000\n123e4567-e89b-42d3-a456-426614174001",
          "metadata-free v1 canonical mismatch");
  auto signed_request = e::Sign("create", envelope, seed);
  for (const auto* field : {"name", "serial", "platform"}) {
    Require(!signed_request.isMember(field), "signing restored retired metadata");
    auto invalid = envelope;
    invalid[field] = Json::nullValue;
    Reject([&] { e::Canonical("create", invalid); });
  }
  envelope.removeMember("public_key");
  Reject([&] { e::Canonical("create", envelope); });
}

void MetadataFreeConfigurationAndLegacyRetry() {
  Fixture f;
  // Existing files are accepted, but their obsolete fields cannot become a
  // new vehicle identity or new enrollment metadata.
  f.config["name"] = "Old display name";
  f.config["serial"] = "Old serial";
  f.config["platform"] = "Old platform";
  f.server = [](const e::Request&) -> e::Response { throw e::TransportError(); };
  {
    e::Bootstrap b(f.config, f.Hooks(), f.storage);
    f.Tick(b);
  }
  auto state = f.State();
  for (const auto* field : {"name", "serial", "platform"}) {
    Require(!state.isMember(field), "new enrollment persisted obsolete metadata");
    state[field] = f.config[field];
    f.config.removeMember(field);
  }
  // Model a create response lost before upgrading the SDK. The saved request
  // must be replayed unchanged even though bootstrap.json has no metadata.
  f.storage.Write(f.directory + "/enrollment.json", state);
  f.server = [](const e::Request&) { return e::Response{201, JSON(Enrollment("pending"))}; };
  {
    e::Bootstrap b(f.config, f.Hooks(), f.storage);
    f.Tick(b);
    auto retry = vehicle_edge::ParseHTTPJSON(f.requests.back().body);
    Require(retry["request_id"] == state["request_id"] &&
                retry["public_key"] == state["public_key"],
            "legacy retry changed the request or key");
    for (const auto* field : {"name", "serial", "platform"})
      Require(retry[field] == state[field], "legacy retry changed signed metadata");
    f.Tick(b);
    auto poll = vehicle_edge::ParseHTTPJSON(f.requests.back().body);
    for (const auto* field : {"name", "serial", "platform"})
      Require(!poll.isMember(field), "poll sent retired metadata");
  }
}

void RestartAndNetwork() {
  Fixture f;
  f.server = [](const e::Request&) -> e::Response {
    throw e::TransportError();
  };
  std::string request_id, public_key;
  {
    e::Bootstrap b(f.config, f.Hooks(), f.storage);
    auto result = f.Tick(b);
    Require(result.delay >= 5 && result.delay <= 10,
            "first jitter out of bounds");
    auto state = f.State();
    Require(state["stage"] == "enroll_create" &&
                state["last_error_code"] == "TRANSPORT_UNAVAILABLE" &&
                !state.isMember("last_http_status") &&
                f.notices.back().find("code=TRANSPORT_UNAVAILABLE") !=
                    std::string::npos,
            "transport diagnostic missing");
    request_id = state["request_id"].asString();
    public_key = state["public_key"].asString();
    auto count = f.requests.size();
    f.now -= result.delay;
    Require(b.Step().status == e::Status::Waiting && f.requests.size() == count,
            "restart pacing deadline ignored");
    f.now += result.delay;
    Reject([&] { e::Bootstrap other(f.config, f.Hooks(), f.storage); });
  }
  f.server = [](const e::Request&) {
    return e::Response{503, "issuer unavailable"};
  };
  {
    e::Bootstrap b(f.config, f.Hooks(), f.storage);
    f.Tick(b);
    Require(f.State()["request_id"] == request_id &&
                f.State()["public_key"] == public_key &&
                f.State()["last_error_code"] == "UPSTREAM_UNAVAILABLE" &&
                f.State()["last_http_status"] == 503,
            "network error rotated identity or omitted 503 diagnostic");
  }
  f.server = [](const e::Request&) {
    return e::Response{201, JSON(Enrollment("pending"))};
  };
  {
    e::Bootstrap b(f.config, f.Hooks(), f.storage);
    f.Tick(b);
    Require(f.State()["request_id"] == request_id &&
                !f.State().isMember("last_error_code") &&
                !f.State().isMember("last_http_status"),
            "lost create response not resumed or retained error diagnostic");
    Require(f.notices.back().find(kCode) == std::string::npos &&
                f.notices.back().find("ABCD-1234") != std::string::npos,
            "notice leaked device code or omitted user code");
  }
}

void ExpiryDenialAndThrottle() {
  Fixture f;
  {
    e::Bootstrap b(f.config, f.Hooks(), f.storage);
    f.Tick(b);
    auto request = f.State()["request_id"];
    auto key = f.State()["public_key"];
    f.server = [](const e::Request&) { return e::Response{429, "", 60}; };
    Require(f.Tick(b).delay >= 60, "Retry-After ignored");
    Require(f.State()["request_id"] == request &&
                f.State()["stage"] == "enroll_poll" &&
                f.State()["last_error_code"] == "ENROLLMENT_SLOW_DOWN" &&
                f.State()["last_http_status"] == 429,
            "429 rotated request or omitted diagnostic");
    f.server = [](const e::Request&) {
      return e::Response{200, JSON(Enrollment("expired"))};
    };
    f.Tick(b);
    Require(
        f.State()["request_id"] != request && f.State()["public_key"] == key,
        "expiry did not refresh request retaining key");
    f.server = [](const e::Request&) {
      return e::Response{200, JSON(Enrollment("denied"))};
    };
    auto denied = f.Tick(b);
    Require(denied.status == e::Status::Denied &&
                denied.error_code == "ENROLLMENT_DENIED" &&
                f.State()["last_error_code"] == "ENROLLMENT_DENIED",
            "denial not final or diagnostic missing");
  }
  auto count = f.requests.size();
  e::Bootstrap restart(f.config, f.Hooks(), f.storage);
  Require(
      restart.Step().status == e::Status::Denied && f.requests.size() == count,
      "denial refreshed on restart");
}

void AuthenticationClassification() {
  for (const auto& response :
       {e::Response{500, "{\"error\":\"invalid_client\"}"},
        e::Response{403, "{\"error\":\"invalid_client\"}"},
        e::Response{401, "{\"error\":\"server_error\"}"},
        e::Response{401, "not json"}})
    Require(!e::InvalidCredentials(response),
            "outage confused with invalid credentials");
  Require(e::InvalidCredentials({400, "{\"error\":\"invalid_client\"}"}),
          "explicit invalid_client not recognized");
  for (int scenario = 0; scenario < 5; ++scenario) {
    Fixture f;
    f.Existing();
    f.server = [scenario](const e::Request& request) -> e::Response {
      if (request.url.find("/oauth") != std::string::npos) {
        if (scenario == 0) throw e::TransportError();
        if (scenario == 1) return {500, "{\"error\":\"invalid_client\"}"};
        if (scenario == 2) return {400, "{\"error\":\"invalid_client\"}"};
        return {200, "{\"access_token\":\"machine-token\",\"expires_in\":300}"};
      }
      return {scenario == 3 ? 403 : 401,
              scenario == 3 ? "{\"code\":\"VEHICLE_IDENTITY_MISMATCH\"}"
                            : "{\"code\":\"OIDC_SCOPE_MISSING\"}"};
    };
    e::Bootstrap b(f.config, f.Hooks(), f.storage);
    auto result = f.Tick(b);
    Require(f.State().isMember("request_id") == (scenario == 2),
            "non-credential failure created enrollment");
    Require(result.status ==
                (scenario < 3 ? e::Status::Waiting : e::Status::Blocked),
            "auth failure classification mismatch");
    if (scenario >= 3) {
      Require(result.stage == "device_auth_check" &&
                  result.error_code ==
                      (scenario == 3 ? "VEHICLE_IDENTITY_MISMATCH"
                                     : "OIDC_SCOPE_MISSING") &&
                  result.http_status == (scenario == 3 ? 403 : 401) &&
                  f.State()["last_error_code"] == result.error_code,
              "blocked device_auth_check diagnostic mismatch");
    }
    Require(
        f.storage.Read(f.directory + "/device.json")["control_mode"] == "cyber",
        "auth recovery changed runtime control");
  }
}

void PendingCredentialRecoverySurvivesTimers() {
  Fixture f;
  f.Existing();
  f.server = [](const e::Request&) {
    return e::Response{400, "{\"error\":\"invalid_client\"}"};
  };
  {
    e::Bootstrap b(f.config, f.Hooks(), f.storage);
    f.Tick(b);
  }
  const auto id = f.State()["request_id"];
  const auto key = f.State()["public_key"];
  f.server = [](const e::Request& request) {
    Require(request.url.find("device-enrollments") != std::string::npos,
            "pending recovery retried rejected OAuth credentials");
    return e::Response{200, JSON(Enrollment("pending"))};
  };
  {
    e::Bootstrap b(f.config, f.Hooks(), f.storage);
    f.Tick(b);
    Require(f.State()["request_id"] == id && f.State()["public_key"] == key,
            "restart before create regenerated recovery");
  }
  {
    e::Bootstrap b(f.config, f.Hooks(), f.storage);
    f.Tick(b);
    Require(f.requests.back().url.find("/token") != std::string::npos &&
                f.State()["request_id"] == id &&
                f.State()["device_code"] == kCode,
            "pending timer run created another enrollment code");
  }
}

void InstallLostResponsesAndRecovery() {
  Fixture f;
  bool lose_complete = true, lose_ack = true;
  f.server = [&](const e::Request& request) -> e::Response {
    if (request.url.find("/device-enrollments/complete") != std::string::npos) {
      if (lose_complete) {
        lose_complete = false;
        throw e::TransportError();
      }
      return {200, JSON(Credentials())};
    }
    if (request.url.find("device-enrollments/token") != std::string::npos)
      return {200, JSON(Enrollment("awaiting_install"))};
    if (request.url.find("device-enrollments") != std::string::npos)
      return {201, JSON(Enrollment("pending"))};
    if (request.url.find("/oauth") != std::string::npos)
      return {200, "{\"access_token\":\"machine-token\",\"expires_in\":300}"};
    if (request.url.find("/device-auth-check") != std::string::npos)
      return {204, ""};
    Require(request.url.find("/installation-complete") != std::string::npos,
            "unexpected installation endpoint");
    Require(f.storage.Read(f.directory + "/device.json")["client_secret"] ==
                "protected-secret",
            "ack occurred before durable credential write");
    if (lose_ack) {
      lose_ack = false;
      throw e::TransportError();
    }
    return {204, ""};
  };
  Json::Value lost;
  {
    e::Bootstrap b(f.config, f.Hooks(), f.storage);
    f.Tick(b);
    auto approved = f.Tick(b);
    Require(approved.delay == 0,
            "awaiting_install did not immediately schedule complete");
    f.Tick(b);
    lost = vehicle_edge::ParseHTTPJSON(f.requests.back().body);
  }
  {
    e::Bootstrap b(f.config, f.Hooks(), f.storage);
    auto completed = f.Tick(b);
    Require(completed.delay == 0,
            "complete did not immediately schedule authenticate");
    auto retry = vehicle_edge::ParseHTTPJSON(f.requests.back().body);
    Require(lost["request_id"] == retry["request_id"] &&
                lost["ticket"] == retry["ticket"] &&
                lost["nonce"] != retry["nonce"],
            "lost redeem response rotated credential");
    auto device = f.storage.Read(f.directory + "/device.json");
    Require(device["control_mode"] == "disabled",
            "new install enabled control");
    Require(f.Tick(b).status == e::Status::Waiting,
            "lost ack reported success");
  }
  {
    e::Bootstrap b(f.config, f.Hooks(), f.storage);
    Require(f.Tick(b).status == e::Status::Ready,
            "restart failed to retry machine ack");
    Require(!f.State().isMember("ticket") && !f.State().isMember("device_code"),
            "installed state retained enrollment secrets");
  }
  auto key = f.State()["public_key"];
  std::filesystem::remove(f.directory + "/device.json");
  {
    e::Bootstrap b(f.config, f.Hooks(), f.storage);
    Require(f.Tick(b).status == e::Status::Waiting &&
                f.State()["public_key"] == key &&
                f.State()["status"] == "pending",
            "lost active credentials did not require same-key approval");
  }
}

void CrashBetweenIntentAndWrite() {
  Fixture f;
  f.server = [](const e::Request& request) -> e::Response {
    if (request.url.find("/complete") != std::string::npos)
      return {200, JSON(Credentials())};
    return {200, JSON(Enrollment("awaiting_install"))};
  };
  {
    e::Bootstrap b(f.config, f.Hooks(), f.storage);
    f.Tick(b);
    f.Tick(b);
  }
  auto state = f.State();
  Require(state["status"] == "installing", "installation intent not saved");
  f.Existing();
  auto old = f.storage.Read(f.directory + "/device.json");
  old["client_id"] = "old-client";
  old["client_secret"] = "old-secret";
  f.storage.Write(f.directory + "/device.json", old);
  {
    e::Bootstrap b(f.config, f.Hooks(), f.storage);
    f.Tick(b);
    Require(f.requests.back().url.find("/complete") != std::string::npos,
            "crash before credential write authenticated rejected old secret");
    auto merged = f.storage.Read(f.directory + "/device.json");
    Require(merged["map_id"] == "do-not-overwrite" &&
                merged["media_enabled"] == false &&
                merged["control_mode"] == "cyber",
            "recovery overwrote runtime configuration");
  }
}

void LegacyAckAndActiveWithoutSecret() {
  for (bool allow : {false, true}) {
    Fixture f;
    f.Existing();
    f.config["allow_legacy_complete_404"] = allow;
    f.server = [](const e::Request& request) -> e::Response {
      if (request.url.find("/oauth") != std::string::npos)
        return {200, "{\"access_token\":\"machine-token\",\"expires_in\":300}"};
      return {request.url.find("device-auth-check") != std::string::npos ? 204
                                                                         : 404,
              ""};
    };
    e::Bootstrap b(f.config, f.Hooks(), f.storage);
    Require(f.Tick(b).status == (allow ? e::Status::Ready : e::Status::Blocked),
            "legacy ack opt-in not enforced");
  }
  Fixture f;
  f.config["allow_legacy_complete_404"] = true;
  f.server = [](const e::Request&) {
    auto active = Enrollment("active");
    active.removeMember("device_code");
    active.removeMember("user_code");
    return e::Response{200, JSON(active)};
  };
  e::Bootstrap b(f.config, f.Hooks(), f.storage);
  Require(f.Tick(b).status == e::Status::Waiting &&
              f.State()["status"] == "creating",
          "active marked ready without secret");
}

void FailedRepairAndInvalidEnrollment() {
  Fixture f;
  std::string key, request;
  {
    e::Bootstrap b(f.config, f.Hooks(), f.storage);
    f.Tick(b);
    key = f.State()["public_key"].asString();
    request = f.State()["request_id"].asString();
    f.server = [](const e::Request&) {
      auto failed = Enrollment("failed");
      failed["error_code"] = "CASDOOR_PROVISION_FAILED";
      return e::Response{200, JSON(failed)};
    };
    Require(f.Tick(b).status == e::Status::Waiting &&
                f.State()["request_id"] == request &&
                f.State()["last_error_code"] == "CASDOOR_PROVISION_FAILED" &&
                f.notices.back().find("code=CASDOOR_PROVISION_FAILED") !=
                    std::string::npos,
            "provider failure refreshed code or omitted error_code");
    const auto notice_count = f.notices.size();
    Require(f.Tick(b).status == e::Status::Waiting &&
                f.notices.size() == notice_count,
            "repeated failed poll spammed duplicate notices");
  }
  {
    e::Bootstrap b(f.config, f.Hooks(), f.storage);
    f.server = [](const e::Request&) {
      return e::Response{200, JSON(Enrollment("pending"))};
    };
    f.Tick(b);
    Require(f.State()["status"] == "pending" &&
                f.State()["request_id"] == request &&
                !f.State().isMember("last_error_code"),
            "failed onboarding not repairable or retained failed error_code");
    f.server = [](const e::Request&) {
      return e::Response{401, "{\"code\":\"ENROLLMENT_PROOF_INVALID\"}"};
    };
    auto blocked = f.Tick(b);
    Require(blocked.status == e::Status::Blocked &&
                blocked.stage == "enroll_poll" &&
                blocked.error_code == "ENROLLMENT_PROOF_INVALID" &&
                blocked.http_status == 401 &&
                blocked.message.find("NTP") != std::string::npos &&
                f.State()["request_id"] == request &&
                f.State()["last_error_code"] == "ENROLLMENT_PROOF_INVALID",
            "bad proof refreshed code or omitted proof diagnostic");
    f.now += 5;
    f.server = [](const e::Request&) { return e::Response{404, ""}; };
    f.Tick(b);
    Require(
        f.State()["request_id"] != request && f.State()["public_key"] == key,
        "missing enrollment recovery lost identity");
  }
}

void TicketExpiryAndNewAck() {
  Fixture f;
  f.config["allow_legacy_complete_404"] = true;
  f.server = [](const e::Request&) {
    auto value = Enrollment("awaiting_install");
    value["ticket_expires_at"] = "2020-01-01T00:00:00Z";
    return e::Response{200, JSON(value)};
  };
  e::Bootstrap b(f.config, f.Hooks(), f.storage);
  f.Tick(b);
  const auto request = f.State()["request_id"];
  f.server = [](const e::Request&) {
    return e::Response{200, JSON(Enrollment("awaiting_install"))};
  };
  f.Tick(b);
  Require(f.requests.back().url.find("/token") != std::string::npos,
          "expired ticket was redeemed rather than re-polled");
  f.server = [](const e::Request&) { return e::Response{410, ""}; };
  f.Tick(b);
  Require(f.State()["request_id"] == request && !f.State().isMember("ticket"),
          "ticket expiry race changed enrollment");
  f.server = [](const e::Request&) {
    return e::Response{200, JSON(Enrollment("awaiting_install"))};
  };
  f.Tick(b);
  f.server = [](const e::Request&) {
    return e::Response{200, JSON(Credentials())};
  };
  f.Tick(b);
  f.server = [](const e::Request& req) -> e::Response {
    if (req.url.find("/oauth") != std::string::npos)
      return {200, "{\"access_token\":\"machine-token\",\"expires_in\":300}"};
    return {req.url.find("device-auth-check") != std::string::npos ? 204 : 404,
            ""};
  };
  Require(f.Tick(b).status == e::Status::Blocked &&
              f.State()["status"] == "installing",
          "new enrollment bypassed ack using legacy 404 option");
}

void LocalHTTPTransport() {
  int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  Require(listener >= 0, "local test socket unavailable");
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) ||
      listen(listener, 1)) {
    close(listener);
    throw std::runtime_error("local test listener failed");
  }
  socklen_t size = sizeof(address);
  Require(
      getsockname(listener, reinterpret_cast<sockaddr*>(&address), &size) == 0,
      "local port unavailable");
  std::thread server([listener] {
    fd_set ready;
    FD_ZERO(&ready);
    FD_SET(listener, &ready);
    timeval timeout{5, 0};
    if (select(listener + 1, &ready, nullptr, nullptr, &timeout) > 0) {
      int client = accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
      if (client >= 0) {
        timeval receive_timeout{5, 0};
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &receive_timeout,
                   sizeof(receive_timeout));
        char buffer[4096];
        recv(client, buffer, sizeof(buffer), 0);
        const std::string response =
            "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 17\r\n"
            "Content-Length: 2\r\nConnection: close\r\n\r\n{}";
        send(client, response.data(), response.size(), MSG_NOSIGNAL);
        close(client);
      }
    }
    close(listener);
  });
  e::Response response;
  try {
    response =
        e::Send({"POST",
                 "http://127.0.0.1:" + std::to_string(ntohs(address.sin_port)) +
                     "/api/v1/device-enrollments",
                 "application/json", "{}", "", true});
  } catch (...) {
    server.join();
    throw;
  }
  server.join();
  Require(response.status == 429 && response.retry_after == 17 &&
              response.body == "{}",
          "real libcurl Retry-After transport failed");
}
void SafeStorageAndMerge() {
  Fixture f;
  const auto path = f.directory + "/safe.json";
  Json::Value value(Json::objectValue);
  value["secret"] = "local-only";
  f.storage.Write(path, value);
  struct stat s{};
  Require(stat(path.c_str(), &s) == 0 && (s.st_mode & 0777) == 0600 &&
              s.st_uid == geteuid(),
          "atomic write ownership/mode incorrect");
  value["secret"] = "replacement";
  f.storage.Write(path, value);
  Require(f.storage.Read(path) == value, "atomic replacement failed");
  if (geteuid() != 0) Reject([&] { e::Storage().Read(path); });
  chmod(path.c_str(), 0644);
  Reject([&] { f.storage.Read(path); });
  Reject([&] { f.storage.Write(path, value); });
  chmod(path.c_str(), 0600);
  std::filesystem::create_symlink("safe.json", f.directory + "/link.json");
  Reject([&] { f.storage.Read(f.directory + "/link.json"); });
  Reject([&] { f.storage.Write(f.directory + "/link.json", value); });
  std::filesystem::create_hard_link(path, f.directory + "/hard.json");
  Reject([&] { f.storage.Write(path, value); });
  std::filesystem::remove(f.directory + "/hard.json");
  auto credentials = Credentials();
  auto existing = credentials;
  existing.removeMember("issuer");
  existing["vehicle_id"] = "another-vehicle";
  Reject([&] {
    e::MergeDevice(Json::Value(Json::objectValue), existing, credentials, true);
  });
  Json::Value oversized(Json::objectValue);
  oversized["software_version"] = std::string(17000, 'v');
  Reject([&] { e::MergeDevice(oversized, Json::Value(), credentials, true); });
  Require(!vehicle_edge::AllowedURL("http://gateway.example.com", true),
          "local test enabled remote HTTP");
  Require(!vehicle_edge::AllowedURL("https://user:secret@example.com", false),
          "credential-bearing endpoint accepted");
  Reject([&] {
    e::Send({"POST", "http://gateway.example.com", "application/json", "{}", "",
             true});
  });
  for (const auto& entry : std::filesystem::directory_iterator(f.directory))
    Require(entry.path().extension() != ".new", "atomic scratch file leaked");
}
}  // namespace

int main() {
  try {
    SuiteDirectory suite;
    SignatureVector();
    MetadataFreeConfigurationAndLegacyRetry();
    RestartAndNetwork();
    ExpiryDenialAndThrottle();
    AuthenticationClassification();
    PendingCredentialRecoverySurvivesTimers();
    InstallLostResponsesAndRecovery();
    CrashBetweenIntentAndWrite();
    LegacyAckAndActiveWithoutSecret();
    FailedRepairAndInvalidEnrollment();
    TicketExpiryAndNewAck();
    LocalHTTPTransport();
    SafeStorageAndMerge();
    std::cout << "bootstrap tests passed\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << "\n";
    return 1;
  }
}
