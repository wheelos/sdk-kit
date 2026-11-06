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

#include "vehicle_edge/auth_client.h"

#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <utility>

namespace vehicle_edge {
namespace {

void ValidateAPIPath(const std::string &path) {
  if (path.rfind("/api/", 0) != 0 ||
      std::any_of(path.begin(), path.end(),
                  [](unsigned char ch) { return ch <= 0x20 || ch >= 0x7f; }) ||
      path.find_first_of("?#\\\r\n") != std::string::npos ||
      path.find("/../") != std::string::npos ||
      path.find("/./") != std::string::npos ||
      (path.size() >= 3 && path.compare(path.size() - 3, 3, "/..") == 0) ||
      (path.size() >= 2 && path.compare(path.size() - 2, 2, "/.") == 0) ||
      path.find('%') != std::string::npos) {
    throw std::invalid_argument("device request requires a literal API path");
  }
}

}  // namespace

SharedTokenProvider::SharedTokenProvider(AuthConfig config)
    : config_(std::move(config)) {}

std::string SharedTokenProvider::GetToken() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (config_.IsLocalSimDebug()) {
    if (!LoopbackURL(config_.gateway_url)) {
      throw AuthClientError("local_debug_non_loopback",
                            "local_sim_debug requires a loopback gateway_url");
    }
    if (!ValidIdentifier(config_.vehicle_id)) {
      throw AuthClientError("local_debug_invalid_vehicle",
                            "local_sim_debug requires a valid vehicle_id");
    }
    token_ = config_.vehicle_id + "|vehicle|vehicle,teleop:vehicle";
    expires_at_ = std::chrono::steady_clock::now() + std::chrono::hours(24);
    return token_;
  }
  if (token_.empty() || std::chrono::steady_clock::now() >= expires_at_) {
    AcquireLocked();
  }
  return token_;
}

void SharedTokenProvider::InvalidateToken(const std::string &token) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (token_ == token) {
    token_.clear();
    expires_at_ = {};
  }
}

void SharedTokenProvider::AcquireLocked() {
  const auto started = std::chrono::steady_clock::now();
  HTTPClient http;
  HTTPResponse response{};
  try {
    response =
        http.Post(config_.token_url, "application/x-www-form-urlencoded",
                  "grant_type=client_credentials&client_id=" +
                      http.Escape(config_.client_id) +
                      "&client_secret=" + http.Escape(config_.client_secret),
                  "", config_.allow_insecure_localhost);
  } catch (...) {
    throw AuthClientError("oauth_transport_error",
                          "OAuth token request failed at the transport");
  }
  if (response.status != 200) {
    throw AuthClientError("oauth_http_error",
                          "OAuth token endpoint rejected the request",
                          response.status);
  }
  Json::Value value;
  try {
    value = ParseHTTPJSON(response.body);
  } catch (...) {
    throw AuthClientError("oauth_response_invalid",
                          "OAuth token response was not valid JSON");
  }
  if (!value["access_token"].isString() ||
      !ValidBearerToken(value["access_token"].asString()) ||
      !value["expires_in"].isNumeric()) {
    throw AuthClientError("oauth_response_invalid",
                          "OAuth token response was incomplete or invalid");
  }
  const auto seconds = value["expires_in"].asDouble();
  if (!std::isfinite(seconds) || seconds < 5 || seconds > 86400) {
    throw AuthClientError("oauth_expiry_invalid",
                          "OAuth expiry was outside the supported range");
  }
  token_ = value["access_token"].asString();
  expires_at_ = started + std::chrono::milliseconds(
                              static_cast<std::int64_t>(seconds * 800));
}

AuthenticatedClient::AuthenticatedClient(
    AuthConfig config, std::shared_ptr<SharedTokenProvider> token_provider)
    : config_(std::move(config)),
      token_provider_(token_provider
                          ? std::move(token_provider)
                          : std::make_shared<SharedTokenProvider>(config_)) {}

void AuthenticatedClient::AcquireToken() {
  (void)token_provider_->GetToken();
}

HTTPResponse AuthenticatedClient::Get(const std::string &path) {
  ValidateAPIPath(path);
  if (config_.IsLocalSimDebug() && !LoopbackURL(config_.gateway_url)) {
    throw std::invalid_argument(
        "local_sim_debug requires loopback gateway_url");
  }
  const auto token = token_provider_->GetToken();
  auto response = http_.Get(config_.gateway_url + path, token,
                            config_.allow_insecure_localhost);
  if (response.status == 401) {
    token_provider_->InvalidateToken(token);
  }
  return response;
}

HTTPResponse AuthenticatedClient::Post(const std::string &path,
                                       const std::string &body) {
  ValidateAPIPath(path);
  if (config_.IsLocalSimDebug() && !LoopbackURL(config_.gateway_url)) {
    throw std::invalid_argument(
        "local_sim_debug requires loopback gateway_url");
  }
  if (body.size() > 65536) {
    throw std::invalid_argument("device request body exceeds 64 KiB");
  }
  const auto token = token_provider_->GetToken();
  auto response = http_.Post(config_.gateway_url + path, "application/json",
                             body, token, config_.allow_insecure_localhost);
  if (response.status == 401) {
    token_provider_->InvalidateToken(token);
  }
  return response;
}

}  // namespace vehicle_edge
