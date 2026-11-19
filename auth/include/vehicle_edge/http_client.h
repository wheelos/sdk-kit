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

#pragma once

#include <chrono>
#include <stdexcept>
#include <string>

#include <curl/curl.h>
#include <json/json.h>

#include "vehicle_edge/auth_config.h"

namespace vehicle_edge {

// Per-transfer limits in milliseconds. The total includes connection setup,
// but not a caller's wait for a shared OAuth token.
struct HTTPTimeouts {
  long connect_ms = 1000;
  long total_ms = 2000;
};

struct HTTPResponse {
  long status = 0;
  std::string body;
  std::string request_id;
  std::string error_code;
  // Safe summary: fixed request category, host and cumulative curl timings.
  // Never contains URL paths, headers, request bodies or response bodies.
  std::string diagnostics;
};

class HTTPTransportError : public std::runtime_error {
 public:
  HTTPTransportError(CURLcode code, const std::string &diagnostics)
      : std::runtime_error("HTTP transport failed (curl code " +
                           std::to_string(static_cast<int>(code)) + "): " +
                           diagnostics),
        code_(code) {}
  CURLcode code() const noexcept { return code_; }

 private:
  CURLcode code_;
};

Json::Value ParseHTTPJSON(const std::string &text);
bool ValidBearerToken(const std::string &token);
void InitializeHTTPTransport();

class HTTPClient {
 public:
  HTTPClient();
  ~HTTPClient();
  HTTPClient(const HTTPClient &) = delete;
  HTTPClient &operator=(const HTTPClient &) = delete;

  HTTPResponse Post(const std::string &url, const std::string &content_type,
                    const std::string &body, const std::string &bearer,
                    bool allow_insecure_localhost,
                    HTTPTimeouts timeouts = {});
  HTTPResponse Get(const std::string &url, const std::string &bearer,
                   bool allow_insecure_localhost,
                   HTTPTimeouts timeouts = {});
  std::string Escape(const std::string &value) const;

 private:
  HTTPResponse Request(const std::string &url, const std::string &content_type,
                       const std::string &body, const std::string &bearer,
                       bool allow_insecure_localhost, bool post,
                       HTTPTimeouts timeouts);

  CURL *handle_;
  std::chrono::steady_clock::time_point next_slow_log_{};
};

}  // namespace vehicle_edge
