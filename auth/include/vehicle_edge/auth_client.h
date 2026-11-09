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
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>

#include "vehicle_edge/auth_config.h"
#include "vehicle_edge/http_client.h"

namespace vehicle_edge {

class AuthClientError : public std::runtime_error {
 public:
  AuthClientError(std::string code, std::string message, long http_status = 0)
      : std::runtime_error(std::move(message)),
        code_(std::move(code)),
        http_status_(http_status) {}

  const std::string &code() const noexcept { return code_; }
  long http_status() const noexcept { return http_status_; }

 private:
  std::string code_;
  long http_status_ = 0;
};

// Thread-safe single-flight OAuth 2.0 client_credentials token cache.
class SharedTokenProvider {
 public:
  explicit SharedTokenProvider(AuthConfig config);

  std::string GetToken();
  void InvalidateToken(const std::string &token);
  const AuthConfig &config() const noexcept { return config_; }

 private:
  void AcquireLocked();

  AuthConfig config_;
  std::mutex mutex_;
  HTTPClient http_;
  std::string token_;
  std::chrono::steady_clock::time_point expires_at_{};
};

// Device-self OAuth 2.0 client_credentials and Gateway HTTPS transport.
class AuthenticatedClient {
 public:
  explicit AuthenticatedClient(
      AuthConfig config,
      std::shared_ptr<SharedTokenProvider> token_provider = nullptr);

  void AcquireToken();
  HTTPResponse Get(const std::string &path);
  HTTPResponse Post(const std::string &path, const std::string &body);

  const AuthConfig &config() const noexcept { return config_; }
  const std::shared_ptr<SharedTokenProvider> &token_provider() const noexcept {
    return token_provider_;
  }

 private:
  AuthConfig config_;
  std::shared_ptr<SharedTokenProvider> token_provider_;
  HTTPClient http_;
};

}  // namespace vehicle_edge
