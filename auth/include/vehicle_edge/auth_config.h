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

#include <string>

#include <json/json.h>

namespace vehicle_edge {

struct AuthConfig {
  std::string auth_mode = "required";
  std::string vehicle_id;
  std::string gateway_url;
  std::string token_url;
  std::string issuer;
  std::string client_id;
  std::string client_secret;
  std::string credentials_file;
  bool allow_insecure_localhost = false;

  bool IsLocalSimDebug() const noexcept {
    return auth_mode == "local_sim_debug";
  }
};

bool ValidIdentifier(const std::string &value);
bool LoopbackURL(const std::string &url);
bool AllowedURL(const std::string &url, bool allow_insecure_localhost);
std::string ClockReadinessError();
std::string ClockDisciplineError(int state, int status, long maxerror);
bool TrustedTokenEndpoint(const std::string &token_url,
                          const std::string &gateway_url,
                          const std::string &issuer,
                          bool allow_insecure_localhost);
Json::Value LoadProtectedJSON(const std::string &path);
bool IsAuthConfigField(const std::string &name);
Json::Value ResolveDeviceConfig(const Json::Value &runtime,
                                const Json::Value &credentials);
Json::Value LoadDeviceConfigJSON(const std::string &path);
AuthConfig ParseAuthConfig(const Json::Value &value);
AuthConfig LoadAuthConfig(const std::string &path);

}  // namespace vehicle_edge
