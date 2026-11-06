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
#include <cstdint>
#include <string>
#include <vector>

#include "vehicle_edge/auth_config.h"

namespace vehicle_edge {

struct DiagnosticStage {
  std::string name;
  std::string label;
  bool passed = false;
  std::int64_t elapsed_ms = 0;
  std::string code;
  std::string message;
  long http_status = 0;
  std::string request_id;
  std::string gateway_error_code;
  std::chrono::steady_clock::time_point started_at{};
};

struct DiagnosticReport {
  bool passed = false;
  std::vector<DiagnosticStage> stages;
};

DiagnosticReport RunVehicleAuthDiagnostic(const std::string &config_path);
DiagnosticReport RunVehicleAuthDiagnostic(const AuthConfig &config);
std::string DiagnosticReportJSON(const DiagnosticReport &report);
std::string DiagnosticReportText(const DiagnosticReport &report);

}  // namespace vehicle_edge
