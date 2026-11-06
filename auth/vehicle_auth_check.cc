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

#include <iostream>
#include <string>

#include "vehicle_edge/diagnostics.h"

int main(int argc, char **argv) {
  bool json = false;
  std::string config_path;
  bool valid = argc == 2 || argc == 3;
  for (int i = 1; valid && i < argc; ++i) {
    const std::string argument(argv[i]);
    if (argument == "--json") {
      if (json)
        valid = false;
      json = true;
    } else if (argument.empty() || argument.front() == '-' ||
               !config_path.empty()) {
      valid = false;
    } else {
      config_path = argument;
    }
  }
  valid = valid && !config_path.empty();
  if (!valid) {
    const std::string usage =
        "usage: vehicle_auth_check [--json] /etc/teleop/device.json\n";
    std::cerr << usage;
    return 2;
  }

  const auto report = vehicle_edge::RunVehicleAuthDiagnostic(config_path);
  const auto output = json ? vehicle_edge::DiagnosticReportJSON(report)
                           : vehicle_edge::DiagnosticReportText(report);
  (report.passed || json ? std::cout : std::cerr) << output;
  if (json)
    std::cout << '\n';
  return report.passed ? 0 : 1;
}
