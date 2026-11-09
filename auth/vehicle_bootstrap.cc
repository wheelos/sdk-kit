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

#include <signal.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <exception>
#include <iostream>
#include <string>
#include <thread>

#include "vehicle_edge/bootstrap.h"

namespace {
volatile sig_atomic_t cancelled = 0;
void Cancel(int) { cancelled = 1; }
bool SafeDiagnosticText(const std::string& text) {
  if (text.empty() || text.size() > 120 || text.find(' ') == std::string::npos)
    return false;
  return std::all_of(text.begin(), text.end(), [](unsigned char c) {
    return c >= 32 && c < 127 && c != '"' && c != '\\';
  });
}
}  // namespace

int main(int argc, char** argv) {
  if (argc != 3 || std::string(argv[1]) != "--config") {
    std::cerr
        << "Usage: vehicle_bootstrap --config /etc/teleop/bootstrap.json\n";
    return 78;
  }
  if (geteuid() != 0) {
    std::cerr << "Bootstrap requires root-owned protected storage.\n";
    return 78;
  }
  const rlimit no_core{0, 0};
  if (setrlimit(RLIMIT_CORE, &no_core) || prctl(PR_SET_DUMPABLE, 0)) {
    std::cerr << "Cannot protect bootstrap process memory.\n";
    return 78;
  }
  signal(SIGTERM, Cancel);
  signal(SIGINT, Cancel);
  try {
    vehicle_edge::enrollment::Storage storage;
    vehicle_edge::enrollment::Hooks hooks;
    hooks.notice = [](const std::string& message) {
      std::cout << message << std::endl;
    };
    vehicle_edge::enrollment::Bootstrap bootstrap(storage.Read(argv[2]), hooks);
    while (!cancelled) {
      auto result = bootstrap.Step();
      using vehicle_edge::enrollment::Status;
      if (result.status == Status::Ready) {
        std::cout << "Vehicle authentication and installation acknowledged.\n";
        return 0;
      }
      if (result.status == Status::Denied) {
        std::cerr << "Enrollment denied; operator action required.";
        if (!result.stage.empty() || !result.error_code.empty()) {
          std::cerr << " [stage=" << result.stage
                    << " code=" << result.error_code;
          if (!result.message.empty())
            std::cerr << " hint=\"" << result.message << "\"";
          std::cerr << "]";
        }
        std::cerr << "\n";
        return 77;
      }
      if (result.status == Status::Blocked) {
        std::cerr << "Bootstrap blocked; check approval, issuer or mapping "
                     "with administrator.";
        if (!result.stage.empty() || !result.error_code.empty()) {
          std::cerr << " [stage=" << result.stage
                    << " code=" << result.error_code;
          if (result.http_status > 0)
            std::cerr << " http=" << result.http_status;
          if (!result.message.empty())
            std::cerr << " hint=\"" << result.message << "\"";
          std::cerr << "]";
        }
        std::cerr << "\n";
        return 78;
      }
      for (unsigned i = 0; i < result.delay && !cancelled; ++i)
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    return 0;
  } catch (const std::exception& error) {
    // Only fixed internal reason strings are printed; raw HTTP bodies and
    // single-token values are never emitted.
    std::cerr << "Bootstrap configuration, protocol or protected storage "
                 "failure.";
    const std::string reason = error.what() ? error.what() : "";
    if (SafeDiagnosticText(reason)) {
      std::cerr << " [reason=\"" << reason << "\"]";
    }
    std::cerr << "\n";
    return 78;
  } catch (...) {
    std::cerr
        << "Bootstrap configuration, protocol or protected storage failure.\n";
    return 78;
  }
}
