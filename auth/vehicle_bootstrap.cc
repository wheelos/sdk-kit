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
#include <cerrno>
#include <chrono>
#include <exception>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>

#include "vehicle_edge/auth_config.h"
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
  const bool check = argc == 4 && std::string(argv[1]) == "--check-config" &&
                     std::string(argv[2]) == "--gateway-url";
  const bool configure = argc == 4 && std::string(argv[1]) == "--configure" &&
                         std::string(argv[2]) == "--gateway-url";
  const bool enroll = argc == 3 && std::string(argv[1]) == "--gateway-url";
  const bool run =
      argc == 1 || (argc == 3 && std::string(argv[1]) == "--config");
  if (!check && !configure && !enroll && !run) {
    std::cerr
        << "Usage: vehicle_bootstrap [--config /etc/teleop/bootstrap.json]\n"
        << "       vehicle_bootstrap --configure|--check-config "
           "--gateway-url HTTPS_URL\n"
        << "       vehicle_bootstrap --gateway-url HTTPS_URL\n";
    return 78;
  }
  if (geteuid() != 0 && !(run && argc == 3)) {
    std::cerr << "Non-root bootstrap requires --config with protected "
                 "current-user-owned paths.\n";
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
    const int gateway_arg = (check || configure) ? 3 : 2;
    if ((check || configure || enroll) &&
        !vehicle_edge::AllowedURL(argv[gateway_arg], false))
      throw std::runtime_error("configuration endpoints require HTTPS");
    if (check) {
      Json::Value config(Json::objectValue);
      if (access("/etc/teleop", F_OK) == 0)
        config = storage.Read("/etc/teleop/bootstrap.json", true, 16384);
      else if (errno != ENOENT)
        throw std::runtime_error("cannot inspect bootstrap configuration");
      if (config.isNull()) config = Json::Value(Json::objectValue);
      config["gateway_url"] = argv[gateway_arg];
      (void)vehicle_edge::enrollment::ParseBootstrapConfig(config);
      return 0;
    }
    if (run && argc == 3) {
      const auto config = vehicle_edge::enrollment::ParseBootstrapConfig(
          storage.Read(argv[2]));
      storage.EnsureDirectory(config["state_directory"].asString());
      storage.EnsureDirectory(std::filesystem::path(
          config["device_config"].asString()).parent_path().string());
      storage.EnsureDirectory(std::filesystem::path(
          config["credentials_config"].asString()).parent_path().string());
    } else {
    storage.EnsureDirectory("/etc/teleop");
    storage.EnsureDirectory("/var/lib/teleop/bootstrap");
    }
    if (configure || enroll) {
      const int lock = storage.Lock("/var/lib/teleop/bootstrap");
      try {
        auto config = storage.Read("/etc/teleop/bootstrap.json", true, 16384);
        if (config.isNull()) config = Json::Value(Json::objectValue);
        config["gateway_url"] = argv[gateway_arg];
        (void)vehicle_edge::enrollment::ParseBootstrapConfig(config);
        storage.Write("/etc/teleop/bootstrap.json", config);
      } catch (...) {
        close(lock);
        throw;
      }
      close(lock);
      std::cout << "Bootstrap address saved; existing keys and runtime "
                   "settings are unchanged.\n";
      if (configure) return 0;
    }
    vehicle_edge::enrollment::Hooks hooks;
    hooks.notice = [](const std::string& message) {
      std::cout << message << std::endl;
    };
    vehicle_edge::enrollment::Bootstrap bootstrap(
        storage.Read(run && argc == 3 ? argv[2] : "/etc/teleop/bootstrap.json"),
        hooks, storage);
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
