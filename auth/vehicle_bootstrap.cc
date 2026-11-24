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
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

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
Json::Value ReadOptional(const vehicle_edge::enrollment::Storage& storage,
                         const std::string& path) {
  auto parent = std::filesystem::path(path).parent_path();
  if (parent.empty()) parent = ".";
  if (access(parent.c_str(), F_OK) != 0) {
    if (errno == ENOENT) return Json::Value();
    throw std::runtime_error("cannot inspect bootstrap configuration parent");
  }
  return storage.Read(path, true, 16384);
}
void CheckPrivatePath(const std::string& path, bool directory = false) {
  struct stat info {};
  if (lstat(path.c_str(), &info)) {
    if (errno == ENOENT) return;
    throw std::runtime_error("cannot inspect private bootstrap path");
  }
  if (info.st_uid != 0 || info.st_gid != 0 ||
      (directory ? !S_ISDIR(info.st_mode) : !S_ISREG(info.st_mode)) ||
      (info.st_mode & 07777) != (directory ? 0700 : 0600) ||
      (!directory && info.st_nlink != 1))
    throw std::runtime_error("bootstrap secrets require private root ownership");
}
}  // namespace

int main(int argc, char** argv) {
  // Keep the original command forms while accepting this option in any position.
  std::string requested_runtime_user;
  std::vector<char*> arguments{argv[0]};
  for (int i = 1; i < argc; ++i) {
    if (std::string(argv[i]) == "--runtime-user") {
      if (!requested_runtime_user.empty() || i + 1 == argc ||
          argv[i + 1][0] == '\0' || argv[i + 1][0] == '-') {
        std::cerr << "Specify one non-empty runtime user.\n";
        return 78;
      }
      requested_runtime_user = argv[++i];
    } else {
      arguments.push_back(argv[i]);
    }
  }
  argc = static_cast<int>(arguments.size());
  argv = arguments.data();
  const bool check = argc == 4 && std::string(argv[1]) == "--check-config" &&
                     std::string(argv[2]) == "--gateway-url";
  const bool prepare_data =
      argc == 4 && std::string(argv[1]) == "--prepare-data-directory";
  const bool prepare_camera =
      argc == 4 && std::string(argv[1]) == "--prepare-camera-config";
  const bool prepare_gateway =
      (prepare_data || prepare_camera) &&
      std::string(argv[2]) == "--gateway-url";
  const bool prepare_config =
      (prepare_data || prepare_camera) &&
      std::string(argv[2]) == "--config";
  const bool prepare = prepare_gateway || prepare_config;
  const bool configure = argc == 4 && std::string(argv[1]) == "--configure" &&
                         std::string(argv[2]) == "--gateway-url";
  const bool enroll = argc == 3 && std::string(argv[1]) == "--gateway-url";
  const bool run =
      argc == 1 || (argc == 3 && std::string(argv[1]) == "--config");
  if (!check && !prepare && !configure && !enroll && !run) {
    std::cerr
        << "Usage: vehicle_bootstrap [--config /etc/teleop/bootstrap.json]\n"
        << "       vehicle_bootstrap --configure|--check-config "
           "--gateway-url HTTPS_URL\n"
        << "       vehicle_bootstrap --gateway-url HTTPS_URL\n"
        << "       vehicle_bootstrap --prepare-data-directory "
           "--gateway-url HTTPS_URL\n"
        << "       vehicle_bootstrap --prepare-data-directory "
           "--config /path/to/bootstrap.json\n"
        << "       vehicle_bootstrap --prepare-camera-config "
           "--gateway-url HTTPS_URL\n"
        << "       vehicle_bootstrap --prepare-camera-config "
           "--config /path/to/bootstrap.json\n"
        << "Root-managed enrollment accepts --runtime-user USER; it is saved "
           "in bootstrap.json, not device.json.\n";
    return 78;
  }
  if (geteuid() != 0 && !(run && argc == 3) && !prepare_config) {
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
    namespace enrollment = vehicle_edge::enrollment;
    const int gateway_arg = (check || prepare_gateway || configure) ? 3 : 2;
    const bool gateway_command = check || prepare_gateway || configure || enroll;
    if (gateway_command &&
        !vehicle_edge::AllowedURL(argv[gateway_arg], false))
      throw std::runtime_error("configuration endpoints require HTTPS");
    const std::string bootstrap_path = prepare_config ? argv[3]
        : run && argc == 3 ? argv[2] : "/etc/teleop/bootstrap.json";
    auto saved = ReadOptional(storage, bootstrap_path);
    if (saved.isNull()) saved = Json::Value(Json::objectValue);
    auto config = saved;
    if (gateway_command) config["gateway_url"] = argv[gateway_arg];
    if (!requested_runtime_user.empty()) {
      if (config.isMember("runtime_user") &&
          config["runtime_user"] != requested_runtime_user)
        throw std::runtime_error("runtime user change requires explicit offline migration");
      config["runtime_user"] = requested_runtime_user;
    } else if (!config.isMember("runtime_user") && geteuid() == 0 &&
               gateway_command) {
      const char* sudo_user = std::getenv("SUDO_USER");
      if (sudo_user && *sudo_user && std::string(sudo_user) != "root")
        config["runtime_user"] = sudo_user;
    }
    if (gateway_command && !config.isMember("runtime_user"))
      throw std::runtime_error("specify runtime user when no saved user or sudo caller exists");
    config = enrollment::ParseBootstrapConfig(config);
    std::optional<enrollment::RuntimeUser> runtime_user;
    if (config.isMember("runtime_user")) {
      if (geteuid() != 0)
        throw std::runtime_error("managed runtime enrollment requires root");
      runtime_user = enrollment::ResolveRuntimeUser(config["runtime_user"].asString());
      CheckPrivatePath(bootstrap_path);
      const auto state = config["state_directory"].asString();
      CheckPrivatePath(state, true);
      for (const auto* file : {"key.json", "enrollment.json", "lock"})
        CheckPrivatePath(state + "/" + file);
    }
    const auto device = config["device_config"].asString();
    const auto credentials = config["credentials_config"].asString();
    const auto runtime = enrollment::MergeRuntimeDefaults(
        ReadOptional(storage, device),
        std::filesystem::absolute(credentials).lexically_normal().string(),
        config);
    if (runtime_user)
      enrollment::ValidateRuntimeLayout(config, runtime, bootstrap_path);
    if (check) {
      std::cout << "Runtime account validated: " << runtime_user->name
                << " uid=" << runtime_user->uid << " gid=" << runtime_user->gid
                << "; registration remains root-owned.\n";
      return 0;
    }
    const auto runtime_parent = [&](const std::string& file) {
      const auto parent = std::filesystem::path(file).parent_path().string();
      if (runtime_user) storage.EnsureRuntimeDirectory(parent, *runtime_user);
      else storage.EnsureDirectory(parent);
    };
    runtime_parent(device);
    runtime_parent(credentials);
    if (runtime_user) runtime_parent(config["state_directory"].asString());
    if (prepare) {
      if (prepare_camera) {
        const bool created = enrollment::PrepareCameraCaptureConfiguration(
            runtime, storage, runtime_user ? &*runtime_user : nullptr);
        std::cout << (runtime["camera_capture_config"].isNull()
            ? "Camera configuration is explicitly unset; no file created.\n"
            : created
                ? "Created protected camera defaults; no cameras or services started.\n"
                : "Existing protected camera configuration preserved.\n");
      } else {
        const bool enabled = enrollment::PrepareRuntimeDataDirectory(
            runtime, config["state_directory"].asString(), storage,
            runtime_user ? &*runtime_user : nullptr);
        std::cout << (enabled
            ? "Runtime data directory prepared; no database or services started.\n"
            : "Data storage is explicitly disabled; no data directory prepared.\n");
      }
      return 0;
    }
    if (runtime_user && !configure) {
      enrollment::PrepareRuntimeDataDirectory(runtime,
          config["state_directory"].asString(), storage, &*runtime_user);
      enrollment::PrepareCameraCaptureConfiguration(runtime, storage, &*runtime_user);
      storage.ShareRuntimeFile(device, *runtime_user);
      storage.ShareRuntimeFile(credentials, *runtime_user);
    }
    storage.EnsureDirectory(config["state_directory"].asString());
    const auto bootstrap_parent = std::filesystem::path(bootstrap_path).parent_path();
    storage.EnsureDirectory(bootstrap_parent.string());
    if (configure || enroll ||
        (runtime_user && saved.get("runtime_user", Json::Value()) !=
                             config["runtime_user"])) {
      const int lock = storage.Lock(config["state_directory"].asString());
      try {
        // Refuse to overwrite configuration changed since validation.
        auto current = storage.Read(bootstrap_path, true, 16384);
        if (current.isNull()) current = Json::Value(Json::objectValue);
        if (current != saved)
          throw std::runtime_error("bootstrap configuration changed; retry enrollment");
        auto updated = saved;
        updated["gateway_url"] = config["gateway_url"];
        if (runtime_user) updated["runtime_user"] = runtime_user->name;
        if (updated != saved) storage.Write(bootstrap_path, updated);
      } catch (...) {
        close(lock);
        throw;
      }
      close(lock);
      std::cout << "Bootstrap address and runtime user saved; existing keys and runtime "
                   "settings are unchanged.\n";
      if (configure) return 0;
    }
    vehicle_edge::enrollment::Hooks hooks;
    hooks.notice = [](const std::string& message) {
      std::cout << message << std::endl;
    };
    vehicle_edge::enrollment::Bootstrap bootstrap(
        config, hooks, storage);
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
