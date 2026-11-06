#pragma once

#include <chrono>
#include <optional>
#include <string>

#include <json/json.h>

#include "vehicle_edge/auth_config.h"

namespace vehicle_edge {

using SteadyTime = std::chrono::steady_clock::time_point;

struct MediaWorkerConfig : AuthConfig {
  std::string livekit_url;
  bool media_enabled = false;
  std::string camera_source = "simulation";
  std::string camera_layout = "single";
  std::string camera_track = "camera0";
  std::string control_mode = "disabled";
};

MediaWorkerConfig ParseMediaWorkerConfig(const Json::Value &root);
MediaWorkerConfig LoadMediaWorkerConfig(const std::string &path);

// Runs in the dedicated worker with supervisor socket descriptor 3.
int RunMediaBackend(const MediaWorkerConfig &config);

} // namespace vehicle_edge

