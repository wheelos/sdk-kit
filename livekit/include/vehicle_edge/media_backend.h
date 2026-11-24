#pragma once

#include <chrono>
#include <optional>
#include <string>

#include <json/json.h>

#include "vehicle_edge/auth_config.h"

namespace vehicle_edge {

using SteadyTime = std::chrono::steady_clock::time_point;

// Publication settings for the encoded output of the local camera pipeline.
struct VideoPublishConfig {
  unsigned width = 1280;
  unsigned height = 720;
  unsigned fps = 30;
  unsigned bitrate_bps = 2000000;
};

struct MediaWorkerConfig : AuthConfig {
  std::string livekit_url;
  bool media_enabled = false;
  std::string camera_source = "disabled";
  std::string camera_layout = "single";
  std::string camera_track = "camera0";
  std::string camera_capture_config;
  std::optional<VideoPublishConfig> video_publish;
  std::string control_mode = "disabled";
};

VideoPublishConfig ParseCameraVideoPublishConfig(const Json::Value &root);
MediaWorkerConfig ParseMediaWorkerConfig(const Json::Value &root);
MediaWorkerConfig LoadMediaWorkerConfig(const std::string &path);

// Runs in the dedicated worker with supervisor socket descriptor 3.
int RunMediaBackend(const MediaWorkerConfig &config);

} // namespace vehicle_edge

