#include <sys/stat.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

#include "vehicle_edge/bootstrap.h"
#include "vehicle_edge/media_backend.h"

namespace {

void Require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

template <typename F>
void Reject(F operation) {
  bool rejected = false;
  try {
    operation();
  } catch (const std::exception&) {
    rejected = true;
  }
  Require(rejected, "invalid media configuration accepted");
}

void NullableMediaConfiguration() {
  Json::Value credentials(Json::objectValue);
  credentials["vehicle_id"] = "test-car";
  credentials["gateway_url"] = "https://gateway.example.com";
  credentials["token_url"] = "https://gateway.example.com/oauth/token";
  credentials["client_id"] = "test-client";
  credentials["client_secret"] = "synthetic-test-secret";
  auto runtime = vehicle_edge::enrollment::DefaultRuntimeConfiguration(
      "/etc/teleop/credentials.json");
  const auto parse = [&](const Json::Value& value) {
    return vehicle_edge::ParseMediaWorkerConfig(
        vehicle_edge::ResolveDeviceConfig(value, credentials));
  };
  const auto disabled = parse(runtime);
  Require(!disabled.media_enabled && disabled.livekit_url.empty() &&
              disabled.camera_source == "disabled" &&
              disabled.control_mode == "disabled",
          "unset media fields enabled a source");
  auto legacy = runtime;
  legacy.removeMember("livekit_url");
  legacy.removeMember("camera_source");
  Require(parse(legacy).camera_source == "disabled",
          "missing camera source selected simulation");

  for (const auto* name : {"livekit_url", "camera_source"}) {
    for (const auto& invalid : {Json::Value(""), Json::Value(false),
                                Json::Value(7), Json::Value(Json::arrayValue)}) {
      auto bad = runtime;
      bad[name] = invalid;
      Reject([&] { parse(bad); });
    }
  }
  for (const auto* name : {"camera_track", "camera_layout", "control_mode",
                           "media_enabled"}) {
    auto bad = runtime;
    bad[name] = Json::Value();
    Reject([&] { parse(bad); });
  }

  runtime["media_enabled"] = true;
  Reject([&] { parse(runtime); });
  runtime["livekit_url"] = "wss://rtc.example.com";
  Reject([&] { parse(runtime); });
  runtime.removeMember("camera_source");
  Reject([&] { parse(runtime); });
  runtime["camera_source"] = "simulation";
  Require(parse(runtime).camera_source == "simulation",
          "explicit simulation source rejected");
  runtime["camera_source"] = "h264_annexb";
  Require(parse(runtime).camera_source == "h264_annexb",
          "explicit encoded video source rejected");
  runtime["livekit_url"] = Json::Value();
  Reject([&] { parse(runtime); });
}

void CameraPublicationSettings() {
  auto camera = vehicle_edge::enrollment::DefaultCameraCaptureConfiguration();
  const auto defaults = vehicle_edge::ParseCameraVideoPublishConfig(camera);
  Require(defaults.width == 1280 && defaults.height == 720 &&
              defaults.fps == 30 && defaults.bitrate_bps == 2000000,
          "camera output did not determine publication settings");
  camera["output_width"] = 640;
  camera["output_height"] = 480;
  camera["fps"] = 15;
  camera["bitrate_bps"] = 750000;
  const auto custom = vehicle_edge::ParseCameraVideoPublishConfig(camera);
  Require(custom.width == 640 && custom.height == 480 && custom.fps == 15 &&
              custom.bitrate_bps == 750000,
          "custom camera publication settings ignored");
  const auto omitted = vehicle_edge::ParseCameraVideoPublishConfig(
      Json::Value(Json::objectValue));
  Require(omitted.width == defaults.width && omitted.height == defaults.height &&
              omitted.fps == defaults.fps &&
              omitted.bitrate_bps == defaults.bitrate_bps,
          "omitted fields differ from capture defaults");
  for (const auto* name : {"width", "height", "output_width", "output_height",
                           "fps", "bitrate_bps"}) {
    for (const auto& invalid : {Json::Value(), Json::Value(true),
                               Json::Value("30"), Json::Value(-1),
                               Json::Value(0), Json::Value(10000001)}) {
      auto bad = camera;
      bad[name] = invalid;
      Reject([&] { vehicle_edge::ParseCameraVideoPublishConfig(bad); });
    }
  }
  for (const auto* name : {"width", "height", "output_width", "output_height"}) {
    auto bad = camera;
    bad[name] = 641;
    Reject([&] { vehicle_edge::ParseCameraVideoPublishConfig(bad); });
  }
  camera["output_width"] = 2048;
  Reject([&] { vehicle_edge::ParseCameraVideoPublishConfig(camera); });
  Reject([&] {
    vehicle_edge::ParseCameraVideoPublishConfig(Json::Value(Json::arrayValue));
  });
}

void LoadCameraPublicationSettings() {
  struct Directory {
    std::filesystem::path path = std::filesystem::current_path() /
        ("media-config-" + vehicle_edge::enrollment::UUID());
    Directory() {
      std::filesystem::create_directory(path);
      Require(chmod(path.c_str(), 0700) == 0, "test directory permissions");
    }
    ~Directory() {
      std::error_code ignored;
      std::filesystem::remove_all(path, ignored);
    }
    void Write(const char* name, const Json::Value& value) const {
      const auto file = path / name;
      {
        std::ofstream out(file);
        out << value;
        Require(out.good(), "write test config");
      }
      Require(chmod(file.c_str(), 0600) == 0, "test config permissions");
    }
  } directory;
  Json::Value credentials(Json::objectValue);
  credentials["vehicle_id"] = "test-car";
  credentials["gateway_url"] = "https://gateway.example.com";
  credentials["token_url"] = "https://gateway.example.com/oauth/token";
  credentials["client_id"] = "test-client";
  credentials["client_secret"] = "synthetic-test-secret";
  directory.Write("credentials.json", credentials);
  auto runtime = vehicle_edge::enrollment::DefaultRuntimeConfiguration(
      (directory.path / "credentials.json").string());
  runtime["camera_capture_config"] = (directory.path / "cameras.json").string();
  runtime["media_enabled"] = true;
  runtime["camera_source"] = "h264_annexb";
  runtime["livekit_url"] = "wss://rtc.example.com";
  const auto load = [&] {
    directory.Write("device.json", runtime);
    return vehicle_edge::LoadMediaWorkerConfig(
        (directory.path / "device.json").string());
  };
  Reject(load);  // A configured, missing camera file must not fall back to VGA.
  auto camera = vehicle_edge::enrollment::DefaultCameraCaptureConfiguration();
  camera["output_width"] = 960;
  camera["output_height"] = 540;
  camera["bitrate_bps"] = 1200000;
  camera["fps"] = 24;
  directory.Write("cameras.json", camera);
  const auto loaded = load();
  Require(loaded.video_publish && loaded.video_publish->width == 960 &&
              loaded.video_publish->height == 540 &&
              loaded.video_publish->bitrate_bps == 1200000 &&
              loaded.video_publish->fps == 24,
          "worker did not load its configured camera file");
  camera["fps"] = 0;
  directory.Write("cameras.json", camera);
  Reject(load);
  runtime["media_enabled"] = false;
  Require(!load().video_publish, "disabled media loaded camera settings");
  runtime["media_enabled"] = true;
  runtime["camera_source"] = "simulation";
  Require(!load().video_publish, "simulation loaded camera settings");
  runtime["camera_source"] = "h264_annexb";
  runtime["camera_capture_config"] = Json::Value();
  Require(!load().video_publish, "null capture path enabled camera publication");
  runtime.removeMember("camera_capture_config");
  Require(!load().video_publish, "missing capture path broke encoded integration");
  for (const auto& invalid : {Json::Value("relative.json"), Json::Value(""),
                             Json::Value("/tmp/camera\n.json"), Json::Value(7)}) {
    runtime["camera_capture_config"] = invalid;
    Reject(load);
  }
}

}  // namespace

int main() {
  try {
    NullableMediaConfiguration();
    CameraPublicationSettings();
    LoadCameraPublicationSettings();
    std::cout << "media configuration tests passed\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << "\n";
    return 1;
  }
}
