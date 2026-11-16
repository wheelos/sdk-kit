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

}  // namespace

int main() {
  try {
    NullableMediaConfiguration();
    std::cout << "media configuration tests passed\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << "\n";
    return 1;
  }
}
