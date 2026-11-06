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

#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <livekit/encoded_video_source.h>
#include <livekit/livekit.h>

#include "vehicle_edge/auth_client.h"
#include "vehicle_edge/encoded_video.h"
#include "vehicle_edge/media_backend.h"

namespace vehicle_edge {
namespace {

std::string OptionalStringField(const Json::Value &root, const char *key,
                                const std::string &fallback = "") {
  if (!root.isMember(key) || root[key].isNull())
    return fallback;
  if (!root[key].isString()) {
    throw std::invalid_argument(std::string("non-string config field: ") + key);
  }
  return root[key].asString();
}

bool ValidEndpointScheme(const std::string &url, const char *s1,
                         const char *s2) {
  if (url.find(' ') != std::string::npos)
    return false;
  const bool first = url.rfind(s1, 0) == 0 && url.size() > std::strlen(s1);
  const bool second = url.rfind(s2, 0) == 0 && url.size() > std::strlen(s2);
  return first || second;
}

std::string FetchMediaTokenFallback(const MediaWorkerConfig &config) {
  AuthenticatedClient client(config);
  const auto response = client.Get("/api/token/vehicle");
  if (response.status != 200)
    throw std::runtime_error("device request rejected (HTTP " +
                             std::to_string(response.status) + ")");
  const auto json = ParseHTTPJSON(response.body);
  if (!json["token"].isString() ||
      !ValidBearerToken(json["token"].asString()))
    throw std::runtime_error("invalid media token response");
  return json["token"].asString();
}

} // namespace

MediaWorkerConfig ParseMediaWorkerConfig(const Json::Value &root) {
  MediaWorkerConfig config;
  static_cast<AuthConfig &>(config) = ParseAuthConfig(root);
  config.livekit_url = OptionalStringField(root, "livekit_url");
  if (root.isMember("media_enabled")) {
    if (!root["media_enabled"].isBool()) {
      throw std::invalid_argument("media_enabled must be a boolean");
    }
    config.media_enabled = root["media_enabled"].asBool();
  }
  config.camera_source =
      OptionalStringField(root, "camera_source", "simulation");
  config.camera_layout = OptionalStringField(root, "camera_layout", "single");
  config.camera_track = OptionalStringField(root, "camera_track", "camera0");
  config.control_mode = OptionalStringField(root, "control_mode", "disabled");
  if (config.camera_source != "disabled" &&
      config.camera_source != "simulation" &&
      config.camera_source != "h264_annexb") {
    throw std::invalid_argument("invalid camera_source");
  }
  if (config.camera_layout != "single" && config.camera_layout != "three") {
    throw std::invalid_argument("invalid camera_layout");
  }
  if (!ValidIdentifier(config.camera_track)) {
    throw std::invalid_argument("invalid camera_track");
  }
  if (config.control_mode != "disabled" &&
      config.control_mode != "simulation" && config.control_mode != "cyber") {
    throw std::invalid_argument("invalid control_mode");
  }
  if (config.IsLocalSimDebug() && config.control_mode == "cyber") {
    throw std::invalid_argument("local_sim_debug forbids cyber control_mode");
  }
  if (config.media_enabled) {
    if (config.camera_source == "disabled" ||
        !ValidEndpointScheme(config.livekit_url, "ws://", "wss://")) {
      throw std::invalid_argument(
          "media requires livekit_url and active camera_source");
    }
    const auto endpoint =
        config.livekit_url.rfind("wss://", 0) == 0
            ? "https://" + config.livekit_url.substr(6)
            : (config.livekit_url.rfind("ws://", 0) == 0
                   ? "http://" + config.livekit_url.substr(5)
                   : "");
    if (config.IsLocalSimDebug() && !LoopbackURL(endpoint)) {
      throw std::invalid_argument(
          "local_sim_debug requires loopback livekit_url");
    }
  }
  return config;
}

MediaWorkerConfig LoadMediaWorkerConfig(const std::string &path) {
  std::ifstream input(path);
  if (!input) {
    throw std::runtime_error("cannot open config file: " + path);
  }
  Json::CharReaderBuilder builder;
  Json::Value root;
  std::string errors;
  if (!Json::parseFromStream(builder, input, &root, &errors)) {
    throw std::invalid_argument("invalid JSON config: " + errors);
  }
  return ParseMediaWorkerConfig(root);
}

} // namespace vehicle_edge

namespace {

std::string EncodeJSON(const Json::Value &value) {
  Json::StreamWriterBuilder builder;
  builder["indentation"] = "";
  builder["useSpecialFloats"] = false;
  return Json::writeString(builder, value);
}

std::optional<std::string> EncodeRTCState(const Json::Value &snapshot,
                                          const Json::Value &sources) {
  Json::Value packet;
  packet["type"] = "vehicle.state";
  packet["schema_version"] = 2;
  packet["telemetry"] = snapshot;
  packet["sources"] = sources;
  auto encoded = EncodeJSON(packet);
  if (encoded.size() > 12000) {
    packet["sources"] = Json::Value();
    packet["sources_omitted"] = true;
    encoded = EncodeJSON(packet);
  }
  if (encoded.size() > 12000)
    return std::nullopt;
  return encoded;
}

volatile sig_atomic_t stopping = 0;
void Stop(int) { stopping = 1; }

struct SDKLifetime {
  SDKLifetime() { livekit::initialize(livekit::LogLevel::Off); }
  ~SDKLifetime() { livekit::shutdown(); }
};

struct ControlDelegate : livekit::RoomDelegate {
  bool enabled = false;
  std::atomic<bool> failed{false};
  explicit ControlDelegate(const vehicle_edge::MediaWorkerConfig &config)
      : enabled(config.control_mode == "simulation" ||
                config.control_mode == "cyber") {}
  void
  onUserPacketReceived(livekit::Room &,
                       const livekit::UserDataPacketEvent &event) override {
    if (!enabled || event.topic != "vehicle.control.v2" ||
        (event.kind != livekit::DataPacketKind::Reliable &&
         event.kind != livekit::DataPacketKind::Lossy) ||
        !event.participant)
      return;
    if (event.data.size() > 2048)
      return;
    Json::Value packet;
    packet["sender"] = event.participant->identity();
    packet["body"] = std::string(event.data.begin(), event.data.end());
    packet["received_ns"] =
        Json::Int64(std::chrono::duration_cast<std::chrono::nanoseconds>(
                        std::chrono::steady_clock::now().time_since_epoch())
                        .count());
    const auto body = EncodeJSON(packet);
    if (body.size() > 4096 ||
        send(3, body.data(), body.size(), MSG_DONTWAIT | MSG_NOSIGNAL) !=
            static_cast<ssize_t>(body.size()))
      failed = true;
  }
};

struct Update {
  std::string vehicle_id;
  Json::Value snapshot;
  Json::Value sources;
  Json::Value control_feedback;
  vehicle_edge::SteadyTime deadline{};
  Json::UInt64 generation = 0;
  bool video_required = true;
  std::string media_token;
};

bool Authorized(const Update &update) {
  return !stopping && update.generation != 0 &&
         std::chrono::steady_clock::now() < update.deadline;
}

bool Receive(Update *update, bool wait, bool watch_video = false) {
  pollfd descriptors[2]{
      {3, POLLIN, 0},
      {4, static_cast<short>(watch_video ? POLLIN : 0), 0},
  };
  const nfds_t descriptor_count = watch_video ? 2 : 1;
  if (poll(descriptors, descriptor_count, wait ? 20 : 0) <= 0 ||
      !(descriptors[0].revents & (POLLIN | POLLHUP | POLLERR)))
    return false;
  char buffer[65537];
  const auto size = recv(3, buffer, sizeof(buffer), MSG_DONTWAIT);
  if (size == 0) {
    stopping = 1;
    return false;
  }
  if (size <= 0 || size > 65536)
    throw std::runtime_error("media supervisor disconnected");
  Json::CharReaderBuilder builder;
  builder["rejectDupKeys"] = true;
  builder["failIfExtra"] = true;
  std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
  Json::Value value;
  std::string errors;
  if (!reader->parse(buffer, buffer + size, &value, &errors) ||
      !value["generation"].isUInt64() || value["generation"].asUInt64() == 0 ||
      !value["deadline_ns"].isInt64() || !value["snapshot"].isObject() ||
      (value.isMember("video_required") && !value["video_required"].isBool()) ||
      (value.isMember("media_token") &&
       (!value["media_token"].isString() ||
        !vehicle_edge::ValidBearerToken(value["media_token"].asString()))))
    throw std::runtime_error("invalid supervisor message");
  if (value["snapshot"]["vehicle_id"] != update->vehicle_id)
    throw std::runtime_error("supervisor vehicle identity mismatch");
  const auto deadline = vehicle_edge::SteadyTime(
      std::chrono::nanoseconds(value["deadline_ns"].asInt64()));
  if (deadline > std::chrono::steady_clock::now() + std::chrono::seconds(5) ||
      (update->generation != 0 &&
       value["generation"].asUInt64() != update->generation))
    throw std::runtime_error("invalid supervisor authorization");
  update->deadline = deadline;
  update->generation = value["generation"].asUInt64();
  update->video_required =
      !value.isMember("video_required") || value["video_required"].asBool();
  if (value.isMember("media_token"))
    update->media_token = value["media_token"].asString();
  update->snapshot = value["snapshot"];
  update->sources = value["sources"];
  update->control_feedback = value["control_feedback"];
  return true;
}

void Drain(Update *update) {
  while (Receive(update, false, false)) {
  }
}

void SimulationFrame(livekit::VideoSource *source, std::uint64_t sequence,
                     int view) {
  constexpr int width = 640;
  constexpr int height = 480;
  auto frame = livekit::VideoFrame::create(width, height,
                                           livekit::VideoBufferType::RGBA);
  auto *pixels = frame.data();
  for (int y = 0; y < height; ++y) {
    for (int x = 0; x < width; ++x) {
      const auto offset = (y * width + x) * 4;
      const bool stripe = (x + static_cast<int>(sequence % width)) % 80 < 40;
      pixels[offset] = stripe ? 220 : 30;
      pixels[offset + 1] = static_cast<std::uint8_t>(y * 255 / height);
      pixels[offset + 2] = stripe ? 30 : 220;
      if (view >= 0) {
        // Left/center/right have red/green/blue dominant synthetic patterns.
        pixels[offset] = 20;
        pixels[offset + 1] = 20;
        pixels[offset + 2] = 20;
        pixels[offset + view] = stripe ? 220 : 80;
        pixels[offset + (view + 1) % 3] =
            static_cast<std::uint8_t>(y * 50 / height);
      }
      pixels[offset + 3] = 255;
    }
  }
  source->captureFrame(frame);
}

} // namespace

int vehicle_edge::RunMediaBackend(const MediaWorkerConfig &config) {
  const auto parent = getppid();
  if (parent <= 1 || prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 ||
      getppid() != parent)
    throw std::runtime_error("media supervisor unavailable");
  stopping = 0;
  signal(SIGTERM, Stop);
  signal(SIGINT, Stop);
  const bool encoded = config.camera_source == "h264_annexb";
  const bool three = config.camera_layout == "three";
  if (!config.media_enabled ||
      (!encoded && config.camera_source != "simulation") ||
      (config.camera_layout != "single" && !three))
    throw std::runtime_error("media is not explicitly enabled");
  Update update;
  update.vehicle_id = config.vehicle_id;
  while (!stopping && !Receive(&update, true, false)) {
  }
  if (!Authorized(update))
    return 0;
  std::string token = update.media_token;
  if (token.empty()) {
    token = FetchMediaTokenFallback(config);
  }
  Drain(&update);
  if (!Authorized(update))
    return 0;
  // SDK diagnostics are suppressed: upstream transport errors may contain URLs.
  SDKLifetime sdk;
  {
    ControlDelegate control(config);
    livekit::Room room;
    room.setDelegate(&control);
    livekit::RoomOptions options;
    options.auto_subscribe = false;
    options.join_retries = 0;
    if (!room.connect(config.livekit_url, token, options))
      throw std::runtime_error("RTC connection failed");
    Drain(&update);
    if (!Authorized(update)) {
      room.disconnect();
      return 0;
    }
    const auto participant = room.localParticipant().lock();
    if (!participant)
      throw std::runtime_error("RTC participant unavailable");
    const bool publish_video = update.video_required;
    std::vector<std::shared_ptr<livekit::EncodedVideoSource>> encoded_sources;
    std::vector<std::shared_ptr<livekit::VideoSource>> sources;
    std::vector<std::shared_ptr<livekit::LocalVideoTrack>> tracks;
    const std::vector<std::string> names =
        !publish_video
            ? std::vector<std::string>{}
            : (three ? std::vector<std::string>{"camera-left", "camera-center",
                                                "camera-right"}
                     : std::vector<std::string>{config.camera_track});
    for (const auto &name : names) {
      std::shared_ptr<livekit::VideoSource> source;
      if (encoded) {
        auto encoded_source = std::make_shared<livekit::EncodedVideoSource>(
            livekit::VideoCodec::H264, 640, 480);
        encoded_sources.push_back(encoded_source);
        source = std::move(encoded_source);
      } else {
        source = std::make_shared<livekit::VideoSource>(640, 480);
      }
      auto track = participant->publishVideoTrack(
          name, source, livekit::TrackSource::SOURCE_CAMERA);
      if (!track)
        throw std::runtime_error("RTC video publication failed");
      sources.push_back(std::move(source));
      tracks.push_back(std::move(track));
      Drain(&update);
      if (!Authorized(update)) {
        room.disconnect();
        return 0;
      }
    }
    if (send(3, "A", 1, MSG_NOSIGNAL | MSG_DONTWAIT) != 1)
      throw std::runtime_error("media supervisor unavailable");
    std::uint64_t sequence = 0;
    auto next_frame = vehicle_edge::SteadyTime{};
    auto next_state = vehicle_edge::SteadyTime{};
    auto next_control = vehicle_edge::SteadyTime{};
    std::array<bool, vehicle_edge::kMaxCameraStreams> waiting_keyframe{
        true, true, true};
    std::array<std::int64_t, vehicle_edge::kMaxCameraStreams> last_pts{0, 0, 0};
    std::array<std::int64_t, vehicle_edge::kMaxCameraStreams> base_pts{0, 0, 0};
    std::array<std::int64_t, vehicle_edge::kMaxCameraStreams> base_time{0, 0, 0};
    std::uint64_t last_sequence = 0;
    vehicle_edge::VideoFeedback feedback;
    feedback.keyframe_requested = publish_video && encoded;
    while (Authorized(update)) {
      if (room.connectionState() != livekit::ConnectionState::Connected)
        throw std::runtime_error("RTC disconnected");
      Drain(&update);
      if (!Authorized(update))
        break;
      const auto now = std::chrono::steady_clock::now();
      if (control.failed)
        throw std::runtime_error("control IPC unavailable");
      if (control.enabled && update.control_feedback.isObject()) {
        if (now >= next_control) {
          const auto body = EncodeJSON(update.control_feedback);
          participant->publishData(
              std::vector<std::uint8_t>(body.begin(), body.end()), true, {},
              "vehicle.control.feedback.v2");
          next_control = now + std::chrono::milliseconds(50);
        }
      }
      if (publish_video && encoded) {
        for (const auto &encoded_source : encoded_sources) {
          const auto requested = encoded_source->takeFeedback();
          feedback.keyframe_requested |= requested.keyframe_requested;
          if (requested.rate_control) {
            feedback.target_bitrate_bps =
                requested.rate_control->target_bitrate_bps;
            feedback.framerate_fps = requested.rate_control->framerate_fps;
          }
        }
        if (feedback.keyframe_requested || feedback.target_bitrate_bps) {
          if (vehicle_edge::SendVideoFeedback(4, feedback))
            feedback = {};
        }
        // Bound work per supervisor iteration, even if a producer floods IPC.
        for (int count = 0; count < 6 && Authorized(update); ++count) {
          auto frame = vehicle_edge::ReceiveEncodedFrame(4);
          if (!frame)
            break;
          if (frame->camera_index >= encoded_sources.size()) {
            feedback.keyframe_requested = true;
            continue;
          }
          const auto cam = frame->camera_index;
          if (frame->sequence != last_sequence + 1)
            waiting_keyframe.fill(true);
          last_sequence = frame->sequence;
          if (frame->timestamp_us <= last_pts[cam])
            throw std::runtime_error("nonmonotonic encoded timestamp");
          last_pts[cam] = frame->timestamp_us;
          if (waiting_keyframe[cam] && !frame->keyframe) {
            feedback.keyframe_requested = true;
            continue;
          }
          waiting_keyframe[cam] = false;
          if (!base_pts[cam]) {
            base_pts[cam] = frame->timestamp_us;
            base_time[cam] =
                std::chrono::duration_cast<std::chrono::microseconds>(
                    now.time_since_epoch())
                    .count();
          }
          const auto elapsed_us = frame->timestamp_us - base_pts[cam];
          const auto clock_us =
              std::chrono::duration_cast<std::chrono::microseconds>(
                  now.time_since_epoch())
                  .count();
          if (elapsed_us > clock_us - base_time[cam] + 250000 ||
              clock_us - base_time[cam] - elapsed_us > 250000)
            throw std::runtime_error("encoded PTS outside freshness window");
          livekit::EncodedVideoSource::Frame input_frame;
          input_frame.is_keyframe = frame->keyframe;
          input_frame.width = frame->width;
          input_frame.height = frame->height;
          input_frame.timestamp_us = base_time[cam] + elapsed_us;
          input_frame.data = std::move(frame->data);
          if (!encoded_sources[cam]->captureFrame(input_frame)) {
            waiting_keyframe[cam] = true;
            feedback.keyframe_requested = true;
          }
        }
      } else if (publish_video && now >= next_frame) {
        ++sequence;
        for (std::size_t view = 0; view < sources.size(); ++view) {
          Drain(&update);
          if (!Authorized(update))
            break;
          SimulationFrame(sources[view].get(), sequence,
                          three ? static_cast<int>(view) : -1);
        }
        next_frame = now + std::chrono::milliseconds(100);
      }
      if (!Authorized(update))
        break;
      if (now >= next_state) {
        const auto data = EncodeRTCState(update.snapshot, update.sources);
        if (data)
          participant->publishData(
              std::vector<std::uint8_t>(data->begin(), data->end()), true, {},
              "vehicle.state");
        next_state = now + std::chrono::milliseconds(200);
      }
      Receive(&update, true, publish_video && encoded);
    }
    for (const auto &track : tracks)
      participant->unpublishTrack(track->sid());
    tracks.clear();
    sources.clear();
    encoded_sources.clear();
    room.disconnect();
  }
  return 0;
}
