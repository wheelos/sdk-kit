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

#include "vehicle_edge/encoded_video.h"

#include <sys/socket.h>

#include <array>
#include <cerrno>
#include <cmath>
#include <cstring>
#include <stdexcept>

#include "vehicle_edge/http_client.h"

namespace vehicle_edge {
namespace {

std::string EncodeJSON(const Json::Value &value) {
  Json::StreamWriterBuilder builder;
  builder["indentation"] = "";
  builder["useSpecialFloats"] = false;
  return Json::writeString(builder, value);
}

std::size_t StartCode(const std::vector<std::uint8_t> &data, std::size_t i) {
  if (i + 3 <= data.size() && data[i] == 0 && data[i + 1] == 0) {
    if (data[i + 2] == 1)
      return 3;
    if (i + 4 <= data.size() && data[i + 2] == 0 && data[i + 3] == 1)
      return 4;
  }
  return 0;
}

bool SendPacket(int fd, const void *data, std::size_t size) {
  const auto sent = send(fd, data, size, MSG_DONTWAIT | MSG_NOSIGNAL);
  if (sent == static_cast<ssize_t>(size))
    return true;
  if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
    return false;
  throw std::runtime_error("encoded video IPC send failed");
}

template <std::size_t N>
std::optional<std::vector<std::uint8_t>> ReceivePacket(int fd) {
  std::array<std::uint8_t, N> data{};
  const auto size =
      recv(fd, data.data(), data.size(), MSG_DONTWAIT | MSG_TRUNC);
  if (size < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
    return {};
  if (size <= 0 || static_cast<std::size_t>(size) > data.size())
    throw std::runtime_error("encoded video IPC closed or oversized");
  return std::vector<std::uint8_t>(data.begin(), data.begin() + size);
}

} // namespace

bool ValidEncodedFrame(const EncodedFrame &frame) {
  if (frame.camera_index >= kMaxCameraStreams || frame.data.empty() ||
      frame.data.size() > kMaxEncodedBytes || frame.width == 0 ||
      frame.width > 4096 || frame.height == 0 || frame.height > 4096 ||
      frame.timestamp_us <= 0 || !StartCode(frame.data, 0))
    return false;
  bool sps = false, pps = false, idr = false, slice = false;
  for (std::size_t i = 0; i < frame.data.size();) {
    const auto code = StartCode(frame.data, i);
    if (!code) {
      ++i;
      continue;
    }
    i += code;
    if (i >= frame.data.size() || (frame.data[i] & 0x80))
      return false;
    const auto type = frame.data[i] & 0x1f;
    if (type == 0 || type >= 24)
      return false;
    if (type == 5 && (!sps || !pps))
      return false;
    sps = sps || type == 7;
    pps = pps || type == 8;
    idr = idr || type == 5;
    slice = slice || type == 1 || type == 5;
    ++i;
  }
  return slice && frame.keyframe == idr && (!idr || (sps && pps));
}

void EncodedIngress::ResetStreamLocked(std::uint32_t camera_index) {
  auto &stream = streams_[camera_index];
  stream.pending.clear();
  stream.waiting_keyframe = true;
  feedback_.keyframe_requested = true;
}

void EncodedIngress::ResetLocked() {
  for (std::uint32_t i = 0; i < kMaxCameraStreams; ++i)
    ResetStreamLocked(i);
}

void EncodedIngress::Activate(bool active) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (active_ != active) {
    feedback_ = {};
    dropped_ = false;
    ResetLocked();
    for (auto &stream : streams_)
      stream.last_timestamp = 0;
    next_camera_ = 0;
    active_ = active;
    if (!active_)
      feedback_ = {};
  }
}

FrameResult EncodedIngress::Submit(EncodedFrame frame, SteadyTime now) {
  std::unique_lock<std::mutex> lock(mutex_, std::try_to_lock);
  if (!lock.owns_lock()) {
    dropped_ = true;
    return FrameResult::BUSY;
  }
  if (dropped_.exchange(false))
    ResetLocked();
  if (!active_)
    return FrameResult::INACTIVE;
  if (!ValidEncodedFrame(frame)) {
    ResetLocked();
    return FrameResult::INVALID;
  }
  auto &stream = streams_[frame.camera_index];
  if (frame.timestamp_us <= stream.last_timestamp) {
    ResetStreamLocked(frame.camera_index);
    return FrameResult::INVALID;
  }
  stream.last_timestamp = frame.timestamp_us;
  if (stream.pending.size() == 2 ||
      (!stream.pending.empty() &&
       now - stream.pending.front().received > kMaxEncodedAge))
    ResetStreamLocked(frame.camera_index);
  if (stream.waiting_keyframe && !frame.keyframe)
    return FrameResult::WAITING_KEYFRAME;
  stream.waiting_keyframe = false;
  stream.pending.push_back({std::move(frame), now});
  return FrameResult::ACCEPTED;
}

std::optional<EncodedFrame> EncodedIngress::Take(SteadyTime now) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (dropped_.exchange(false))
    ResetLocked();
  for (std::uint32_t i = 0; i < kMaxCameraStreams; ++i) {
    if (!streams_[i].pending.empty() &&
        now - streams_[i].pending.front().received > kMaxEncodedAge)
      ResetStreamLocked(i);
  }
  for (std::size_t attempt = 0; attempt < kMaxCameraStreams; ++attempt) {
    const std::size_t index = (next_camera_ + attempt) % kMaxCameraStreams;
    auto &stream = streams_[index];
    if (!stream.pending.empty()) {
      next_camera_ = (index + 1) % kMaxCameraStreams;
      auto frame = std::move(stream.pending.front().frame);
      stream.pending.pop_front();
      return frame;
    }
  }
  return {};
}

void EncodedIngress::Feedback(const VideoFeedback &feedback) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!active_)
    return;
  feedback_.keyframe_requested |= feedback.keyframe_requested;
  if (feedback.target_bitrate_bps) {
    feedback_.target_bitrate_bps = feedback.target_bitrate_bps;
    feedback_.framerate_fps = feedback.framerate_fps;
  }
}

VideoFeedback EncodedIngress::TakeFeedback() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!active_)
    return {};
  if (dropped_.exchange(false))
    ResetLocked();
  const auto result = feedback_;
  feedback_ = {};
  return result;
}

void EncodedIngress::Discontinuity() { dropped_ = true; }

bool SendEncodedFrame(int fd, const EncodedFrame &frame) {
  if (!ValidEncodedFrame(frame) || frame.sequence == 0)
    throw std::invalid_argument("invalid encoded frame");
  Json::Value header;
  header["version"] = 1;
  header["width"] = frame.width;
  header["height"] = frame.height;
  header["timestamp_us"] = Json::Int64(frame.timestamp_us);
  header["keyframe"] = frame.keyframe;
  header["sequence"] = Json::UInt64(frame.sequence);
  header["camera_index"] = frame.camera_index;
  header["sent_at_ns"] =
      Json::Int64(std::chrono::duration_cast<std::chrono::nanoseconds>(
                      std::chrono::steady_clock::now().time_since_epoch())
                      .count());
  const auto metadata = EncodeJSON(header);
  if (metadata.size() > 512)
    throw std::invalid_argument("encoded metadata too large");
  std::vector<std::uint8_t> packet;
  packet.reserve(2 + metadata.size() + frame.data.size());
  packet.push_back(static_cast<std::uint8_t>(metadata.size() >> 8));
  packet.push_back(static_cast<std::uint8_t>(metadata.size()));
  packet.insert(packet.end(), metadata.begin(), metadata.end());
  packet.insert(packet.end(), frame.data.begin(), frame.data.end());
  return SendPacket(fd, packet.data(), packet.size());
}

std::optional<EncodedFrame> ReceiveEncodedFrame(int fd) {
  const auto packet = ReceivePacket<kMaxEncodedBytes + 514>(fd);
  if (!packet)
    return {};
  if (packet->size() < 3)
    throw std::runtime_error("invalid encoded packet");
  const std::size_t length = ((*packet)[0] << 8) | (*packet)[1];
  if (length == 0 || length > 512 || length + 2 >= packet->size())
    throw std::runtime_error("invalid encoded metadata length");
  const auto header = ParseHTTPJSON(
      std::string(packet->begin() + 2, packet->begin() + 2 + length));
  if (header["version"] != 1 || !header["width"].isUInt() ||
      !header["height"].isUInt() || !header["timestamp_us"].isInt64() ||
      !header["keyframe"].isBool() || !header["sequence"].isUInt64() ||
      !header["sent_at_ns"].isInt64() || header["sequence"].asUInt64() == 0 ||
      (header.isMember("camera_index") && !header["camera_index"].isUInt()))
    throw std::runtime_error("invalid encoded metadata");
  const auto sent =
      SteadyTime(std::chrono::nanoseconds(header["sent_at_ns"].asInt64()));
  const auto now = std::chrono::steady_clock::now();
  if (sent > now || now - sent > kMaxEncodedAge)
    throw std::runtime_error("stale encoded frame IPC");
  EncodedFrame frame;
  frame.width = header["width"].asUInt();
  frame.height = header["height"].asUInt();
  frame.timestamp_us = header["timestamp_us"].asInt64();
  frame.keyframe = header["keyframe"].asBool();
  frame.sequence = header["sequence"].asUInt64();
  frame.camera_index =
      header.isMember("camera_index") ? header["camera_index"].asUInt() : 0u;
  frame.data.assign(packet->begin() + 2 + length, packet->end());
  if (!ValidEncodedFrame(frame))
    throw std::runtime_error("invalid H264 access unit");
  return frame;
}

bool SendVideoFeedback(int fd, const VideoFeedback &feedback) {
  Json::Value value;
  value["version"] = 1;
  value["keyframe_requested"] = feedback.keyframe_requested;
  value["target_bitrate_bps"] = Json::UInt64(feedback.target_bitrate_bps);
  value["framerate_fps"] = feedback.framerate_fps;
  const auto body = EncodeJSON(value);
  return SendPacket(fd, body.data(), body.size());
}

std::optional<VideoFeedback> ReceiveVideoFeedback(int fd) {
  const auto packet = ReceivePacket<512>(fd);
  if (!packet)
    return {};
  const auto value = ParseHTTPJSON(std::string(packet->begin(), packet->end()));
  if (value["version"] != 1 || !value["keyframe_requested"].isBool() ||
      !value["target_bitrate_bps"].isUInt64() ||
      !value["framerate_fps"].isNumeric())
    throw std::runtime_error("invalid video feedback");
  const double fps = value["framerate_fps"].asDouble();
  if (!std::isfinite(fps) || fps < 0 || fps > 240)
    throw std::runtime_error("invalid feedback frame rate");
  return VideoFeedback{value["keyframe_requested"].asBool(),
                       value["target_bitrate_bps"].asUInt64(), fps};
}

} // namespace vehicle_edge
