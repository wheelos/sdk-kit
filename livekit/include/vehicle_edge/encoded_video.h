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

#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <vector>

namespace vehicle_edge {

using SteadyTime = std::chrono::steady_clock::time_point;

constexpr std::size_t kMaxEncodedBytes = 512 * 1024;
constexpr auto kMaxEncodedAge = std::chrono::milliseconds(250);
constexpr std::uint32_t kMaxCameraStreams = 3;

struct EncodedFrame {
  std::vector<std::uint8_t> data;
  std::uint32_t width = 0;
  std::uint32_t height = 0;
  std::int64_t timestamp_us = 0;
  // Unix microseconds at appsink read; zero means unavailable.
  std::int64_t capture_time_us = 0;
  // Capture PTS mapped to Linux CLOCK_MONOTONIC. Zero when unavailable.
  std::int64_t capture_monotonic_us = 0;
  bool keyframe = false;
  bool discontinuity = false;
  std::uint64_t sequence = 0;
  std::uint32_t camera_index = 0;
};

struct VideoFeedback {
  bool keyframe_requested = false;
  std::uint64_t target_bitrate_bps = 0;
  double framerate_fps = 0;
  // Bitmask of camera indices (bit i => camera i). Zero with keyframe_requested
  // preserves legacy broadcast behavior (request keyframe on all cameras).
  std::uint32_t camera_mask = 0;
};

enum class FrameResult { ACCEPTED, INACTIVE, BUSY, INVALID, WAITING_KEYFRAME };

// Annex B AU contract: no B frames; every IDR includes SPS/PPS.
bool ValidEncodedFrame(const EncodedFrame &frame);

class EncodedIngress {
public:
  void Activate(bool active);
  FrameResult Submit(EncodedFrame frame, SteadyTime now);
  std::optional<EncodedFrame> Take(SteadyTime now);
  void Feedback(const VideoFeedback &feedback);
  VideoFeedback TakeFeedback();
  void Discontinuity();
  void Discontinuity(std::uint32_t camera_index);

private:
  struct Pending {
    EncodedFrame frame;
    SteadyTime received;
  };
  struct StreamState {
    bool waiting_keyframe = true;
    bool discontinuity = true;
    std::int64_t last_timestamp = 0;
    std::deque<Pending> pending;
  };
  void ResetLocked();
  void ResetStreamLocked(std::uint32_t camera_index);
  void ApplyDropsLocked();
  std::mutex mutex_;
  std::atomic<bool> dropped_{false};
  std::array<std::atomic<bool>, kMaxCameraStreams> dropped_streams_{};
  bool active_ = false;
  std::size_t next_camera_ = 0;
  std::array<StreamState, kMaxCameraStreams> streams_{};
  VideoFeedback feedback_;
};

// Dedicated inherited SOCK_SEQPACKET channel, never a public network endpoint.
bool SendEncodedFrame(int fd, const EncodedFrame &frame);
std::optional<EncodedFrame> ReceiveEncodedFrame(int fd);
bool SendVideoFeedback(int fd, const VideoFeedback &feedback);
std::optional<VideoFeedback> ReceiveVideoFeedback(int fd);

} // namespace vehicle_edge
