#include <sys/socket.h>
#include <unistd.h>

#include <iostream>
#include <stdexcept>
#include <thread>

#include "vehicle_edge/encoded_video.h"

namespace {

using namespace vehicle_edge;
using namespace std::chrono_literals;

void Require(bool value, const char *message) {
  if (!value)
    throw std::runtime_error(message);
}

EncodedFrame Frame(std::int64_t pts, bool key = true) {
  EncodedFrame frame;
  // Structural Annex B fixture, not a decodable camera image.
  frame.data =
      key ? std::vector<std::uint8_t>{0, 0,    0,    1, 0x67, 0x42, 0,    0,
                                      1, 0x68, 0x01, 0, 0,    1,    0x65, 0x01}
          : std::vector<std::uint8_t>{0, 0, 1, 0x41, 0x01};
  frame.width = 640;
  frame.height = 480;
  frame.timestamp_us = pts;
  frame.keyframe = key;
  frame.sequence = static_cast<std::uint64_t>(pts);
  return frame;
}

void Queue() {
  EncodedIngress queue;
  const auto now = std::chrono::steady_clock::now();
  Require(queue.Submit(Frame(1), now) == FrameResult::INACTIVE,
          "inactive input accepted");
  queue.Activate(true);
  Require(queue.TakeFeedback().keyframe_requested,
          "new session did not request IDR");
  Require(queue.Submit(Frame(1, false), now) == FrameResult::WAITING_KEYFRAME,
          "session began with undecodable delta");
  Require(queue.Submit(Frame(2), now) == FrameResult::ACCEPTED, "IDR rejected");
  Require(queue.Submit(Frame(3, false), now) == FrameResult::ACCEPTED,
          "delta rejected");
  Require(queue.Submit(Frame(4, false), now) == FrameResult::WAITING_KEYFRAME,
          "overflow did not reset reference chain");
  Require(!queue.Take(now), "overflow retained obsolete frame");
  Require(queue.TakeFeedback().keyframe_requested,
          "overflow did not request IDR");
  Require(queue.Submit(Frame(5), now) == FrameResult::ACCEPTED,
          "fresh IDR failed to recover");
  Require(!queue.Take(now + 251ms), "stale AU survived");
  Require(queue.Submit(Frame(6, false), now + 251ms) ==
              FrameResult::WAITING_KEYFRAME,
          "stale drop did not invalidate chain");
  Require(queue.Submit(Frame(7), now + 251ms) == FrameResult::ACCEPTED,
          "stale recovery failed");
  Require(queue.Submit(Frame(7, false), now + 251ms) == FrameResult::INVALID,
          "duplicate PTS accepted");
  queue.Activate(false);
  queue.Activate(true);
  Require(queue.Submit(Frame(1), now) == FrameResult::ACCEPTED,
          "new generation retained previous PTS");
  auto frame = queue.Take(now);
  Require(frame && frame->timestamp_us == 1, "wrong generation frame");
  queue.Feedback({true, 500000, 15});
  queue.Activate(false);
  auto feedback = queue.TakeFeedback();
  Require(!feedback.keyframe_requested && feedback.target_bitrate_bps == 0,
          "ended session retained encoder feedback");
  queue.Feedback({true, 900000, 30});
  queue.Activate(true);
  feedback = queue.TakeFeedback();
  Require(feedback.keyframe_requested && feedback.target_bitrate_bps == 0,
          "new session inherited previous bitrate");
  queue.Discontinuity();
  Require(
      queue.TakeFeedback().keyframe_requested,
      "upstream discontinuity did not request keyframe until another frame");

  // Multi-camera independent GOP state (camera_index 0..2).
  queue.Activate(true);
  auto cam0 = Frame(10, true);
  cam0.camera_index = 0;
  auto cam2_delta = Frame(10, false);
  cam2_delta.camera_index = 2;
  auto cam2_idr = Frame(11, true);
  cam2_idr.camera_index = 2;
  Require(queue.Submit(cam0, now) == FrameResult::ACCEPTED,
          "camera0 IDR rejected");
  Require(queue.Submit(cam2_delta, now) == FrameResult::WAITING_KEYFRAME,
          "camera2 delta accepted without camera2 IDR");
  Require(queue.Submit(cam2_idr, now) == FrameResult::ACCEPTED,
          "camera2 IDR rejected");
  while (queue.Take(now)) {}

  // Single-camera discontinuity resets only that camera, preserving healthy siblings,
  // and marks the recovery IDR frame with discontinuity=true for the worker.
  queue.Discontinuity(2);
  auto cam0_delta = Frame(12, false);
  cam0_delta.camera_index = 0;
  auto cam2_after_discont = Frame(12, false);
  cam2_after_discont.camera_index = 2;
  auto cam2_recovery_idr = Frame(13, true);
  cam2_recovery_idr.camera_index = 2;
  auto cam2_next_delta = Frame(14, false);
  cam2_next_delta.camera_index = 2;
  Require(queue.Submit(cam0_delta, now) == FrameResult::ACCEPTED,
          "single-camera discontinuity broke sibling camera0");
  Require(queue.Submit(cam2_after_discont, now) ==
              FrameResult::WAITING_KEYFRAME,
          "single-camera discontinuity did not reset target camera2");
  Require(queue.Submit(cam2_recovery_idr, now) == FrameResult::ACCEPTED,
          "camera2 recovery IDR rejected");
  Require(queue.Submit(cam2_next_delta, now) == FrameResult::ACCEPTED,
          "camera2 post-recovery delta rejected");
  bool saw_cam2_discontinuity_idr = false;
  while (auto out = queue.Take(now)) {
    if (out->camera_index == 0 && out->discontinuity)
      throw std::runtime_error("sibling camera0 received spurious discontinuity");
    if (out->camera_index == 2 && out->timestamp_us == 13)
      saw_cam2_discontinuity_idr = out->discontinuity;
    if (out->camera_index == 2 && out->timestamp_us == 14 && out->discontinuity)
      throw std::runtime_error("post-recovery delta retained discontinuity");
  }
  Require(saw_cam2_discontinuity_idr,
          "recovery IDR did not carry discontinuity flag to worker");
  Require(queue.TakeFeedback().keyframe_requested,
          "single-camera discontinuity did not request keyframe");
}

void Validation() {
  auto frame = Frame(1);
  Require(ValidEncodedFrame(frame), "Annex B fixture invalid");
  frame.keyframe = false;
  Require(!ValidEncodedFrame(frame), "IDR flag mismatch accepted");
  frame = Frame(1);
  frame.data = {0, 0, 1, 0x65, 0x01};
  Require(!ValidEncodedFrame(frame), "IDR without SPS/PPS accepted");
  frame.data = {0, 0, 1, 0x65, 0x01, 0, 0, 1, 0x67, 0x42, 0, 0, 1, 0x68, 0x01};
  Require(!ValidEncodedFrame(frame), "SPS/PPS after IDR accepted");
  frame.data = {0x80, 0x60, 0, 1};
  Require(!ValidEncodedFrame(frame), "RTP accepted as AU");
  frame = Frame(1);
  frame.data.resize(kMaxEncodedBytes + 1);
  Require(!ValidEncodedFrame(frame), "oversized AU accepted");
  frame = Frame(1);
  frame.capture_time_us = -1;
  Require(!ValidEncodedFrame(frame), "negative capture time accepted");
  frame = Frame(1);
  frame.data.push_back(0);
  frame.data.push_back(0);
  frame.data.push_back(1);
  Require(!ValidEncodedFrame(frame), "truncated NAL accepted");
}

void IPC() {
  int sockets[2];
  Require(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets) == 0,
          "socketpair failed");
  try {
    Require(!ReceiveEncodedFrame(sockets[1]), "empty channel produced frame");
    auto frame = Frame(1);
    frame.camera_index = 2;
    frame.capture_time_us = 1700000000123456;
    frame.discontinuity = true;
    Require(SendEncodedFrame(sockets[0], frame), "frame send failed");
    const auto received = ReceiveEncodedFrame(sockets[1]);
    Require(received && received->data == frame.data &&
                received->timestamp_us == 1 && received->keyframe &&
                received->discontinuity &&
                received->width == 640 && received->sequence == 1 &&
                received->camera_index == 2 &&
                received->capture_time_us == frame.capture_time_us,
            "IPC metadata or payload corrupted");
    frame.capture_time_us = 0;
    frame.discontinuity = false;
    Require(SendEncodedFrame(sockets[0], frame), "legacy frame send failed");
    const auto legacy = ReceiveEncodedFrame(sockets[1]);
    Require(legacy && legacy->capture_time_us == 0 && !legacy->discontinuity,
            "frame without capture time was not preserved");
    Require(SendVideoFeedback(sockets[1], {true, 500000, 15}),
            "feedback send failed");
    const auto feedback = ReceiveVideoFeedback(sockets[0]);
    Require(feedback && feedback->keyframe_requested &&
                feedback->target_bitrate_bps == 500000 &&
                feedback->framerate_fps == 15,
            "feedback not returned");
    const char malformed[] = "invalid";
    Require(send(sockets[1], malformed, sizeof(malformed), MSG_NOSIGNAL) > 0,
            "malformed fixture not sent");
    bool rejected = false;
    try {
      ReceiveVideoFeedback(sockets[0]);
    } catch (const std::runtime_error &) {
      rejected = true;
    }
    Require(rejected, "malformed feedback accepted");
    Require(SendEncodedFrame(sockets[0], frame), "stale fixture not sent");
    std::this_thread::sleep_for(260ms);
    rejected = false;
    try {
      ReceiveEncodedFrame(sockets[1]);
    } catch (const std::runtime_error &) {
      rejected = true;
    }
    Require(rejected, "stale IPC frame accepted");
    int buffer = 8192;
    setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &buffer, sizeof(buffer));
    bool blocked = false;
    for (int i = 0; i < 1000 && !blocked; ++i)
      blocked = !SendEncodedFrame(sockets[0], frame);
    Require(blocked, "nonblocking channel did not bound backpressure");
  } catch (...) {
    close(sockets[0]);
    close(sockets[1]);
    throw;
  }
  close(sockets[0]);
  close(sockets[1]);
}

} // namespace

int main() {
  try {
    Queue();
    Validation();
    IPC();
    return 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
