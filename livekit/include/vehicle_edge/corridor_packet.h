// Copyright 2026 WheelOS. All Rights Reserved.
// Licensed under the Apache License, Version 2.0.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <json/json.h>

namespace vehicle_edge {

constexpr std::size_t kMaxCorridorPacketBytes = 1200;
constexpr std::size_t kMaxCorridorSnapshotBytes = 16000;

struct CorridorPacket {
  std::string track;
  std::uint64_t sequence = 0;
  std::vector<std::string> payloads;
};

// Validates the local supervisor envelope and produces a bounded wire packet.
// deadline_ns is a same-host monotonic timestamp; it is not sent to browsers.
bool ParseCorridorPacket(const Json::Value &envelope,
                         const std::string &vehicle_id,
                         const std::string &stream_id, std::int64_t now_ns,
                         CorridorPacket *packet);

} // namespace vehicle_edge
