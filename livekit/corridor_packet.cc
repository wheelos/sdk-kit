// Copyright 2026 WheelOS. All Rights Reserved.
// Licensed under the Apache License, Version 2.0.
#include "vehicle_edge/corridor_packet.h"

#include <limits>

#include "vehicle_edge/auth_config.h"

namespace vehicle_edge {

bool ParseCorridorPacket(const Json::Value &envelope,
                         const std::string &vehicle_id,
                         const std::string &stream_id, std::int64_t now_ns,
                         CorridorPacket *packet) {
  constexpr std::int64_t kMaxAgeNs = 500000000;
  constexpr std::uint64_t kMaxSafeInteger = 9007199254740991ULL;
  if (!packet || !ValidIdentifier(vehicle_id) || !ValidIdentifier(stream_id) ||
      now_ns < 0 ||
      now_ns > std::numeric_limits<std::int64_t>::max() - kMaxAgeNs ||
      !envelope.isObject() || !envelope["deadline_ns"].isInt64() ||
      envelope["deadline_ns"].asInt64() <= now_ns ||
      envelope["deadline_ns"].asInt64() > now_ns + kMaxAgeNs ||
      !envelope["body"].isObject()) {
    return false;
  }
  const auto &body = envelope["body"];
  if (body["type"] != "vehicle.corridor" || body["schema_version"] != 1 ||
      body["vehicle_id"] != vehicle_id || body["stream_id"] != stream_id ||
      !body["camera_track"].isString() ||
      !ValidIdentifier(body["camera_track"].asString()) ||
      !body["sequence"].isUInt64() || body["sequence"].asUInt64() == 0 ||
      body["sequence"].asUInt64() > kMaxSafeInteger ||
      !body["valid"].isBool() || !body["ttl_ms"].isUInt() ||
      body["ttl_ms"].asUInt() == 0 || body["ttl_ms"].asUInt() > 500 ||
      envelope["deadline_ns"].asInt64() >
          now_ns + static_cast<std::int64_t>(body["ttl_ms"].asUInt()) *
                       1000000) {
    return false;
  }
  const auto remaining_ms =
      (envelope["deadline_ns"].asInt64() - now_ns) / 1000000;
  if (remaining_ms <= 0) return false;
  Json::StreamWriterBuilder builder;
  builder["indentation"] = "";
  builder["useSpecialFloats"] = false;
  const auto snapshot = Json::writeString(builder, body);
  if (snapshot.size() > kMaxCorridorSnapshotBytes) return false;
  for (const unsigned char ch : snapshot)
    if (ch >= 128) return false;
  // ASCII chunks avoid splitting a UTF-8 code point. 300 raw bytes leave room
  // for JSON escaping and the per-fragment routing metadata.
  constexpr std::size_t kChunkBytes = 300;
  const std::size_t count = (snapshot.size() + kChunkBytes - 1) / kChunkBytes;
  std::vector<std::string> payloads;
  payloads.reserve(count);
  for (std::size_t index = 0; index < count; ++index) {
    Json::Value fragment(Json::objectValue);
    fragment["type"] = "vehicle.corridor.fragment";
    fragment["schema_version"] = 1;
    fragment["vehicle_id"] = vehicle_id;
    fragment["stream_id"] = stream_id;
    fragment["camera_track"] = body["camera_track"];
    fragment["sequence"] = body["sequence"];
    fragment["ttl_ms"] = static_cast<Json::UInt>(remaining_ms);
    fragment["part"] = static_cast<Json::UInt>(index);
    fragment["parts"] = static_cast<Json::UInt>(count);
    fragment["data"] = snapshot.substr(index * kChunkBytes, kChunkBytes);
    auto encoded = Json::writeString(builder, fragment);
    if (encoded.size() > kMaxCorridorPacketBytes) return false;
    payloads.push_back(std::move(encoded));
  }
  packet->track = body["camera_track"].asString();
  packet->sequence = body["sequence"].asUInt64();
  packet->payloads = std::move(payloads);
  return true;
}

} // namespace vehicle_edge
