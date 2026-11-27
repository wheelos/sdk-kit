#include <iostream>
#include <memory>
#include <stdexcept>

#include "vehicle_edge/corridor_packet.h"

namespace {

void Require(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}

Json::Value Envelope() {
  Json::Value envelope(Json::objectValue);
  envelope["deadline_ns"] = Json::Int64(1100000000);
  auto &body = envelope["body"];
  body["type"] = "vehicle.corridor";
  body["schema_version"] = 1;
  body["vehicle_id"] = "car";
  body["stream_id"] = "session";
  body["camera_track"] = "camera-center";
  body["sequence"] = Json::UInt64(1);
  body["valid"] = true;
  body["ttl_ms"] = 200;
  return envelope;
}

void TestPackets() {
  vehicle_edge::CorridorPacket packet;
  auto envelope = Envelope();
  Require(vehicle_edge::ParseCorridorPacket(envelope, "car", "session",
                                            1000000000, &packet),
          "valid packet rejected");
  Require(packet.track == "camera-center" && packet.sequence == 1 &&
              !packet.payloads.empty() &&
              packet.payloads.front().size() <=
                  vehicle_edge::kMaxCorridorPacketBytes,
          "invalid wire packet");
  Require(!vehicle_edge::ParseCorridorPacket(envelope, "other", "session",
                                             1000000000, &packet),
          "vehicle mismatch accepted");
  Require(!vehicle_edge::ParseCorridorPacket(envelope, "car", "other",
                                             1000000000, &packet),
          "session mismatch accepted");
  Require(!vehicle_edge::ParseCorridorPacket(envelope, "car", "",
                                             1000000000, &packet),
          "invalid session accepted");
  Require(!vehicle_edge::ParseCorridorPacket(envelope, "car", "session",
                                             1100000000, &packet),
          "expired packet accepted");
  envelope["body"]["ttl_ms"] = 50;
  Require(!vehicle_edge::ParseCorridorPacket(envelope, "car", "session",
                                             1000000000, &packet),
          "deadline exceeds TTL");
  envelope = Envelope();
  envelope["body"]["geometry"] = std::string(5000, '"');
  Require(vehicle_edge::ParseCorridorPacket(envelope, "car", "session",
                                            1000000000, &packet),
          "bounded multi-part snapshot rejected");
  Require(packet.payloads.size() > 1, "large snapshot was not fragmented");
  std::string reconstructed;
  Json::CharReaderBuilder reader_builder;
  for (std::size_t i = 0; i < packet.payloads.size(); ++i) {
    Require(packet.payloads[i].size() <= vehicle_edge::kMaxCorridorPacketBytes,
            "fragment exceeds wire bound");
    Json::Value fragment;
    std::string errors;
    auto reader = std::unique_ptr<Json::CharReader>(reader_builder.newCharReader());
    const auto &bytes = packet.payloads[i];
    Require(reader->parse(bytes.data(), bytes.data() + bytes.size(), &fragment,
                          &errors),
            "invalid fragment JSON");
    Require(fragment["part"].asUInt() == i &&
                fragment["parts"].asUInt() == packet.payloads.size() &&
                fragment["sequence"].asUInt64() == 1 &&
                fragment["ttl_ms"].asUInt() == 100,
            "fragment routing or remaining TTL incorrect");
    reconstructed += fragment["data"].asString();
  }
  Json::StreamWriterBuilder writer;
  writer["indentation"] = "";
  writer["useSpecialFloats"] = false;
  Require(reconstructed == Json::writeString(writer, envelope["body"]),
          "fragment reassembly changed geometry");
  envelope = Envelope();
  envelope["body"]["geometry"] = std::string(16001, 'x');
  Require(!vehicle_edge::ParseCorridorPacket(envelope, "car", "session",
                                             1000000000, &packet),
          "oversized packet accepted");
  envelope = Envelope();
  envelope["body"]["sequence"] = Json::UInt64(0);
  Require(!vehicle_edge::ParseCorridorPacket(envelope, "car", "session",
                                             1000000000, &packet),
          "zero sequence accepted");
}

} // namespace

int main() {
  try {
    TestPackets();
    return 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
