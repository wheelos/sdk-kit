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

#include <algorithm>
#include <array>
#include <memory>
#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "vehicle_edge/bootstrap.h"

namespace vehicle_edge {
namespace enrollment {
namespace {
using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
Key LoadKey(const std::string& raw) {
  if (raw.size() != 32) throw std::runtime_error("invalid private key");
  Key key(EVP_PKEY_new_raw_private_key(
              EVP_PKEY_ED25519, nullptr,
              reinterpret_cast<const unsigned char*>(raw.data()), raw.size()),
          EVP_PKEY_free);
  if (!key) throw std::runtime_error("cannot load private key");
  return key;
}
}  // namespace

std::string UUID() {
  std::array<unsigned char, 16> bytes{};
  if (RAND_bytes(bytes.data(), bytes.size()) != 1)
    throw std::runtime_error("random generator failed");
  bytes[6] = (bytes[6] & 15) | 64;
  bytes[8] = (bytes[8] & 63) | 128;
  const char* hex = "0123456789abcdef";
  std::string value;
  for (unsigned i = 0; i < bytes.size(); ++i) {
    if (i == 4 || i == 6 || i == 8 || i == 10) value += '-';
    value += hex[bytes[i] >> 4];
    value += hex[bytes[i] & 15];
  }
  return value;
}

std::string Base64URL(const std::string& raw) {
  std::string result(4 * ((raw.size() + 2) / 3), '\0');
  EVP_EncodeBlock(reinterpret_cast<unsigned char*>(&result[0]),
                  reinterpret_cast<const unsigned char*>(raw.data()),
                  raw.size());
  while (!result.empty() && result.back() == '=') result.pop_back();
  std::replace(result.begin(), result.end(), '+', '-');
  std::replace(result.begin(), result.end(), '/', '_');
  return result;
}

std::string DecodeBase64URL(const std::string& encoded, std::size_t bytes) {
  if (encoded.size() != (bytes * 8 + 5) / 6 || encoded.empty() ||
      !std::all_of(encoded.begin(), encoded.end(), [](unsigned char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') || c == '-' || c == '_';
      }))
    throw std::runtime_error("invalid key encoding");
  auto padded = encoded;
  std::replace(padded.begin(), padded.end(), '-', '+');
  std::replace(padded.begin(), padded.end(), '_', '/');
  while (padded.size() % 4) padded += '=';
  std::string raw(padded.size(), '\0');
  int length = EVP_DecodeBlock(
      reinterpret_cast<unsigned char*>(&raw[0]),
      reinterpret_cast<const unsigned char*>(padded.data()), padded.size());
  if (length < 0) throw std::runtime_error("invalid key encoding");
  length -= padded.size() - encoded.size();
  raw.resize(length);
  if (raw.size() != bytes || Base64URL(raw) != encoded)
    throw std::runtime_error("invalid key length");
  return raw;
}

std::string PublicKey(const std::string& private_key) {
  auto key = LoadKey(private_key);
  std::string raw(32, '\0');
  std::size_t size = raw.size();
  if (EVP_PKEY_get_raw_public_key(
          key.get(), reinterpret_cast<unsigned char*>(&raw[0]), &size) != 1 ||
      size != 32)
    throw std::runtime_error("cannot derive public key");
  return Base64URL(raw);
}

std::string Canonical(const std::string& action, const Json::Value& value) {
  if (action != "create" && action != "poll" && action != "complete")
    throw std::runtime_error("invalid enrollment action");
  std::string result = "teleop-enrollment-v1\n" + action;
  for (const auto* field : {"request_id", "public_key", "name", "serial",
                            "platform", "device_code", "ticket"}) {
    if (!value[field].isString())
      throw std::runtime_error("invalid enrollment field");
    const auto text = value[field].asString();
    if (std::any_of(text.begin(), text.end(),
                    [](unsigned char c) { return c < 32 || c == 127; }))
      throw std::runtime_error("invalid enrollment text");
    result += "\n" + text;
  }
  if (!value["timestamp"].isInt64() || !value["nonce"].isString())
    throw std::runtime_error("invalid enrollment time/nonce");
  return result + "\n" + std::to_string(value["timestamp"].asInt64()) + "\n" +
         value["nonce"].asString();
}

Json::Value Sign(const std::string& action, Json::Value envelope,
                 const std::string& private_key) {
  auto key = LoadKey(private_key);
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(
      EVP_MD_CTX_new(), EVP_MD_CTX_free);
  const auto text = Canonical(action, envelope);
  std::string signature(64, '\0');
  std::size_t size = signature.size();
  if (!context ||
      EVP_DigestSignInit(context.get(), nullptr, nullptr, nullptr, key.get()) !=
          1 ||
      EVP_DigestSign(context.get(),
                     reinterpret_cast<unsigned char*>(&signature[0]), &size,
                     reinterpret_cast<const unsigned char*>(text.data()),
                     text.size()) != 1 ||
      size != 64)
    throw std::runtime_error("cannot sign enrollment");
  envelope["signature"] = Base64URL(signature);
  return envelope;
}
}  // namespace enrollment
}  // namespace vehicle_edge
