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

#include "vehicle_edge/auth_config.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_set>

#include <curl/curl.h>

namespace vehicle_edge {
namespace {

struct FDCloser {
  void operator()(int *fd) const {
    close(*fd);
    delete fd;
  }
};

std::string RequiredString(const Json::Value &value, const char *field) {
  if (!value[field].isString() || value[field].asString().empty()) {
    throw std::invalid_argument(
        std::string("missing or invalid config field: ") + field);
  }
  return value[field].asString();
}

const std::unordered_set<std::string> &KnownConfigFields() {
  static const std::unordered_set<std::string> fields = {
      "vehicle_id",
      "gateway_url",
      "token_url",
      "client_id",
      "client_secret",
      "chassis_channel",
      "localization_channel",
      "node_name",
      "upload_interval_ms",
      "media_enabled",
      "livekit_url",
      "media_worker_path",
      "camera_source",
      "control_mode",
      "control_channel",
      "camera_track",
      "camera_layout",
      "mission_runtime_channel",
      "mission_result_channel",
      "system_status_channel",
      "data_store_path",
      "task_mode",
      "map_id",
      "vehicle_model",
      "software_version",
      "mission_request_channel",
      "allow_insecure_localhost"};
  return fields;
}

}  // namespace

bool ValidIdentifier(const std::string &value) {
  if (value.empty() || value.size() > 64)
    return false;
  const auto alphanumeric = [](char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9');
  };
  if (!alphanumeric(value.front()))
    return false;
  for (const char c : value) {
    if (!alphanumeric(c) && c != '_' && c != '.' && c != '-')
      return false;
  }
  return true;
}

bool AllowedURL(const std::string &url, bool allow_insecure_localhost) {
  std::unique_ptr<CURLU, decltype(&curl_url_cleanup)> parsed(curl_url(),
                                                             curl_url_cleanup);
  if (!parsed ||
      curl_url_set(parsed.get(), CURLUPART_URL, url.c_str(), 0) != CURLUE_OK) {
    return false;
  }
  const auto part = [&parsed](CURLUPart key) {
    char *value = nullptr;
    const auto status = curl_url_get(parsed.get(), key, &value, 0);
    std::unique_ptr<char, decltype(&curl_free)> holder(value, curl_free);
    return status == CURLUE_OK ? std::string(value) : std::string();
  };
  const auto scheme = part(CURLUPART_SCHEME);
  const auto host = part(CURLUPART_HOST);
  if (!part(CURLUPART_USER).empty() || !part(CURLUPART_PASSWORD).empty() ||
      !part(CURLUPART_QUERY).empty() || !part(CURLUPART_FRAGMENT).empty() ||
      host.empty())
    return false;
  if (scheme == "https")
    return true;
  return allow_insecure_localhost && scheme == "http" &&
         (host == "localhost" || host == "127.0.0.1" || host == "[::1]");
}

Json::Value LoadProtectedJSON(const std::string &path) {
  const int raw =
      open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (raw < 0)
    throw std::runtime_error("cannot open protected device config");
  std::unique_ptr<int, FDCloser> fd(new int(raw));
  struct stat info {};
  if (fstat(raw, &info) != 0 || !S_ISREG(info.st_mode) || info.st_uid != 0 ||
      (info.st_mode & 0777) != 0600 || info.st_size > 16384) {
    throw std::runtime_error(
        "device config must be root-owned regular file mode 0600, <=16 KiB");
  }
  std::string text;
  char chunk[1024];
  ssize_t size;
  while ((size = read(raw, chunk, sizeof(chunk))) > 0) {
    text.append(chunk, static_cast<std::size_t>(size));
    if (text.size() > 16384)
      throw std::runtime_error("device config exceeds size limit");
  }
  if (size < 0)
    throw std::runtime_error("cannot read device config");
  Json::CharReaderBuilder builder;
  builder["rejectDupKeys"] = true;
  builder["failIfExtra"] = true;
  builder["allowComments"] = false;
  Json::Value value;
  std::string errors;
  std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
  if (!reader->parse(text.data(), text.data() + text.size(), &value, &errors)) {
    throw std::runtime_error("invalid device config JSON");
  }
  return value;
}

AuthConfig ParseAuthConfig(const Json::Value &value) {
  if (!value.isObject())
    throw std::invalid_argument("config must be an object");
  const auto &fields = KnownConfigFields();
  for (const auto &name : value.getMemberNames()) {
    if (fields.count(name) == 0)
      throw std::invalid_argument("unknown config field");
  }
  AuthConfig config;
  config.vehicle_id = RequiredString(value, "vehicle_id");
  config.gateway_url = RequiredString(value, "gateway_url");
  config.token_url = RequiredString(value, "token_url");
  config.client_id = RequiredString(value, "client_id");
  config.client_secret = RequiredString(value, "client_secret");
  if (!ValidIdentifier(config.vehicle_id))
    throw std::invalid_argument("invalid vehicle_id");
  if (value.isMember("allow_insecure_localhost")) {
    if (!value["allow_insecure_localhost"].isBool()) {
      throw std::invalid_argument("allow_insecure_localhost must be boolean");
    }
    config.allow_insecure_localhost =
        value["allow_insecure_localhost"].asBool();
  }
  if (!AllowedURL(config.gateway_url, config.allow_insecure_localhost) ||
      !AllowedURL(config.token_url, config.allow_insecure_localhost)) {
    throw std::invalid_argument(
        "endpoints require HTTPS without credentials/query/fragment");
  }
  while (config.gateway_url.back() == '/')
    config.gateway_url.pop_back();
  return config;
}

AuthConfig LoadAuthConfig(const std::string &path) {
  return ParseAuthConfig(LoadProtectedJSON(path));
}

}  // namespace vehicle_edge
