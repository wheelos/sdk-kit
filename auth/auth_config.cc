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
#include <sys/timex.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
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
      "auth_mode",
      "vehicle_id",
      "gateway_url",
      "token_url",
      "issuer",
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
      "camera_capture_config",
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

bool LoopbackURL(const std::string &url) {
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
  if (scheme != "http" && scheme != "https")
    return false;
  return host == "localhost" || host == "127.0.0.1" || host == "[::1]";
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

namespace {

std::string Origin(const std::string &url) {
  std::unique_ptr<CURLU, decltype(&curl_url_cleanup)> parsed(curl_url(),
                                                             curl_url_cleanup);
  if (!parsed ||
      curl_url_set(parsed.get(), CURLUPART_URL, url.c_str(), 0) != CURLUE_OK) {
    return {};
  }
  char *value = nullptr;
  const auto status = curl_url_get(parsed.get(), CURLUPART_HOST, &value, 0);
  std::unique_ptr<char, decltype(&curl_free)> holder(value, curl_free);
  if (status != CURLUE_OK || !value)
    return {};
  std::string host(value);
  std::transform(host.begin(), host.end(), host.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  char *port = nullptr;
  char *scheme = nullptr;
  if (curl_url_get(parsed.get(), CURLUPART_PORT, &port, CURLU_DEFAULT_PORT) !=
          CURLUE_OK ||
      curl_url_get(parsed.get(), CURLUPART_SCHEME, &scheme, 0) != CURLUE_OK) {
    curl_free(port);
    curl_free(scheme);
    return {};
  }
  const auto origin = std::string(scheme) + "://" + host + ":" + port;
  curl_free(port);
  curl_free(scheme);
  return origin;
}

}  // namespace

bool TrustedTokenEndpoint(const std::string &token_url,
                          const std::string &gateway_url,
                          const std::string &issuer,
                          bool allow_insecure_localhost) {
  if (!AllowedURL(token_url, allow_insecure_localhost) ||
      !AllowedURL(gateway_url, allow_insecure_localhost))
    return false;
  if (!issuer.empty() && !AllowedURL(issuer, allow_insecure_localhost))
    return false;
  if (allow_insecure_localhost) {
    return LoopbackURL(gateway_url) && LoopbackURL(token_url);
  }
  if (!AllowedURL(token_url, false) || !AllowedURL(gateway_url, false) ||
      (!issuer.empty() && !AllowedURL(issuer, false)))
    return false;
  // Gateway's authenticated credential response delegates to this exact issuer
  // origin. Without an issuer, only the Gateway origin is trusted.
  return Origin(token_url) == Origin(issuer.empty() ? gateway_url : issuer);
}

std::string ClockReadinessError() {
  struct timex clock {};
  const int state = adjtimex(&clock);
  return ClockDisciplineError(state, clock.status, clock.maxerror);
}

std::string ClockDisciplineError(int state, int status, long maxerror) {
  if (state < 0)
    return "clock readiness unavailable: cannot query host kernel time discipline";
  if (state == TIME_ERROR || (status & STA_UNSYNC))
    return "clock not synchronized: discipline host CLOCK_REALTIME with chrony/NTP or PTP system-clock servo";
  if (maxerror < 0 || maxerror > 1000000)
    return "clock uncertainty exceeds 1 second: wait for host NTP/PTP convergence";
  return {};
}

Json::Value LoadProtectedJSON(const std::string &path) {
  if (path.empty() || path.back() == '/')
    throw std::runtime_error("invalid protected config path");
  const auto slash = path.find_last_of('/');
  const auto filename = slash == std::string::npos ? path : path.substr(slash + 1);
  const auto parent = slash == std::string::npos ? "." : path.substr(0, slash);
  std::unique_ptr<int, FDCloser> directory(new int(open(
      path.front() == '/' ? "/" : ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC)));
  std::size_t start = path.front() == '/' ? 1 : 0;
  while (true) {
    struct stat info {};
    if (*directory < 0 || fstat(*directory, &info) ||
        (info.st_uid != 0 && info.st_uid != geteuid()) ||
        (info.st_mode & 0022))
      throw std::runtime_error("unsafe protected config directory");
    if (start >= parent.size()) break;
    auto end = parent.find('/', start);
    if (end == std::string::npos) end = parent.size();
    const auto part = parent.substr(start, end - start);
    start = end + 1;
    if (part == "..")
      throw std::runtime_error("protected config parent traversal forbidden");
    if (part.empty() || part == ".") continue;
    directory.reset(new int(openat(*directory, part.c_str(),
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)));
  }
  if (filename == "." || filename == "..")
    throw std::runtime_error("invalid protected config filename");
  const int raw = openat(*directory, filename.c_str(),
      O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (raw < 0)
    throw std::runtime_error("cannot open protected device config");
  std::unique_ptr<int, FDCloser> fd(new int(raw));
  struct stat info {};
  if (fstat(raw, &info) != 0 || !S_ISREG(info.st_mode) ||
      (info.st_uid != 0 && info.st_uid != geteuid()) ||
      info.st_nlink != 1 ||
      ((info.st_mode & 07777) != 0600 &&
       !((info.st_mode & 07777) == 0640 && info.st_uid == 0 &&
         info.st_gid != 0 && (geteuid() == 0 || info.st_gid == getegid()))) ||
      info.st_size > 16384) {
    throw std::runtime_error(
        "device config requires root/current owner, one link, mode 0600 (or root-owned 0640 for dedicated runtime group), <=16 KiB");
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
      throw std::invalid_argument("unknown config field: " + name);
  }
  AuthConfig config;
  if (value.isMember("auth_mode")) {
    if (!value["auth_mode"].isString()) {
      throw std::invalid_argument("auth_mode must be required or local_sim_debug");
    }
    config.auth_mode = value["auth_mode"].asString();
    if (config.auth_mode != "required" &&
        config.auth_mode != "local_sim_debug") {
      throw std::invalid_argument("auth_mode must be required or local_sim_debug");
    }
  }
  config.vehicle_id = RequiredString(value, "vehicle_id");
  config.gateway_url = RequiredString(value, "gateway_url");
  if (!ValidIdentifier(config.vehicle_id))
    throw std::invalid_argument("invalid vehicle_id");
  if (config.IsLocalSimDebug()) {
#ifdef TELEOP_PRODUCTION_BUILD
    throw std::invalid_argument(
        "local_sim_debug is disabled in production builds");
#endif
    config.allow_insecure_localhost = true;
    if (value.isMember("allow_insecure_localhost")) {
      if (!value["allow_insecure_localhost"].isBool()) {
        throw std::invalid_argument(
            "allow_insecure_localhost must be boolean");
      }
      config.allow_insecure_localhost =
          value["allow_insecure_localhost"].asBool();
    }
    if (!LoopbackURL(config.gateway_url) ||
        !AllowedURL(config.gateway_url, config.allow_insecure_localhost)) {
      throw std::invalid_argument(
          "local_sim_debug requires loopback gateway_url");
    }
    if (value.isMember("token_url") && !value["token_url"].isNull()) {
      if (!value["token_url"].isString()) {
        throw std::invalid_argument("non-string config field: token_url");
      }
      config.token_url = value["token_url"].asString();
      if (!config.token_url.empty() &&
          (!LoopbackURL(config.token_url) ||
           !AllowedURL(config.token_url, config.allow_insecure_localhost))) {
        throw std::invalid_argument(
            "local_sim_debug requires loopback token_url");
      }
    }
    if (value.isMember("client_id") && !value["client_id"].isNull()) {
      if (!value["client_id"].isString()) {
        throw std::invalid_argument("non-string config field: client_id");
      }
      config.client_id = value["client_id"].asString();
    }
    if (value.isMember("client_secret") && !value["client_secret"].isNull()) {
      if (!value["client_secret"].isString()) {
        throw std::invalid_argument("non-string config field: client_secret");
      }
      config.client_secret = value["client_secret"].asString();
    }
  } else {
    config.token_url = RequiredString(value, "token_url");
    if (value.isMember("issuer"))
      config.issuer = RequiredString(value, "issuer");
    config.client_id = RequiredString(value, "client_id");
    config.client_secret = RequiredString(value, "client_secret");
    if (value.isMember("allow_insecure_localhost")) {
#ifdef TELEOP_PRODUCTION_BUILD
      throw std::invalid_argument(
          "allow_insecure_localhost is disabled in production builds");
#endif
      if (!value["allow_insecure_localhost"].isBool()) {
        throw std::invalid_argument(
            "allow_insecure_localhost must be boolean");
      }
      config.allow_insecure_localhost =
          value["allow_insecure_localhost"].asBool();
    }
    if (config.allow_insecure_localhost &&
        (!LoopbackURL(config.gateway_url) || !LoopbackURL(config.token_url))) {
      throw std::invalid_argument(
          "allow_insecure_localhost requires loopback gateway_url and token_url");
    }
    if (!AllowedURL(config.gateway_url, config.allow_insecure_localhost) ||
        !AllowedURL(config.token_url, config.allow_insecure_localhost) ||
        !TrustedTokenEndpoint(config.token_url, config.gateway_url, config.issuer,
                              config.allow_insecure_localhost)) {
      throw std::invalid_argument(
          "endpoints require HTTPS and exact trusted issuer/Gateway origin");
    }
  }
  while (config.gateway_url.back() == '/')
    config.gateway_url.pop_back();
  return config;
}

AuthConfig LoadAuthConfig(const std::string &path) {
  const auto value = LoadProtectedJSON(path);
  if (value.isMember("credentials_file"))
    return ParseAuthConfig(LoadDeviceConfigJSON(path));
  for (const auto &name : value.getMemberNames())
    if (!IsAuthConfigField(name))
      throw std::invalid_argument("non-authentication field in credentials: " +
                                  name);
  auto config = ParseAuthConfig(value);
  config.credentials_file = path;
  return config;
}

bool IsAuthConfigField(const std::string &name) {
  return name == "auth_mode" || name == "vehicle_id" || name == "gateway_url" ||
         name == "token_url" || name == "issuer" || name == "client_id" ||
         name == "client_secret" || name == "allow_insecure_localhost";
}

Json::Value ResolveDeviceConfig(const Json::Value &runtime,
                                const Json::Value &credentials) {
  if (!runtime.isObject() || !credentials.isObject())
    throw std::invalid_argument("runtime and credentials must be objects");
  if (!runtime["credentials_file"].isString() ||
      runtime["credentials_file"].asString().empty() ||
      runtime["credentials_file"].asString().front() != '/')
    throw std::invalid_argument("credentials_file must be an absolute path");
  Json::Value resolved = runtime;
  resolved.removeMember("credentials_file");
  for (const auto &name : resolved.getMemberNames()) {
    if (IsAuthConfigField(name))
      throw std::invalid_argument(
          "authentication belongs in credentials file: " + name);
  }
  for (const auto &name : credentials.getMemberNames()) {
    if (!IsAuthConfigField(name))
      throw std::invalid_argument("non-authentication field in credentials: " +
                                  name);
    resolved[name] = credentials[name];
  }
  (void)ParseAuthConfig(resolved);
  return resolved;
}

Json::Value LoadDeviceConfigJSON(const std::string &path) {
  const auto runtime = LoadProtectedJSON(path);
  if (!runtime["credentials_file"].isString() ||
      runtime["credentials_file"].asString().empty() ||
      runtime["credentials_file"].asString().front() != '/')
    throw std::invalid_argument("credentials_file must be an absolute path");
  return ResolveDeviceConfig(
      runtime, LoadProtectedJSON(runtime["credentials_file"].asString()));
}

}  // namespace vehicle_edge
