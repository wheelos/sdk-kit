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
#include <cctype>
#include <memory>
#include <stdexcept>

#include <curl/curl.h>

#include "vehicle_edge/bootstrap.h"
#include "vehicle_edge/http_client.h"

namespace vehicle_edge {
namespace enrollment {
namespace {
std::size_t Body(char* data, std::size_t size, std::size_t count,
                 void* context) {
  auto* response = static_cast<Response*>(context);
  if (size && count > 65536 / size) return 0;
  auto bytes = size * count;
  if (response->body.size() + bytes > 65536) return 0;
  response->body.append(data, bytes);
  return bytes;
}
std::size_t Header(char* data, std::size_t size, std::size_t count,
                   void* context) {
  if (size && count > 8192 / size) return 0;
  auto bytes = size * count;
  std::string line(data, bytes);
  std::transform(line.begin(), line.end(), line.begin(),
                 [](unsigned char c) { return std::tolower(c); });
  auto* response = static_cast<Response*>(context);
  if (line.rfind("http/", 0) == 0) response->retry_after = 0;
  if (line.rfind("retry-after:", 0) == 0) {
    auto start = line.find_first_not_of(" \t", 12);
    if (start != std::string::npos) {
      auto end = line.find_first_not_of("0123456789", start);
      auto number = line.substr(start, end - start);
      if (!number.empty() && number.size() <= 5) {
        auto seconds = std::stoul(number);
        if (seconds <= 86400) response->retry_after = seconds;
      }
    }
  }
  return bytes;
}
void Check(CURLcode result) {
  if (result != CURLE_OK) throw std::runtime_error("HTTP configuration failed");
}
}  // namespace

Response Send(const Request& request) {
  if (!AllowedURL(request.url, request.local_test) ||
      (!request.bearer.empty() && !ValidBearerToken(request.bearer)) ||
      (request.method != "GET" && request.method != "POST"))
    throw std::runtime_error("invalid bootstrap endpoint");
  InitializeHTTPTransport();
  thread_local std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl(
      curl_easy_init(), curl_easy_cleanup);
  if (!curl) throw std::runtime_error("HTTP allocation failed");
  curl_easy_reset(curl.get());
  std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> headers(
      nullptr, curl_slist_free_all);
  for (const auto& line :
       {"Content-Type: " + request.content_type,
        std::string("Accept: application/json"),
        request.bearer.empty() ? std::string()
                               : "Authorization: Bearer " + request.bearer}) {
    if (line.empty()) continue;
    auto* updated = curl_slist_append(headers.get(), line.c_str());
    if (!updated) throw std::runtime_error("HTTP header allocation failed");
    headers.release();
    headers.reset(updated);
  }
  Response response;
  Check(curl_easy_setopt(curl.get(), CURLOPT_URL, request.url.c_str()));
  Check(curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, headers.get()));
  Check(curl_easy_setopt(curl.get(), CURLOPT_CONNECTTIMEOUT_MS, 5000L));
  Check(curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT_MS, 15000L));
  Check(curl_easy_setopt(curl.get(), CURLOPT_NOSIGNAL, 1L));
  Check(curl_easy_setopt(curl.get(), CURLOPT_FOLLOWLOCATION, 0L));
  Check(curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYPEER, 1L));
  Check(curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYHOST, 2L));
  Check(curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, Body));
  Check(curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response));
  Check(curl_easy_setopt(curl.get(), CURLOPT_HEADERFUNCTION, Header));
  Check(curl_easy_setopt(curl.get(), CURLOPT_HEADERDATA, &response));
  if (request.method == "POST") {
    Check(curl_easy_setopt(curl.get(), CURLOPT_POST, 1L));
    Check(
        curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, request.body.data()));
    Check(curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE_LARGE,
                           static_cast<curl_off_t>(request.body.size())));
  }
  if (curl_easy_perform(curl.get()) != CURLE_OK) throw TransportError();
  Check(
      curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &response.status));
  return response;
}
}  // namespace enrollment
}  // namespace vehicle_edge
