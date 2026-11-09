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

#include <sys/types.h>

#include <cstdint>
#include <exception>
#include <functional>
#include <string>

#include <json/json.h>

namespace vehicle_edge {
namespace enrollment {

struct Request {
  std::string method, url, content_type, body, bearer;
  bool local_test = false;
};
struct Response {
  long status = 0;
  std::string body;
  unsigned retry_after = 0;
};
class TransportError : public std::exception {
 public:
  const char* what() const noexcept override { return "transport unavailable"; }
};
Response Send(const Request& request);

std::string UUID();
std::string Base64URL(const std::string& raw);
std::string DecodeBase64URL(const std::string& encoded, std::size_t bytes);
std::string PublicKey(const std::string& private_key);
std::string Canonical(const std::string& action, const Json::Value& envelope);
Json::Value Sign(const std::string& action, Json::Value envelope,
                 const std::string& private_key);

// Owner injection is for unprivileged isolated tests; the CLI always uses root.
class Storage {
 public:
  explicit Storage(uid_t owner = 0) : owner_(owner) {}
  Json::Value Read(const std::string& path, bool optional = false,
                   std::size_t limit = 65536) const;
  void Write(const std::string& path, const Json::Value& value) const;
  int Lock(const std::string& directory) const;

 private:
  uid_t owner_;
};

Json::Value MergeDevice(const Json::Value& base, const Json::Value& existing,
                        const Json::Value& credentials, bool local_test);
bool InvalidCredentials(const Response& response);

enum class Status { Waiting, Ready, Denied, Blocked };
struct Result {
  Status status;
  unsigned delay = 0;
  std::string stage;
  std::string error_code;
  std::string message;
  long http_status = 0;
};
struct Hooks {
  std::function<Response(const Request&)> request = Send;
  std::function<std::int64_t()> now;
  std::function<void(const std::string&)> notice;
};

class Bootstrap {
 public:
  Bootstrap(Json::Value config, Hooks hooks, Storage storage = Storage());
  ~Bootstrap();
  Result Step();

 private:
  Result Advance();
  Result Wait(unsigned seconds);
  Result Retry(unsigned minimum = 5, const std::string& code = "",
               const std::string& hint = "", long http_status = 0);
  Result Block(const std::string& stage, const std::string& code,
               const std::string& hint, long http_status = 0);
  void ClearError();
  void NotifyOnce(const std::string& key, const std::string& message);
  void Save();
  void NewEnrollment();
  Response Call(const std::string& method, const std::string& url,
                const std::string& body = "", const std::string& bearer = "",
                const std::string& type = "application/json");
  Response Enrollment(const std::string& action);
  Result Authenticate(const Json::Value& device);

  Json::Value config_, state_;
  Hooks hooks_;
  Storage storage_;
  std::string private_key_;
  std::string current_stage_;
  std::string last_diagnostic_key_;
  int lock_ = -1;
  unsigned failures_ = 0;
  bool local_test_ = false;
};

}  // namespace enrollment
}  // namespace vehicle_edge
