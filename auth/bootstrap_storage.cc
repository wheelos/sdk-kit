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

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <memory>
#include <stdexcept>

#include "vehicle_edge/bootstrap.h"
#include "vehicle_edge/http_client.h"

namespace vehicle_edge {
namespace enrollment {
namespace {
class FD {
 public:
  explicit FD(int value) : value_(value) {
    if (value < 0) throw std::runtime_error("protected storage unavailable");
  }
  ~FD() { close(value_); }
  int get() const { return value_; }

 private:
  int value_;
};
void CheckFile(int fd, uid_t owner) {
  struct stat s{};
  if (fstat(fd, &s) || !S_ISREG(s.st_mode) || s.st_uid != owner ||
      (s.st_mode & 07777) != 0600 || s.st_nlink != 1 || s.st_size > 65536)
    throw std::runtime_error(
        "protected file requires owner, 0600 and one link");
}
// Resolve every directory component without following symlinks.
int Directory(const std::string& path, uid_t owner) {
  int current =
      open(path.front() == '/' ? "/" : ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (current < 0) throw std::runtime_error("cannot open storage directory");
  struct stat initial{};
  if (fstat(current, &initial) ||
      (initial.st_uid != 0 && initial.st_uid != owner) ||
      (initial.st_mode & 0022)) {
    close(current);
    throw std::runtime_error("unsafe initial storage directory");
  }
  std::size_t start = path.front() == '/' ? 1 : 0;
  while (start < path.size()) {
    auto end = path.find('/', start);
    if (end == std::string::npos) end = path.size();
    auto part = path.substr(start, end - start);
    start = end + 1;
    if (part.empty() || part == ".") continue;
    if (part == "..") {
      close(current);
      throw std::runtime_error("parent traversal forbidden");
    }
    int next = openat(current, part.c_str(),
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(current);
    if (next < 0) throw std::runtime_error("cannot open storage directory");
    struct stat s{};
    if (fstat(next, &s) || (s.st_uid != 0 && s.st_uid != owner) ||
        (s.st_mode & 0022)) {
      close(next);
      throw std::runtime_error(
          "storage directory must not be publicly writable");
    }
    current = next;
  }
  return current;
}
std::pair<std::string, std::string> Split(const std::string& path) {
  if (path.empty() || path.back() == '/')
    throw std::runtime_error("invalid protected path");
  auto slash = path.find_last_of('/');
  const auto name = slash == std::string::npos ? path : path.substr(slash + 1);
  if (name == "." || name == "..") throw std::runtime_error("invalid filename");
  return {slash == std::string::npos
              ? "."
              : (slash == 0 ? "/" : path.substr(0, slash)),
          name};
}
}  // namespace

Json::Value Storage::Read(const std::string& path, bool optional,
                          std::size_t limit) const {
  auto parts = Split(path);
  FD dir(Directory(parts.first, owner_));
  int raw = openat(dir.get(), parts.second.c_str(),
                   O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (raw < 0 && errno == ENOENT && optional) return Json::Value();
  FD file(raw);
  CheckFile(file.get(), owner_);
  std::string text;
  char chunk[4096];
  ssize_t size;
  while ((size = read(file.get(), chunk, sizeof(chunk))) > 0) {
    text.append(chunk, size);
    if (text.size() > limit)
      throw std::runtime_error("protected file too large");
  }
  if (size < 0) throw std::runtime_error("cannot read protected file");
  auto value = ParseHTTPJSON(text);
  if (!value.isObject())
    throw std::runtime_error("protected JSON must be object");
  return value;
}

void Storage::Write(const std::string& path, const Json::Value& value) const {
  if (geteuid() != owner_) throw std::runtime_error("incorrect storage owner");
  auto parts = Split(path);
  FD dir(Directory(parts.first, owner_));
  int existing = openat(dir.get(), parts.second.c_str(),
                        O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  if (existing >= 0) {
    FD old(existing);
    CheckFile(old.get(), owner_);
  } else if (errno != ENOENT) {
    throw std::runtime_error("unsafe destination");
  }
  Json::StreamWriterBuilder writer;
  writer["indentation"] = "  ";
  auto text = Json::writeString(writer, value) + "\n";
  if (text.size() > 65536) throw std::runtime_error("protected file too large");
  const auto name = "." + parts.second + "." + UUID() + ".new";
  FD file(openat(dir.get(), name.c_str(),
                 O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
  try {
    std::size_t offset = 0;
    while (offset < text.size()) {
      auto size = write(file.get(), text.data() + offset, text.size() - offset);
      if (size < 0 && errno == EINTR) continue;
      if (size <= 0) throw std::runtime_error("cannot write protected file");
      offset += size;
    }
    if (fsync(file.get()) ||
        renameat(dir.get(), name.c_str(), dir.get(), parts.second.c_str()) ||
        fsync(dir.get()))
      throw std::runtime_error("cannot commit protected file");
  } catch (...) {
    unlinkat(dir.get(), name.c_str(), 0);
    throw;
  }
}

int Storage::Lock(const std::string& directory) const {
  FD dir(Directory(directory, owner_));
  int fd = openat(dir.get(), "lock",
                  O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
  if (fd < 0) throw std::runtime_error("cannot lock bootstrap");
  try {
    CheckFile(fd, owner_);
    if (flock(fd, LOCK_EX | LOCK_NB))
      throw std::runtime_error("bootstrap already running");
  } catch (...) {
    close(fd);
    throw;
  }
  return fd;
}
}  // namespace enrollment
}  // namespace vehicle_edge
