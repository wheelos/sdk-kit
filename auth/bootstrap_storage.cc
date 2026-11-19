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
      ((s.st_mode & 07777) != 0600 &&
       !((s.st_mode & 07777) == 0640 && owner == 0 && s.st_gid != 0)) ||
      s.st_nlink != 1 || s.st_size > 65536)
    throw std::runtime_error(
        "protected file requires owner, 0600 and one link");
}
// Resolve every directory component without following symlinks.
int Directory(const std::string& path, uid_t owner, bool create = false,
              gid_t runtime_group = 0) {
  if (path.empty()) throw std::runtime_error("empty storage directory");
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
    bool created = false;
    if (create) {
      created = mkdirat(current, part.c_str(), 0700) == 0;
      if (!created && errno != EEXIST) {
        close(current);
        throw std::runtime_error("cannot create protected directory");
      }
    }
    int next = openat(current, part.c_str(),
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (next < 0) {
      close(current);
      throw std::runtime_error("cannot open storage directory");
    }
    if (created && runtime_group != 0 &&
        (fchown(next, 0, runtime_group) || fchmod(next, 0750) || fsync(next))) {
      close(current);
      close(next);
      throw std::runtime_error("cannot create runtime configuration directory");
    }
    if (created && runtime_group == 0 && owner == 0 &&
        (fchown(next, 0, 0) || fchmod(next, 0700) || fsync(next))) {
      close(current);
      close(next);
      throw std::runtime_error("cannot create private root directory");
    }
    if (create && fsync(current)) {
      close(current);
      close(next);
      throw std::runtime_error("cannot persist protected directory");
    }
    close(current);
    struct stat s{};
    if (fstat(next, &s) || (s.st_uid != 0 && s.st_uid != owner) ||
        (s.st_mode & 0022)) {
      close(next);
      throw std::runtime_error(
          "storage directory must not be publicly writable");
    }
    if (runtime_group != 0 && start < path.size() &&
        ((s.st_gid == runtime_group ? (s.st_mode >> 3) : s.st_mode) & 5) != 5) {
      close(next);
      throw std::runtime_error("runtime cannot traverse configuration parents");
    }
    current = next;
  }
  return current;
}
void RuntimeOwner(uid_t owner, const RuntimeUser& user) {
  if (owner != 0 || geteuid() != 0 || user.uid == 0 || user.gid == 0)
    throw std::runtime_error("runtime provisioning requires root and non-root runtime");
}
void RuntimeFile(int fd, const RuntimeUser& user) {
  CheckFile(fd, 0);
  struct stat info {};
  if (fstat(fd, &info) || (info.st_gid != 0 && info.st_gid != user.gid))
    throw std::runtime_error("runtime file group change requires explicit migration");
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

void Storage::EnsureDirectory(const std::string& path) const {
  if (geteuid() != owner_) throw std::runtime_error("incorrect storage owner");
  FD directory(Directory(path, owner_, true));
  struct stat s {};
  if (fstat(directory.get(), &s) || s.st_uid != owner_ ||
      ((s.st_mode & 07777) != 0700 &&
       !((s.st_mode & 07777) == 0750 && owner_ == 0 && s.st_gid != 0)) ||
      fsync(directory.get()))
    throw std::runtime_error("cannot protect storage directory");
}

void Storage::EnsureRuntimeDirectory(const std::string& path,
                                     const RuntimeUser& user) const {
  RuntimeOwner(owner_, user);
  FD directory(Directory(path, owner_, true, user.gid));
  struct stat info {};
  if (fstat(directory.get(), &info) || info.st_uid != 0 ||
      (info.st_gid != 0 && info.st_gid != user.gid) ||
      ((info.st_mode & 07777) != 0700 &&
       (info.st_mode & 07777) != 0750))
    throw std::runtime_error("runtime configuration requires a dedicated protected directory");
  if (fchown(directory.get(), 0, user.gid) ||
      fchmod(directory.get(), 0750) || fsync(directory.get()))
    throw std::runtime_error("cannot share runtime configuration directory");
}

void Storage::ShareRuntimeFile(const std::string& path,
                               const RuntimeUser& user) const {
  RuntimeOwner(owner_, user);
  const auto parts = Split(path);
  FD dir(Directory(parts.first, owner_));
  const int raw = openat(dir.get(), parts.second.c_str(),
                        O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  if (raw < 0 && errno == ENOENT) return;
  FD file(raw);
  RuntimeFile(file.get(), user);
  if (fchown(file.get(), 0, user.gid) || fchmod(file.get(), 0640) ||
      fsync(file.get()))
    throw std::runtime_error("cannot share protected runtime file");
}

void Storage::EnsureDataDirectory(const std::string& path,
                                  const RuntimeUser& user) const {
  RuntimeOwner(owner_, user);
  const auto parts = Split(path);
  // The parent is root-owned, so the runtime cannot replace the directory.
  FD parent(Directory(parts.first, owner_));
  const bool created = mkdirat(parent.get(), parts.second.c_str(), 0700) == 0;
  if (!created && errno != EEXIST)
    throw std::runtime_error("cannot create runtime data directory");
  FD dir(openat(parent.get(), parts.second.c_str(),
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
  struct stat info {};
  if (fstat(dir.get(), &info))
    throw std::runtime_error("cannot inspect runtime data directory");
  if (created) {
    if (info.st_uid != 0 || fchown(dir.get(), user.uid, user.gid) ||
        fchmod(dir.get(), 0700) || fsync(dir.get()) || fsync(parent.get()))
      throw std::runtime_error("cannot assign runtime data directory");
  } else if (info.st_uid != user.uid || info.st_gid != user.gid ||
             (info.st_mode & 07777) != 0700) {
    throw std::runtime_error("existing data directory needs offline ownership migration");
  }
}

void Storage::Remove(const std::string& path) const {
  if (geteuid() != owner_) throw std::runtime_error("incorrect storage owner");
  auto parts = Split(path);
  int dir_fd = -1;
  try {
    dir_fd = Directory(parts.first, owner_);
  } catch (const std::runtime_error&) {
    if (errno == ENOENT) return;
    throw;
  }
  FD dir(dir_fd);
  int raw = openat(dir.get(), parts.second.c_str(),
                   O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  if (raw < 0 && errno == ENOENT) return;
  FD file(raw);
  CheckFile(file.get(), owner_);
  if (unlinkat(dir.get(), parts.second.c_str(), 0) || fsync(dir.get()))
    throw std::runtime_error("cannot remove protected file");
}

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
  WriteFile(path, value, nullptr);
}

void Storage::WriteRuntime(const std::string& path, const Json::Value& value,
                           const RuntimeUser& user) const {
  RuntimeOwner(owner_, user);
  WriteFile(path, value, &user);
}

void Storage::WriteFile(const std::string& path, const Json::Value& value,
                        const RuntimeUser* user) const {
  if (geteuid() != owner_) throw std::runtime_error("incorrect storage owner");
  auto parts = Split(path);
  FD dir(Directory(parts.first, owner_));
  int existing = openat(dir.get(), parts.second.c_str(),
                        O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  mode_t mode = 0600;
  gid_t group = owner_ == 0 ? 0 : getegid();
  if (existing >= 0) {
    FD old(existing);
    CheckFile(old.get(), owner_);
    if (user) RuntimeFile(old.get(), *user);
    struct stat previous {};
    if (fstat(old.get(), &previous))
      throw std::runtime_error("cannot inspect protected destination");
    mode = previous.st_mode & 07777;
    group = previous.st_gid;
  } else if (errno != ENOENT) {
    throw std::runtime_error("unsafe destination");
  }
  if (user) {
    group = user->gid;
    mode = 0640;
  }
  Json::StreamWriterBuilder writer;
  writer["indentation"] = "  ";
  auto text = Json::writeString(writer, value) + "\n";
  if (text.size() > 65536) throw std::runtime_error("protected file too large");
  const auto name = "." + parts.second + "." + UUID() + ".new";
  FD file(openat(dir.get(), name.c_str(),
                 O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
  try {
    if (fchown(file.get(), owner_, group) || fchmod(file.get(), mode))
      throw std::runtime_error("cannot preserve protected file ownership");
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
                  O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK,
                  0600);
  const bool created = fd >= 0;
  if (fd < 0 && errno == EEXIST)
    fd = openat(dir.get(), "lock", O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0) throw std::runtime_error("cannot lock bootstrap");
  try {
    if (created && (fchown(fd, owner_, owner_ == 0 ? 0 : getegid()) ||
                    fchmod(fd, 0600)))
      throw std::runtime_error("cannot protect bootstrap lock");
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
