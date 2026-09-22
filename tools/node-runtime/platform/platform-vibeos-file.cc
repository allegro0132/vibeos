// V8 file access goes through newlib's invocation-scoped syscall backend.
// No direct filesystem, device, or global path authority is introduced here.
#include "src/base/platform/platform.h"
#include "src/base/logging.h"
#include "vibeos-sync.h"
#include <cerrno>
#include <cstdio>
#include <sys/stat.h>
#include <unistd.h>

namespace v8::base {
FILE* OS::FOpen(const char* path, const char* mode) {
  FILE* file = std::fopen(path, mode);
  if (!file) return nullptr;
  struct stat info;
  if (fstat(fileno(file), &info) != 0) {
    const int error = errno;
    std::fclose(file);
    errno = error;
    return nullptr;
  }
  if (S_ISREG(info.st_mode)) return file;
  std::fclose(file);
  errno = S_ISDIR(info.st_mode) ? EISDIR : ENOTSUP;
  return nullptr;
}
FILE* OS::OpenTemporaryFile() {
  // tmpfile's open/unlink operations must pass the same root and permission
  // checks as ordinary files. An unavailable temporary directory is an error.
  return std::tmpfile();
}
int OS::GetCurrentProcessId() {
  // v1 has one native thread per invocation and no subprocesses. Its stable
  // execution ID is also the virtual process ID; never expose a hart or ptr.
  const int32_t id = vibeos_native_thread_id();
  CHECK_GT(id, 0);
  return id;
}
}  // namespace v8::base
