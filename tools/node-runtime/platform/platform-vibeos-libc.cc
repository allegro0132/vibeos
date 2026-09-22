// newlib entry points backed by the admitted native invocation.
#include "vibeos-entropy.h"
#include "vibeos-libc-heap.h"
#include "vibeos-sync.h"
#include "vibeos-stdio.h"
#include "vibeos-process.h"
#include "vibeos-files.h"
#include "vibeos-time.h"
#include <atomic>
#include <cerrno>
#include <fcntl.h>
#include <cstring>
#include <malloc.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>

extern "C" int _gettimeofday(struct timeval* value, void*) {
  if (!value) { errno = EFAULT; return -1; }
  const int64_t now = vibeos_native_realtime_us();
  if (now < 0) { errno = EIO; return -1; }
  value->tv_sec = now / 1000000;
  value->tv_usec = now % 1000000;
  return 0;
}

extern "C" pid_t _getpid(void) {
  return static_cast<pid_t>(vibeos_native_thread_id());
}

extern "C" int _getentropy(void* output, size_t length) {
  if (length > 256) { errno = EIO; return -1; }
  if (!output && length) { errno = EFAULT; return -1; }
  // The granted device service accepts at most 64 bytes per operation.
  // Stage all chunks so a later failure cannot partially modify the caller.
  uint8_t bytes[256];
  if (!length && vibeos_native_entropy(bytes, 0) != 0) {
    errno = EIO; return -1;
  }
  for (size_t offset = 0; offset < length;) {
    const size_t count = length - offset < 64 ? length - offset : 64;
    if (vibeos_native_entropy(bytes + offset, count) != 0) {
      errno = EIO; return -1;
    }
    offset += count;
  }
  if (length) std::memcpy(output, bytes, length);
  return 0;
}

extern "C" int posix_memalign(void** output, size_t alignment, size_t size) {
  if (alignment < sizeof(void*) || (alignment & (alignment - 1)) != 0)
    return EINVAL;
  const int saved_errno = errno;
  void* allocation = memalign(alignment, size);
  errno = saved_errno;
  if (!allocation) return ENOMEM;
  *output = allocation;
  return 0;
}

extern "C" void* _sbrk(ptrdiff_t increment) {
  void* previous = vibeos_native_sbrk(increment);
  if (previous == reinterpret_cast<void*>(static_cast<uintptr_t>(-1)))
    errno = ENOMEM;
  return previous;
}

namespace {
_READ_WRITE_RETURN_TYPE io_result(ptrdiff_t result) {
  if (result >= 0) return static_cast<_READ_WRITE_RETURN_TYPE>(result);
  switch (result) {
    case -1: errno = EBADF; break;
    case -2: errno = EFAULT; break;
    case -3: errno = EACCES; break;
    case -4: errno = EPIPE; break;
    case -6: errno = ENOENT; break;
    case -7: errno = EISDIR; break;
    case -8: errno = EBUSY; break;
    case -9: errno = EINVAL; break;
    case -10: errno = ENAMETOOLONG; break;
    case -11: errno = ENOTDIR; break;
    case -12: errno = ELOOP; break;
    case -13: errno = ENOTSUP; break;
    case -14: errno = EMFILE; break;
    default: errno = EIO; break;
  }
  return -1;
}
}
extern "C" _READ_WRITE_RETURN_TYPE _read(int fd, void* output, size_t length) {
  return io_result(vibeos_native_read(fd, output, length));
}
extern "C" _READ_WRITE_RETURN_TYPE _write(int fd, const void* input, size_t length) {
  return io_result(vibeos_native_write(fd, input, length));
}

extern "C" int _close(int fd) {
  return static_cast<int>(io_result(vibeos_native_close(fd)));
}
extern "C" int _fstat(int fd, struct stat* output) {
  const int kind = vibeos_native_fd_kind(fd);
  if (kind < 0) return static_cast<int>(io_result(kind));
  if (!output) { errno = EFAULT; return -1; }
  if (kind != 1 && kind != 2) { errno = ENOTSUP; return -1; }
  struct stat value = {};
  if (kind == 2) {
    const int64_t size = vibeos_native_file_size(fd);
    if (size < 0) return static_cast<int>(io_result(size));
    value.st_size = size;
    value.st_mode = S_IFREG | S_IRUSR;
  } else value.st_mode = S_IFIFO | (fd == 0 ? S_IRUSR : S_IWUSR);
  value.st_nlink = 1;
  value.st_blksize = 1024;
  *output = value;
  return 0;
}
extern "C" int _isatty(int fd) {
  const int kind = vibeos_native_fd_kind(fd);
  if (kind < 0) { io_result(kind); return 0; }
  errno = ENOTTY;
  return 0;
}
extern "C" off_t _lseek(int fd, off_t offset, int whence) {
  const int kind = vibeos_native_fd_kind(fd);
  if (kind < 0) io_result(kind);
  else if (kind == 2) {
    const int64_t position = vibeos_native_file_seek(fd, offset, whence);
    if (position >= 0) return static_cast<off_t>(position);
    io_result(position);
  } else errno = kind == 1 ? ESPIPE : ENOTSUP;
  return static_cast<off_t>(-1);
}

extern "C" __attribute__((noreturn)) void _exit(int status) {
  vibeos_native_fatal_exit(status);
}
extern "C" int _kill(pid_t, int) {
  // v1 has no POSIX signal delivery or process-group authority. Node's normal
  // return/cancellation must use the native runner, not emulate a signal.
  errno = ENOTSUP;
  return -1;
}

extern "C" int _unlink(const char* path) {
  if (!path) { errno = EFAULT; return -1; }
  const size_t length = strnlen(path, 4097);
  const int result = vibeos_native_unlink(path, length);
  if (result >= 0) return result;
  switch (result) {
    case -6: errno = ENOENT; break;
    case -7: errno = EISDIR; break;
    case -8: errno = EBUSY; break;
    case -9: errno = EINVAL; break;
    case -10: errno = ENAMETOOLONG; break;
    case -11: errno = ENOTDIR; break;
    case -12: errno = ELOOP; break;
    default: return static_cast<int>(io_result(result));
  }
  return -1;
}

extern "C" int _open(const char* path, int flags, int) {
  if (!path) { errno = EFAULT; return -1; }
  const uint32_t mode = flags == O_RDONLY ? 0 : 1;
  return static_cast<int>(io_result(vibeos_native_open(path, strnlen(path, 4097), mode)));
}

extern "C" void __libc_init_array(void);
extern "C" void __libc_fini_array(void);
// Pinned newlib register_fini tests this symbol's address before registering
// __libc_fini_array with atexit. Give it a real callable implementation too.
extern "C" void __libc_fini(void) { __libc_fini_array(); }

extern "C" int vibeos_native_runtime_initialize(void) {
  // Process-lifetime static initialization, never repeated per Node invocation.
  // Recursion/concurrent initialization fails instead of spinning in scheduler.
  static std::atomic<unsigned> state{0};
  (void)vibeos_native_thread_id(); // Requires an admitted native context.
  unsigned expected = 0;
  if (!state.compare_exchange_strong(expected, 1)) return expected == 2 ? 0 : -1;
  __libc_init_array();
  state.store(2);
  return 0;
}
