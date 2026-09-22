// Host contract test with injected bridges, not target runtime acceptance.
#include <cassert>
#include <cstdlib>
#include <cstddef>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
extern "C" int _gettimeofday(timeval*, void*);
extern "C" pid_t _getpid();
extern "C" int _kill(pid_t, int);
extern "C" int vibeos_native_runtime_initialize();
static int initializations;
extern "C" void __libc_init_array() { ++initializations; }
extern "C" void __libc_fini_array() {}
extern "C" int _unlink(const char*);
extern "C" int _open(const char*, int, int);
extern "C" int vibeos_native_open(const void*, size_t, uint32_t mode) { return mode == 0 ? 3 : -13; }
extern "C" int64_t vibeos_native_file_size(int) { return 42; }
extern "C" int64_t vibeos_native_file_seek(int, int64_t offset, int) { return offset; }
static int unlink_result;
extern "C" int vibeos_native_unlink(const void*, size_t) { return unlink_result; }
extern "C" __attribute__((noreturn)) void vibeos_native_fatal_exit(int) { std::abort(); }
extern "C" ssize_t _read(int, void*, size_t);
extern "C" ssize_t _write(int, const void*, size_t);
extern "C" int _close(int);
extern "C" int _fstat(int, struct stat*);
extern "C" int _isatty(int);
extern "C" off_t _lseek(int, off_t, int);
static int fd_kind = 1;
extern "C" int vibeos_native_fd_kind(int) { return fd_kind; }
extern "C" int vibeos_native_close(int) { return fd_kind < 0 ? fd_kind : 0; }
static ptrdiff_t io_return;
extern "C" ptrdiff_t vibeos_native_read(int, void*, size_t) { return io_return; }
extern "C" ptrdiff_t vibeos_native_write(int, const void*, size_t) { return io_return; }
extern "C" void* _sbrk(ptrdiff_t);
extern "C" int _getentropy(void*, size_t);
extern "C" int vibeos_test_posix_memalign(void**, size_t, size_t);
static int calls, fail_on;
static int64_t clock_us = 123456789;
static bool allocation_fails;
alignas(64) static uint8_t allocation[128];
extern "C" int64_t vibeos_native_realtime_us() { return clock_us; }
extern "C" int32_t vibeos_native_thread_id() { return 42; }
extern "C" int vibeos_native_entropy(uint8_t* bytes, size_t count) {
  assert(count <= 64);
  if (++calls == fail_on) return -1;
  std::memset(bytes, calls, count);
  return 0;
}
extern "C" void* vibeos_test_memalign(size_t alignment, size_t size) {
  assert(alignment == 64 && size == 128);
  errno = ENOMEM;
  return allocation_fails ? nullptr : allocation;
}
extern "C" void* vibeos_native_sbrk(ptrdiff_t increment) {
  assert(increment == 128 || increment == -128);
  return increment > 0 ? allocation : reinterpret_cast<void*>(uintptr_t(-1));
}
int main() {
  assert(vibeos_native_runtime_initialize() == 0);
  assert(vibeos_native_runtime_initialize() == 0 && initializations == 1);
  assert(_open("file", 0, 0) == 3);
  assert(_open("file", 1, 0) == -1 && errno == ENOTSUP);
  assert(_unlink(nullptr) == -1 && errno == EFAULT);
  assert(_unlink("file") == 0);
  const int file_errors[] = {ENOENT, EISDIR, EBUSY, EINVAL, ENAMETOOLONG, ENOTDIR, ELOOP};
  for (int i = 0; i < 7; ++i) {
    unlink_result = -6 - i;
    assert(_unlink("file") == -1 && errno == file_errors[i]);
  }
  assert(_kill(42, 15) == -1 && errno == ENOTSUP);
  struct stat info{};
  assert(_fstat(0, &info) == 0 && S_ISFIFO(info.st_mode));
  assert((info.st_mode & 0777) == S_IRUSR && info.st_blksize == 1024);
  assert(_fstat(1, &info) == 0 && (info.st_mode & 0777) == S_IWUSR);
  assert(_fstat(1, nullptr) == -1 && errno == EFAULT);
  assert(_isatty(1) == 0 && errno == ENOTTY);
  assert(_lseek(1, 0, 0) == -1 && errno == ESPIPE);
  assert(_close(1) == 0);
  fd_kind = -1;
  const auto old_mode = info.st_mode;
  assert(_fstat(1, &info) == -1 && errno == EBADF && info.st_mode == old_mode);
  assert(_isatty(1) == 0 && errno == EBADF);
  assert(_lseek(1, 0, 0) == -1 && errno == EBADF);
  assert(_close(1) == -1 && errno == EBADF);
  fd_kind = -3;
  assert(_fstat(1, &info) == -1 && errno == EACCES);
  fd_kind = 2;
  assert(_fstat(3, &info) == 0 && S_ISREG(info.st_mode) && info.st_size == 42);
  assert(_lseek(3, 5, 0) == 5);
  fd_kind = 1;
  const int errors[] = {EBADF, EFAULT, EACCES, EPIPE, EIO};
  for (int i = 1; i <= 5; ++i) {
    io_return = -i;
    assert(_read(0, allocation, 128) == -1 && errno == errors[i - 1]);
    assert(_write(1, allocation, 128) == -1 && errno == errors[i - 1]);
  }
  io_return = 3;
  assert(_write(1, allocation, 128) == 3);
  io_return = 0;
  assert(_read(0, allocation, 128) == 0);
  errno = EBUSY;
  assert(_sbrk(128) == allocation && errno == EBUSY);
  assert(_sbrk(-128) == reinterpret_cast<void*>(uintptr_t(-1)) && errno == ENOMEM);
  timeval time{9, 8};
  assert(_gettimeofday(&time, nullptr) == 0);
  assert(time.tv_sec == 123 && time.tv_usec == 456789);
  clock_us = -1;
  assert(_gettimeofday(&time, nullptr) == -1 && errno == EIO);
  assert(time.tv_sec == 123 && time.tv_usec == 456789);
  assert(_gettimeofday(nullptr, nullptr) == -1 && errno == EFAULT);
  assert(_getpid() == 42);
  uint8_t bytes[257]; std::memset(bytes, 0xAA, sizeof(bytes));
  assert(_getentropy(bytes, 256) == 0 && calls == 4);
  for (int i = 0; i < 256; ++i) assert(bytes[i] == i / 64 + 1);
  assert(bytes[256] == 0xAA);
  std::memset(bytes, 0xAA, sizeof(bytes)); calls = 0; fail_on = 3;
  assert(_getentropy(bytes, 256) == -1 && errno == EIO);
  for (auto byte : bytes) assert(byte == 0xAA);
  calls = 0;
  assert(_getentropy(bytes, 257) == -1 && errno == EIO && calls == 0);
  assert(_getentropy(nullptr, 1) == -1 && errno == EFAULT && calls == 0);
  fail_on = 1;
  assert(_getentropy(nullptr, 0) == -1 && errno == EIO);
  fail_on = 0;
  assert(_getentropy(nullptr, 0) == 0);
  void* output = bytes; errno = EBUSY;
  assert(vibeos_test_posix_memalign(&output, 3, 128) == EINVAL);
  assert(output == bytes && errno == EBUSY);
  allocation_fails = true;
  assert(vibeos_test_posix_memalign(&output, 64, 128) == ENOMEM);
  assert(output == bytes && errno == EBUSY);
  allocation_fails = false;
  assert(vibeos_test_posix_memalign(&output, 64, 128) == 0);
  assert(output == allocation && errno == EBUSY);
}
