#ifndef VIBEOS_NATIVE_FILES_H_
#define VIBEOS_NATIVE_FILES_H_
#include <stddef.h>
#include <stdint.h>
#include <fcntl.h>
#ifdef __cplusplus
extern "C" {
#endif
// 0 success; errors -2 pointer, -3 authority/escape, -5 IO, -6 missing,
// -7 directory, -8 busy, -9 invalid, -10 long path, -11 not-dir, -12 loop.
// Normalize target/host libc flags into the native ABI, rejecting unknown bits.
static inline uint32_t vibeos_native_open_mode(int flags) {
  if (flags & ~(O_ACCMODE | O_CREAT | O_EXCL | O_TRUNC | O_APPEND)) return UINT32_MAX;
  int access = flags & O_ACCMODE;
  uint32_t mode = access == O_RDONLY ? 0 : access == O_WRONLY ? 1 : access == O_RDWR ? 2 : UINT32_MAX;
  if (mode == UINT32_MAX) return mode;
  return mode | ((flags & O_CREAT) ? 4 : 0) | ((flags & O_EXCL) ? 8 : 0) |
         ((flags & O_TRUNC) ? 16 : 0) | ((flags & O_APPEND) ? 32 : 0);
}
int vibeos_native_copyfile(const void* source, size_t source_length,
    const void* destination, size_t destination_length, uint32_t flags);
int vibeos_native_open(const void* path, size_t length, uint32_t mode);
int vibeos_native_chdir(const void* path, size_t length);
ptrdiff_t vibeos_native_getcwd(void* output, size_t capacity);
int64_t vibeos_native_file_size(int fd);
typedef struct {
  uint64_t file_id, size, links, generation, kind; /* 2 file, 3 directory, 4 link */
} vibeos_native_file_stat_t;
int vibeos_native_file_stat(int fd, vibeos_native_file_stat_t* output);
// Completed writes already await authoritative commit. Pending publication is
// explicitly busy; volatile roots retain their volatile persistence policy.
int vibeos_native_file_sync(int fd);
typedef int (*vibeos_native_dir_emit)(void*, const void*, size_t, uint32_t);
int vibeos_native_scandir(const void* path, size_t length,
                          vibeos_native_dir_emit emit, void* context);
int vibeos_native_access(const void* path, size_t length, uint32_t mode);
int vibeos_native_path_stat(const void* path, size_t length, int follow,
                            vibeos_native_file_stat_t* output);
// Target text includes a NUL; success length excludes it. Short buffers remain untouched.
ptrdiff_t vibeos_native_readlink(const void* path, size_t length,
                                void* output, size_t capacity);
ptrdiff_t vibeos_native_realpath(const void* path, size_t length,
                                void* output, size_t capacity);
// offset=-1 uses/advances the cursor; nonnegative offsets leave it unchanged.
ptrdiff_t vibeos_native_file_read_at(int fd, void* output, size_t length, int64_t offset);
ptrdiff_t vibeos_native_file_write_at(int fd, const void* input, size_t length, int64_t offset);
int64_t vibeos_native_file_read_begin_at(int fd, size_t length, int64_t offset);
int64_t vibeos_native_file_write_begin_at(int fd, const void* input, size_t length, int64_t offset);
// Read poll consumes completed/denied requests; -15 pending, bad output retryable.
int64_t vibeos_native_file_read_begin(int fd, size_t length);
ptrdiff_t vibeos_native_file_read_poll(uint64_t id, void* output, size_t capacity);
int64_t vibeos_native_file_write_begin(int fd, const void* bytes, size_t length);
int64_t vibeos_native_file_truncate_begin(int fd, int64_t length);
int vibeos_native_file_truncate(int fd, int64_t length);
int64_t vibeos_native_file_seek(int fd, int64_t offset, int whence);
// Begin returns a positive invocation-owned request id or a negative error.
// Poll consumes the id on completion; -15 means pending with a Rust waker.
// mkdir=1, rmdir=2, rename=3, symlink=4 (literal source), hard link=5.
// Sync returns status, async returns a request id.
int64_t vibeos_native_tree_change(uint32_t operation, const void* path, size_t length,
    const void* destination, size_t destination_length, uint32_t asynchronous);
int64_t vibeos_native_unlink_begin(const void* path, size_t length);
int vibeos_native_mutation_poll(uint64_t id);
int vibeos_native_unlink(const void* path, size_t length);
#ifdef __cplusplus
}
#endif
#endif
