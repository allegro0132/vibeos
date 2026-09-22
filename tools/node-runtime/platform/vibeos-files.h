#ifndef VIBEOS_NATIVE_FILES_H_
#define VIBEOS_NATIVE_FILES_H_
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
// 0 success; errors -2 pointer, -3 authority/escape, -5 IO, -6 missing,
// -7 directory, -8 busy, -9 invalid, -10 long path, -11 not-dir, -12 loop.
int vibeos_native_open(const void* path, size_t length, uint32_t mode);
int64_t vibeos_native_file_size(int fd);
int64_t vibeos_native_file_seek(int fd, int64_t offset, int whence);
int vibeos_native_unlink(const void* path, size_t length);
#ifdef __cplusplus
}
#endif
#endif
