#ifndef VIBEOS_NATIVE_STDIO_H_
#define VIBEOS_NATIVE_STDIO_H_
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
// Short transfers are permitted. Negative results: -1 bad descriptor,
// -2 bad pointer, -3 denied, -4 closed pipe, -5 backend/runner failure.
// Kind 1 is a pipe; negative results use the same error convention.
int vibeos_native_fd_kind(int fd);
int vibeos_native_close(int fd);
ptrdiff_t vibeos_native_read(int fd, void* output, size_t length);
ptrdiff_t vibeos_native_write(int fd, const void* input, size_t length);
#ifdef __cplusplus
}
#endif
#endif
