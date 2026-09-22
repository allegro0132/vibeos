#ifndef VIBEOS_NATIVE_LIBC_HEAP_H_
#define VIBEOS_NATIVE_LIBC_HEAP_H_
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
// Process-lifetime, bounded and accounted TCB heap. Returns old break or -1.
// No pointer from this heap may be reclaimed by invocation-page teardown.
void* vibeos_native_sbrk(ptrdiff_t increment);
#ifdef __cplusplus
}
#endif
#endif
