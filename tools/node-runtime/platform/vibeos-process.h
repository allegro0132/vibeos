#ifndef VIBEOS_NATIVE_PROCESS_H_
#define VIBEOS_NATIVE_PROCESS_H_
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
// Invocation-local display title, capped at 4096 bytes. Short reads preserve
// the buffer. Native errors: -9 invalid, -16 allocation, -20 limit, -21 short.
int vibeos_native_set_title(const void* title, size_t length);
ptrdiff_t vibeos_native_get_title(void* output, size_t capacity);
// Static image sysname/release/version/machine labels; unknown field is NULL.
const char* vibeos_native_system_label(uint32_t field);
// Cooperative native-stack yield: 0 live, 1 cancelled, -1 missing runner.
// A nonzero result must terminate through V8 normal exception unwinding.
int vibeos_native_checkpoint(void);
// Read cancellation without yielding, for environment/event-loop boundaries.
int vibeos_native_is_cancelled(void);
// Must run on the admitted native stack before V8/Node initialization.
int vibeos_native_runtime_initialize(void);
__attribute__((noreturn)) void vibeos_native_fatal_exit(int status);
#ifdef __cplusplus
}
#endif
#endif
