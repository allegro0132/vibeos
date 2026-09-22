#ifndef VIBEOS_NATIVE_PROCESS_H_
#define VIBEOS_NATIVE_PROCESS_H_
#ifdef __cplusplus
extern "C" {
#endif
// Must run on the admitted native stack before V8/Node initialization.
int vibeos_native_runtime_initialize(void);
__attribute__((noreturn)) void vibeos_native_fatal_exit(int status);
#ifdef __cplusplus
}
#endif
#endif
