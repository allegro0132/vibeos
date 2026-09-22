// Native instruction-cache synchronization. Does not grant executable memory.
#ifndef VIBEOS_NATIVE_CACHE_H_
#define VIBEOS_NATIVE_CACHE_H_
#ifdef __cplusplus
extern "C" {
#endif
// Complete local fence.i and SBI remote fence.i on every other online hart.
// Synchronization failure is fatal: callers cannot safely continue with stale
// instructions. This global operation needs no caller-provided memory pointer.
void vibeos_native_flush_instruction_cache(void);
#ifdef __cplusplus
}
#endif
#endif
