// VibeOS native-runtime synchronization ABI. Implemented by the Rust bridge.
// This header deliberately provides no POSIX aliases or fallback spin loops.
#ifndef VIBEOS_NATIVE_SYNC_H_
#define VIBEOS_NATIVE_SYNC_H_
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

// A handle is private to its active runtime invocation. Destruction is called
// only after all users have returned from their C++ frames.
void* vibeos_native_semaphore_create(int count);
void vibeos_native_semaphore_destroy(void* semaphore);
int vibeos_native_semaphore_signal(void* semaphore);
// Must suspend the native execution task while unavailable, not the scheduler.
// timeout_us: -1 means indefinite; 0 means try; positive values are relative.
// Returns 1 after acquiring a permit, 0 on timeout, or -1 on platform failure.
int vibeos_native_semaphore_wait(void* semaphore, int64_t timeout_us);

// Atomically register a waiter and recheck ready(key) before parking. A wake
// may be spurious, so the bridge must recheck before returning. No waiter or
// callback can survive this call. Returns 0 on readiness, -1 on platform error.
int vibeos_native_wait_until(void* key, int (*ready)(void*));
void vibeos_native_wake_all(void* key);
// Positive identity for the current native execution task; never a hart ID.
int32_t vibeos_native_thread_id(void);
// Timed form with separate callback context. The context may live on the
// suspended native stack; the bridge must not retain it after returning.
// Returns 1 on readiness, 0 on timeout, -1 on platform failure.
int vibeos_native_wait_until_context(void* key, int (*ready)(void*),
                                    void* context, int64_t timeout_us);

#ifdef __cplusplus
}
#endif
#endif
