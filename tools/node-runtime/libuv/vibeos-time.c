/* Clocks and identity come from the admitted native invocation. */
#include "uv.h"
#include "vibeos-time.h"
#include "vibeos-sync.h"
#include "vibeos-memory.h"
#include <stdlib.h>

int uv_gettimeofday(uv_timeval64_t* output) {
  if (!output) return UV_EINVAL;
  int64_t us = vibeos_native_realtime_us();
  if (us < 0) return UV_EIO;
  output->tv_sec = us / 1000000;
  output->tv_usec = (int32_t) (us % 1000000);
  return 0;
}
int uv_clock_gettime(uv_clock_id id, uv_timespec64_t* output) {
  if (!output) return UV_EINVAL;
  int64_t us;
  switch (id) {
    case UV_CLOCK_MONOTONIC: us = vibeos_native_monotonic_us(); break;
    case UV_CLOCK_REALTIME: us = vibeos_native_realtime_us(); break;
    default: return UV_EINVAL;
  }
  if (us < 0) return UV_EIO;
  output->tv_sec = us / 1000000;
  output->tv_nsec = (int32_t) ((us % 1000000) * 1000);
  return 0;
}
int uv_uptime(double* output) {
  if (!output) return UV_EINVAL;
  int64_t us = vibeos_native_monotonic_us();
  if (us < 0) return UV_EIO;
  *output = (double) us / 1000000;
  return 0;
}
static int pending(void* context) { (void) context; return 0; }
void uv_sleep(unsigned int msec) {
  if (!msec) return;
  if (vibeos_native_wait_until_context(&msec, pending, NULL,
                                      (int64_t) msec * 1000) != 0) abort();
}
uv_thread_t uv_thread_self(void) {
  int32_t identity = vibeos_native_thread_id();
  if (identity <= 0) abort();
  return (uv_thread_t) identity;
}
int uv_thread_equal(const uv_thread_t* a, const uv_thread_t* b) {
  return *a == *b;
}
unsigned int uv_available_parallelism(void) {
  /* One active native task is admitted, independent of the machine hart count. */
  return 1;
}

uint64_t uv_get_total_memory(void) {
  uint64_t total, free_bytes;
  return vibeos_native_system_memory(&total, &free_bytes) ? 0 : total;
}
uint64_t uv_get_free_memory(void) {
  uint64_t total, free_bytes;
  return vibeos_native_system_memory(&total, &free_bytes) ? 0 : free_bytes;
}
uint64_t uv_get_constrained_memory(void) {
  /* libuv defines zero as unknown/no unified OS limit. The V8 page grant,
   * newlib arena and Rust service allocations have separate accounting;
   * reporting just one arena as a process-wide quota would be misleading. */
  return 0;
}
uint64_t uv_get_available_memory(void) {
  /* Same fallback as libuv platforms without a unified process constraint. */
  return uv_get_free_memory();
}
int uv_resident_set_memory(size_t* rss) {
  /* Shared kernel/image/TCB pages do not yet have a process RSS attribution. */
  return rss ? UV_ENOTSUP : UV_EINVAL;
}
