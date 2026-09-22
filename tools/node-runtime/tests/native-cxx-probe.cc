// Target-only ABI/RAII probe, intentionally independent of the C++ library.
// The complete V8/Node port must separately link and qualify its static TCB.
#include "../platform/vibeos-cache.h"
#include "../platform/vibeos-time.h"
#include "../platform/vibeos-sync.h"
#include "../platform/vibeos-backtrace.h"
#include "../platform/vibeos-memory.h"
#include "../platform/vibeos-stack.h"
#include "../platform/vibeos-tcb-pages.h"
static_assert(sizeof(unsigned long) == 8);
alignas(64) static thread_local volatile unsigned long tls_initialized = 0x51a7;
alignas(64) static thread_local volatile unsigned long tls_zero;
static thread_local int32_t tls_task_id;
extern "C" unsigned long vibeos_native_cxx_tls_probe(unsigned long expected) {
  const auto id = vibeos_native_thread_id();
  if (id <= 0 || (tls_task_id != 0 && tls_task_id != id)) return 0;
  tls_task_id = id;
  const auto stack = vibeos_native_stack_bounds();
  const auto frame = reinterpret_cast<unsigned long>(__builtin_frame_address(0));
  void* frames[8];
  if (VibeosCollectFrames(frame, stack, frames, 8) == 0) return 0;
  if (VibeosCollectFrames(stack.low, stack, frames, 8) != 0 ||
      VibeosCollectFrames(stack.high + 16, stack, frames, 8) != 0 ||
      VibeosCollectFrames(frame + 1, stack, frames, 8) != 0 ||
      VibeosCollectFrames(frame, stack, frames, 0) != 0) return 0;
  // The frame/CFA can equal high after a tail call; actual stack storage
  // must still lie strictly below high.
  volatile unsigned char stack_slot = 0;
  const auto slot = reinterpret_cast<unsigned long>(&stack_slot);
  if (frame < stack.low || frame > stack.high || slot < stack.low ||
      slot >= stack.high || stack.high - stack.low != 256 * 1024) return 0;
  if (tls_initialized != 0x51a7 + expected || tls_zero != expected) return 0;
  if (reinterpret_cast<unsigned long>(&tls_initialized) % 64 != 0 ||
      reinterpret_cast<unsigned long>(&tls_zero) % 64 != 0) return 0;
  tls_initialized = tls_initialized + 1;
  tls_zero = tls_zero + 1;
  return 42;
}
using TlsEvent = void (*)(void*, unsigned long);
struct DynamicValue {
  void* context;
  TlsEvent event;
  unsigned long id;
  DynamicValue(void* context, TlsEvent event, unsigned long id)
      : context(context), event(event), id(id) { event(context, id); }
  ~DynamicValue() { event(context, tls_zero == 4 ? 100 + id : 999); }
};
static bool DynamicValues(void* context, TlsEvent event) {
  thread_local DynamicValue first(context, event, 1);
  thread_local DynamicValue second(context, event, 2);
  return first.context == context && second.context == context &&
         first.id == 1 && second.id == 2;
}
extern "C" unsigned long vibeos_native_cxx_probe(
    void* context, void (*yield)(void*, unsigned long), void (*drop)(void*),
    TlsEvent event) {
  struct Guard {
    void* context;
    void (*drop)(void*);
    ~Guard() { drop(context); }
  } guard{context, drop};
  vibeos_native_flush_instruction_cache();
  auto* owned = static_cast<unsigned char*>(vibeos_native_pages_allocate(nullptr, 16384, 4096, 2));
  if (!owned) return 0;
  owned[0] = 0xa5;
  owned[8192] = 0x5a;
  if (vibeos_native_pages_release(owned + 8192, 8192) != 0) return 0;
  auto* tail = static_cast<unsigned char*>(vibeos_native_pages_allocate(nullptr, 8192, 4096, 2));
  if (tail != owned + 8192 || owned[0] != 0xa5 || tail[0] != 0) return 0;
  if (vibeos_native_pages_release(owned, 16384) == 0 ||
      vibeos_native_pages_protect(owned, 8192, 3) == 0) return 0;
  if (vibeos_native_pages_decommit(owned, 8192) != 0 ||
      vibeos_native_pages_protect(owned, 8192, 1) != 0 || owned[0] != 0) return 0;
  if (vibeos_native_pages_discard(tail, 8192) != 0 ||
      vibeos_native_pages_release(tail, 8192) != 0 ||
      vibeos_native_pages_release(owned, 8192) != 0 ||
      vibeos_native_pages_release(owned, 8192) == 0) return 0;
  auto* pages = static_cast<unsigned char*>(vibeos_tcb_pages_allocate(8192));
  if (!pages) return 0;
  for (unsigned long i = 0; i != 8192; ++i) if (pages[i] != 0) return 0;
  pages[0] = 0xa5;
  if (vibeos_tcb_pages_release(pages, 4096) == 0 ||
      vibeos_tcb_pages_release(pages, 12288) == 0 || pages[0] != 0xa5) return 0;
  if (vibeos_tcb_pages_release(pages, 8192) != 0 ||
      vibeos_tcb_pages_release(pages, 8192) == 0) return 0;
  if (vibeos_native_cxx_tls_probe(0) != 42 || !DynamicValues(context, event)) return 0;
  const auto realtime = vibeos_native_realtime_us();
  auto monotonic = vibeos_native_monotonic_us();
  if (realtime <= 0 || monotonic < 0) return 0;
  volatile double seed = 1.5;
  double value = seed;
  for (unsigned long step = 1; step <= 3; ++step) {
    yield(context, step);
    const auto after = vibeos_native_monotonic_us();
    if (after < monotonic ||
        vibeos_native_realtime_us() < realtime) return 0;
    monotonic = after;
    if (vibeos_native_cxx_tls_probe(step) != 42 || !DynamicValues(context, event)) return 0;
    value *= 2.0;
  }
  return value == 12.0 ? 42 : 0;
}

extern "C" int vibeos_native_probe_schedule_post(void*);
static int NeverReady(void*) { return 0; }
static int AlwaysReady(void*) { return 1; }
extern "C" unsigned long vibeos_native_cxx_wait_probe() {
  unsigned drops = 0;
  struct WaitGuard { unsigned* drops; ~WaitGuard() { ++*drops; } };
  const auto id = vibeos_native_thread_id();
  const auto start = vibeos_native_monotonic_us();
  {
    WaitGuard guard{&drops};
    int key;
    if (vibeos_native_wait_until_context(&key, AlwaysReady, nullptr, -1) != 1 ||
        vibeos_native_wait_until_context(&key, NeverReady, nullptr, 0) != 0 ||
        vibeos_native_wait_until_context(&key, NeverReady, nullptr, -2) != -1) return 0;
    for (unsigned i = 0; i < 2; ++i) {
      if (vibeos_native_wait_until_context(&key, NeverReady, nullptr, 3000) != 0 ||
          vibeos_native_thread_id() != id || drops != 0) return 0;
    }
  }
  auto* sem = vibeos_native_semaphore_create(1);
  if (!sem || vibeos_native_semaphore_create(-1) != nullptr) return 0;
  if (vibeos_native_semaphore_wait(sem, 0) != 1 ||
      vibeos_native_semaphore_wait(sem, 0) != 0 ||
      vibeos_native_semaphore_wait(sem, 3000) != 0 ||
      vibeos_native_semaphore_signal(sem) != 0 ||
      vibeos_native_semaphore_wait(sem, -1) != 1) return 0;
  if (vibeos_native_probe_schedule_post(sem) != 0 ||
      vibeos_native_semaphore_wait(sem, -1) != 1 ||
      vibeos_native_semaphore_wait(sem, 0) != 0) return 0;
  vibeos_native_semaphore_destroy(sem);
  if (vibeos_native_semaphore_signal(sem) != -1 ||
      vibeos_native_semaphore_wait(sem, 0) != -1) return 0;
  auto* full = vibeos_native_semaphore_create(2147483647);
  if (!full || vibeos_native_semaphore_signal(full) != -1) return 0;
  vibeos_native_semaphore_destroy(full);
  return drops == 1 && vibeos_native_monotonic_us() - start >= 9000 ? 42 : 0;
}
