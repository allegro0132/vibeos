// Optional fixed-storage diagnostic; never allocates from the allocator being
// observed. Single native admission makes the recursion guard invocation-local.
#include "node-allocation-trace.h"
#ifdef VIBEOS_NODE_ALLOCATION_TRACE
#include "vibeos-backtrace.h"
#include "vibeos-sync.h"
#include <stddef.h>
#include <stdint.h>
namespace {
constexpr size_t kSlots = 65536;
struct Allocation { uintptr_t pointer; size_t size; int32_t born; void* frames[8]; };
Allocation entries[kSlots];
unsigned depth;
size_t overflow;
struct Guard { bool outer = depth++ == 0; ~Guard() { --depth; } };
size_t Hash(uintptr_t pointer) { return ((pointer >> 4) * 0x9e3779b97f4a7c15ULL) & (kSlots - 1); }
void Remove(uintptr_t pointer) {
  if (!pointer) return;
  for (size_t n = 0, i = Hash(pointer); n < kSlots; ++n, i = (i + 1) & (kSlots - 1)) {
    if (!entries[i].pointer) return;
    if (entries[i].pointer == pointer) { entries[i].pointer = 1; return; }
  }
}
__attribute__((noinline)) void Add(void* pointer, size_t size) {
  if (!pointer) return;
  const auto address = reinterpret_cast<uintptr_t>(pointer);
  for (size_t n = 0, i = Hash(address); n < kSlots; ++n, i = (i + 1) & (kSlots - 1)) {
    if (entries[i].pointer <= 1) {
      auto& entry = entries[i];
      entry.pointer = address; entry.size = size; entry.born = vibeos_native_thread_id();
      for (auto& pc : entry.frames) pc = nullptr;
      VibeosCollectFrames(reinterpret_cast<uintptr_t>(__builtin_frame_address(0)),
                          vibeos_native_stack_bounds(), entry.frames, 8);
      return;
    }
  }
  ++overflow;
}
}
struct _reent;
extern "C" {
void* __real_malloc(size_t);
void* __real_calloc(size_t, size_t);
void* __real_realloc(void*, size_t);
void* __real_memalign(size_t, size_t);
void __real_free(void*);
void* __real__malloc_r(_reent*, size_t);
void* __real__calloc_r(_reent*, size_t, size_t);
void* __real__realloc_r(_reent*, void*, size_t);
void* __real__memalign_r(_reent*, size_t, size_t);
void __real__free_r(_reent*, void*);
void* __real__Znwm(size_t);
void* __real__Znam(size_t);
#define ALLOCATE(name, params, args, size) \
void* __wrap_##name params { Guard guard; void* p = __real_##name args; \
  if (guard.outer) Add(p, size); return p; }
ALLOCATE(malloc, (size_t n), (n), n)
ALLOCATE(calloc, (size_t n, size_t s), (n,s), n*s)
ALLOCATE(memalign, (size_t a, size_t n), (a,n), n)
ALLOCATE(_malloc_r, (_reent* r, size_t n), (r,n), n)
ALLOCATE(_calloc_r, (_reent* r, size_t n, size_t s), (r,n,s), n*s)
ALLOCATE(_memalign_r, (_reent* r, size_t a, size_t n), (r,a,n), n)
// The toolchain's operator new omits frame pointers. Intercept its boundary
// so the recorded stack reaches the frame-pointer-enabled V8/Node callers.
ALLOCATE(_Znwm, (size_t n), (n), n)
ALLOCATE(_Znam, (size_t n), (n), n)
#undef ALLOCATE
#define REALLOCATE(name, params, args) \
void* __wrap_##name params { Guard guard; uintptr_t old = reinterpret_cast<uintptr_t>(p); \
  void* next = __real_##name args; if (guard.outer && (next || n == 0)) { Remove(old); Add(next,n); } return next; }
REALLOCATE(realloc, (void* p, size_t n), (p,n))
REALLOCATE(_realloc_r, (_reent* r, void* p, size_t n), (r,p,n))
#undef REALLOCATE
void __wrap_free(void* p) { Guard guard; if (guard.outer) Remove(reinterpret_cast<uintptr_t>(p)); __real_free(p); }
void __wrap__free_r(_reent* r, void* p) { Guard guard; if (guard.outer) Remove(reinterpret_cast<uintptr_t>(p)); __real__free_r(r,p); }
void vibeos_node_allocation_record(int32_t, size_t, size_t, const void*);
void vibeos_node_allocation_totals(size_t, size_t, size_t);
void vibeos_node_allocation_snapshot() {
  size_t count = 0, bytes = 0;
  const int32_t id = vibeos_native_thread_id();
  for (const auto& entry : entries) {
    if (entry.pointer <= 1) continue;
    ++count; bytes += entry.size;
    if (id > 1 && entry.born == id)
      vibeos_node_allocation_record(id, entry.pointer, entry.size, entry.frames);
  }
  vibeos_node_allocation_totals(count, bytes, overflow);
}
}
#else
extern "C" void vibeos_node_allocation_snapshot() {}
#endif
