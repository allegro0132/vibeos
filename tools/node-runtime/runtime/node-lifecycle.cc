// Audit the pinned newlib allocator after Node and TLS destructors return.
// This runs on the admitted native stack, where allocator locking/TLS is valid.
#include "node-lifecycle.h"
#include "node-allocation-trace.h"
#ifdef VIBEOS_NODE_LIFECYCLE_AUDIT
#include <stdint.h>
#include <stddef.h>
#include <reent.h>
#include <cstdlib>
// xPack GCC 14.2.0-3's LP64D libc.a returns ten 32-bit fields, although
// its installed malloc.h declares size_t fields. Bind the pinned binary ABI:
// _mallinfo_r writes offsets 0..36 with sw (40 bytes), not sd (80 bytes).
// Revalidate this shim when upgrading the locked toolchain.
struct PinnedMallinfo {
  int32_t arena, ordblks, smblks, hblks, hblkhd;
  int32_t usmblks, fsmblks, uordblks, fordblks, keepcost;
};
static_assert(sizeof(PinnedMallinfo) == 40);
extern "C" PinnedMallinfo pinned_mallinfo() asm("mallinfo");
extern "C" size_t malloc_usable_size(void*);
extern "C" void vibeos_node_libc_cache_record(size_t pointer, size_t chunk_bytes);
// Verified against this libc.a's _Balloc/_Bfree and _malloc_usable_size_r.
// _Balloc allocates 65 heads on RV64; _Bfree links unused blocks at offset 104.
static_assert(offsetof(_reent, _freelist) == 104);
static_assert(offsetof(_Bigint, _next) == 0 && offsetof(_Bigint, _k) == 8);
extern "C" void vibeos_node_libc_snapshot(size_t* output) {
  vibeos_node_allocation_snapshot();
  const PinnedMallinfo info = pinned_mallinfo();
  output[0] = info.arena;
  output[1] = info.uordblks;
  output[2] = info.fordblks;
  output[3] = info.ordblks;
  size_t cached_blocks = 0, cached_chunk_bytes = 0;
  if (_impure_ptr->_freelist) {
    for (size_t k = 0; k <= 8 * sizeof(size_t); ++k) {
      for (auto* block = _impure_ptr->_freelist[k]; block; block = block->_next) {
        // A corrupt or cyclic list must fail the audit, never silently truncate.
        if (block->_k != static_cast<int>(k) || ++cached_blocks > 65536) std::abort();
        const size_t usable = malloc_usable_size(block);
        // The fixed non-mmap dlmalloc ABI returns chunk_size - one size_t.
        if (!usable || usable > static_cast<size_t>(info.arena) - sizeof(size_t)) std::abort();
        const size_t chunk = usable + sizeof(size_t);
        cached_chunk_bytes += chunk;
        if (cached_chunk_bytes > static_cast<size_t>(info.uordblks)) std::abort();
        vibeos_node_libc_cache_record(reinterpret_cast<size_t>(block), chunk);
      }
    }
  }
  output[4] = cached_blocks;
  output[5] = cached_chunk_bytes;
}
#endif
