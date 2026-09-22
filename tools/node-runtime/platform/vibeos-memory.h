// Invocation-owned native pages. The Rust bridge must enforce ownership and
// current grants on every operation, including partial-range operations.
#ifndef VIBEOS_NATIVE_MEMORY_H_
#define VIBEOS_NATIVE_MEMORY_H_
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define VIBEOS_NATIVE_PAGE_SIZE 4096u
enum VibeosPagePermission {
  VIBEOS_PAGE_NONE = 0,
  VIBEOS_PAGE_READ = 1,
  VIBEOS_PAGE_READ_WRITE = 2
};
// Hint is advisory. Reserve physical backing eagerly, return aligned and
// initially zeroed bytes. All data mappings are NX. Null means failure.
void* vibeos_native_pages_allocate(void* hint, size_t size, size_t alignment,
                                   int permission);
// Release the specified owned page range; partial tail releases are valid.
// Restore allocator access before returning the physical backing to its pool.
int vibeos_native_pages_release(void* address, size_t size);
// Each integer operation returns zero on success, negative on failure. On
// failure leave the range unchanged. Permission changes include TLB shootdown.
int vibeos_native_pages_protect(void* address, size_t size, int permission);
// Discard destroys contents, preserving reservation and current permissions.
int vibeos_native_pages_discard(void* address, size_t size);
// Decommit keeps the owned address reservation, makes it inaccessible and
// guarantees zero-filled contents if later recommitted using protect().
int vibeos_native_pages_decommit(void* address, size_t size);
// V8 freezes its statically linked flag block during initialization. This is
// separate from invocation-owned heap pages: accept only registered V8 image
// data, make it RO/NX, and forbid later writes through the heap protect API.
int vibeos_native_static_readonly(void* address, size_t size);
// Optional placement hints only; never used as the engine's entropy source.
void vibeos_native_page_hint_seed(int64_t seed);
void* vibeos_native_page_hint(void);
#ifdef __cplusplus
}
#endif
#endif
