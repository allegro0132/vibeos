// Process-lifetime pages for the statically trusted C++ runtime's arenas.
// These are not invocation heap grants; they need separate accounting/ownership.
#ifndef VIBEOS_TCB_PAGES_H_
#define VIBEOS_TCB_PAGES_H_
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
// Eager, zeroed, 4096-byte-aligned RW/NX pages. Null indicates failure.
void* vibeos_tcb_pages_allocate(size_t size);
// Release an owned page range, including coalesced adjacent arena allocations.
// Return zero only after actual reclamation; negative means failure.
int vibeos_tcb_pages_release(void* address, size_t size);
#ifdef __cplusplus
}
#endif
#endif
