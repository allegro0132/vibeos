#ifndef VIBEOS_NATIVE_STACK_H_
#define VIBEOS_NATIVE_STACK_H_
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct { uintptr_t low; uintptr_t high; } VibeosStackBounds;
// Bounds of the admitted native task's usable downward-growing stack.
// high is exclusive; the guard page is excluded. Fails fatally outside entry.
VibeosStackBounds vibeos_native_stack_bounds(void);
#ifdef __cplusplus
}
#endif
#endif
