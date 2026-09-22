// RV64 frame-pointer walk confined to the admitted stack. Not signal-safe.
#ifndef VIBEOS_NATIVE_BACKTRACE_H_
#define VIBEOS_NATIVE_BACKTRACE_H_
#include "vibeos-stack.h"
#include <stddef.h>
#include <stdint.h>
inline size_t VibeosCollectFrames(uintptr_t frame, VibeosStackBounds bounds,
                                  void** addresses, size_t capacity) {
  size_t count = 0;
  while (count < capacity) {
    // psABI: previous fp and return address occupy the two words below fp.
    // Check by subtraction to avoid overflowing a potentially corrupt value.
    if ((frame & 15) != 0 || frame > bounds.high || frame < bounds.low ||
        frame - bounds.low < 2 * sizeof(uintptr_t)) break;
    const auto* record = reinterpret_cast<const uintptr_t*>(frame);
    const uintptr_t previous = record[-2];
    const uintptr_t pc = record[-1];
    if (pc == 0) break;
    addresses[count++] = reinterpret_cast<void*>(pc);
    // Older frames must move strictly toward the stack's upper bound.
    if (previous <= frame) break;
    frame = previous;
  }
  return count;
}
#endif
