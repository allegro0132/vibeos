#include "src/base/platform/platform.h"
#include "src/base/logging.h"
#include "vibeos-stack.h"

namespace v8::base {
Stack::StackSlot Stack::ObtainCurrentThreadStackStart() {
  const auto bounds = vibeos_native_stack_bounds();
  const auto frame = reinterpret_cast<uintptr_t>(__builtin_frame_address(0));
  CHECK_LE(bounds.low, frame);
  // A frame/CFA may equal the exclusive high address after a tail call.
  CHECK_LE(frame, bounds.high);
  return bounds.high;
}

Stack::StackSlot Stack::GetCurrentStackPosition() {
  return __builtin_frame_address(0);
}
}  // namespace v8::base
