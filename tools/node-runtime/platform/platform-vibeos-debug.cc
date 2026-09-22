// Raw addresses can be symbolized offline against the exact kernel ELF.
#include "src/base/debug/stack_trace.h"
#include "src/base/platform/platform.h"
#include "vibeos-backtrace.h"
#include <cerrno>
#include <ostream>

namespace v8::base::debug {
bool EnableInProcessStackDumping() {
  errno = ENOTSUP;
  return false;  // No Unix signals or signal-handler unwinding on VibeOS.
}
void DisableSignalStackDump() {}  // Enabling is always rejected.
StackTrace::StackTrace() {
  count_ = VibeosCollectFrames(
      reinterpret_cast<uintptr_t>(__builtin_frame_address(0)),
      vibeos_native_stack_bounds(), trace_, kMaxTraces);
}
void StackTrace::Print() const {
  for (size_t i = 0; i < count_; ++i)
    OS::PrintError("#%zu %p\n", i, trace_[i]);
}
void StackTrace::OutputToStream(std::ostream* out) const {
  for (size_t i = 0; i < count_; ++i) *out << '#' << i << ' ' << trace_[i] << '\n';
}
}  // namespace v8::base::debug
