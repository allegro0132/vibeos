// VibeOS static-image lifecycle. Fatal process exits are not isolate teardown.
#include "src/base/platform/platform.h"
#include "src/base/abort-mode.h"
#include "src/base/immediate-crash.h"
#include <cstdio>
#include <cstdlib>
#include <unistd.h>

namespace v8::base {
void OS::Initialize(AbortMode mode, const char* /* gc_fake_mmap */) {
  g_abort_mode = mode;
  // V8 supplies a Linux profiler filename even when profiling is disabled.
  // This platform never opens it or emits Linux mmap notifications.
}
int OS::ActivationFrameAlignment() { return 16; }  // RV64 psABI, including LP64D.
void OS::AdjustSchedulingParams() {
  // The VibeOS executor owns scheduling; there is no process-priority API.
}
std::vector<OS::SharedLibraryAddress> OS::GetSharedLibraryAddresses() {
  // All native code belongs to the statically linked trusted image. There is
  // no dynamic loader and therefore no shared-library mapping to enumerate.
  return {};
}
void OS::SignalCodeMovingGC() {
  // External sampling/profiler integration is unsupported by this port.
}
void OS::Abort() {
  switch (g_abort_mode) {
    case AbortMode::kExitWithSuccessAndIgnoreDcheckFailures: _exit(0);
    case AbortMode::kExitWithFailureAndIgnoreDcheckFailures: _exit(-1);
    case AbortMode::kImmediateCrash: IMMEDIATE_CRASH();
    case AbortMode::kDefault: break;
  }
  std::abort();
}
void OS::DebugBreak() { asm volatile("ebreak" ::: "memory"); }
void OS::ExitProcess(int code) {
  std::fflush(stdout);
  std::fflush(stderr);
  // Do not use exit(), run global destructors, or jump across C++ frames.
  // The kernel's _exit backend must terminate the trusted image. Normal
  // invocation completion returns through the native runner instead.
  _exit(code);
}
}  // namespace v8::base
