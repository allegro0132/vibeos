// VibeOS time and execution identity. All waits park the native task.
#include "src/base/platform/platform.h"
#include "src/base/platform/time.h"
#include "src/base/logging.h"
#include "vibeos-sync.h"
#include <cerrno>

namespace v8::base {
namespace {
int NeverReady(void*) { return 0; }
}

double OS::TimeCurrentMillis() { return Time::Now().ToJsTime(); }

void OS::Sleep(TimeDelta interval) {
  const int64_t micros = interval.InMicroseconds();
  if (micros <= 0) return;
  // The key remains alive on the suspended stack. A spurious wake must not
  // shorten the delay: the bridge rechecks NeverReady until its deadline.
  char key;
  CHECK_EQ(0, vibeos_native_wait_until_context(&key, NeverReady, nullptr,
                                              micros));
}

int OS::GetCurrentThreadIdInternal() {
  const int32_t id = vibeos_native_thread_id();
  CHECK_GT(id, 0);
  return id;
}

int OS::GetLastError() { return errno; }
}  // namespace v8::base
