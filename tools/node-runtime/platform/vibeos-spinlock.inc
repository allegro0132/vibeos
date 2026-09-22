// VibeOS implementation of Abseil's platform wait hooks.
// Waiting preserves the complete native stack and parks its execution task.
#include "vibeos-sync.h"
#include "absl/base/internal/errno_saver.h"
#include "absl/base/internal/raw_logging.h"

namespace {
struct VibeosSpinWait {
  std::atomic<uint32_t>* word;
  uint32_t expected;
};
int VibeosSpinReady(void* context) {
  const auto* wait = static_cast<const VibeosSpinWait*>(context);
  return wait->word->load(std::memory_order_acquire) != wait->expected;
}
}  // namespace

extern "C" {
void ABSL_INTERNAL_C_SYMBOL(AbslInternalSpinLockDelay)(
    std::atomic<uint32_t>* word, uint32_t value, int loop,
    absl::base_internal::SchedulingMode /* mode */) {
  absl::base_internal::ErrnoSaver save_errno;
  VibeosSpinWait wait{word, value};
  // Abseil permits wake-less callers, so preserve its bounded retry delay.
  // Both timeout and notification resume through the native task scheduler.
  const int64_t micros =
      (absl::base_internal::SpinLockSuggestedDelayNS(loop) + 999) / 1000;
  const int result = vibeos_native_wait_until_context(
      word, VibeosSpinReady, &wait, micros);
  ABSL_RAW_CHECK(result >= 0, "VibeOS native spin wait failed");
}
void ABSL_INTERNAL_C_SYMBOL(AbslInternalSpinLockWake)(
    std::atomic<uint32_t>* word, bool /* all */) {
  vibeos_native_wake_all(word);
}
}  // extern "C"
