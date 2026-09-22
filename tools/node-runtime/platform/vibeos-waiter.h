// Abseil's per-task waiter backed by the VibeOS native execution bridge.
#ifndef VIBEOS_ABSEIL_WAITER_H_
#define VIBEOS_ABSEIL_WAITER_H_
#include <atomic>
#include <cstdint>
#include "vibeos-sync.h"
#include "absl/base/internal/raw_logging.h"
#include "absl/synchronization/internal/waiter_base.h"

namespace absl {
ABSL_NAMESPACE_BEGIN
namespace synchronization_internal {
class VibeosWaiter : public WaiterCrtp<VibeosWaiter> {
 public:
  static constexpr char kName[] = "VibeosWaiter";
  bool Wait(KernelTimeout timeout) {
    bool first = true;
    for (;;) {
      auto count = posts_.load(std::memory_order_relaxed);
      while (count != 0) {
        if (posts_.compare_exchange_weak(count, count - 1,
              std::memory_order_acquire, std::memory_order_relaxed)) return true;
      }
      if (!first) MaybeBecomeIdle();
      first = false;
      int64_t micros = -1;
      if (timeout.has_timeout()) {
        const int64_t nanos = timeout.ToChronoDuration().count();
        if (nanos <= 0) return false;
        micros = nanos / 1000 + (nanos % 1000 != 0);
      }
      Waiting state{this, pokes_.load(std::memory_order_acquire)};
      const int result = vibeos_native_wait_until_context(this, Ready, &state, micros);
      ABSL_RAW_CHECK(result >= 0, "VibeOS per-task wait failed");
      if (result == 0) return false;
      // A Poke only triggers an idle check; only Post supplies a permit.
    }
  }
  void Post() {
    const uint32_t old = posts_.fetch_add(1, std::memory_order_release);
    ABSL_RAW_CHECK(old != UINT32_MAX, "VibeOS waiter permit overflow");
    if (old == 0) vibeos_native_wake_all(this);
  }
  void Poke() {
    pokes_.fetch_add(1, std::memory_order_release);
    vibeos_native_wake_all(this);
  }
 private:
  struct Waiting { VibeosWaiter* waiter; uint64_t generation; };
  static int Ready(void* context) {
    auto* state = static_cast<Waiting*>(context);
    return state->waiter->posts_.load(std::memory_order_acquire) != 0 ||
           state->waiter->pokes_.load(std::memory_order_acquire) != state->generation;
  }
  std::atomic<uint32_t> posts_{0};
  std::atomic<uint64_t> pokes_{0};
};
using Waiter = VibeosWaiter;
}  // namespace synchronization_internal
ABSL_NAMESPACE_END
}  // namespace absl
#endif
