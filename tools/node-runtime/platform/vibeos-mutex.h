// Non-recursive BasicLockable adapter for libraries built without pthreads.
#ifndef VIBEOS_NATIVE_MUTEX_H_
#define VIBEOS_NATIVE_MUTEX_H_
#include <atomic>
#include "vibeos-sync.h"
#include "absl/base/internal/raw_logging.h"

class VibeosMutex {
 public:
  VibeosMutex() = default;
  ~VibeosMutex() {
    ABSL_RAW_CHECK(!held_.load(std::memory_order_relaxed),
                   "destroying locked native mutex");
  }
  VibeosMutex(const VibeosMutex&) = delete;
  VibeosMutex& operator=(const VibeosMutex&) = delete;
  void lock() {
    bool expected = false;
    while (!held_.compare_exchange_strong(expected, true,
                                          std::memory_order_acquire,
                                          std::memory_order_relaxed)) {
      // The predicate never acquires the lock. The bridge registers and
      // rechecks atomically before parking, so an unlock cannot be missed.
      ABSL_RAW_CHECK(vibeos_native_wait_until(this, [](void* key) -> int {
        return !static_cast<VibeosMutex*>(key)->held_.load(
            std::memory_order_acquire);
      }) == 0, "native mutex wait failed");
      expected = false;
    }
  }
  void unlock() {
    ABSL_RAW_CHECK(held_.exchange(false, std::memory_order_release),
                   "unlocking unheld native mutex");
    vibeos_native_wake_all(this);
  }
 private:
  // No invocation-owned handle: cctz keeps this mutex for process lifetime.
  std::atomic<bool> held_{false};
};
#endif
