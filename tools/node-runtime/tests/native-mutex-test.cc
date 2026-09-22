// Adapter unit test with a host blocking bridge. Not a VibeOS execution test.
#include "vibeos-mutex.h"
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <mutex>
#include <thread>
#include <vector>

namespace {
std::mutex wait_gate;
std::condition_variable changed;
std::atomic<unsigned> waits{0};
std::atomic<unsigned> parked{0};
}

extern "C" int vibeos_native_wait_until(void* key, int (*ready)(void*)) {
  std::unique_lock<std::mutex> guard(wait_gate);
  ++waits;
  ++parked;
  changed.wait(guard, [&] { return ready(key) != 0; });
  --parked;
  return 0;
}
extern "C" void vibeos_native_wake_all(void*) {
  // The same gate covers registration, predicate recheck and wake publication.
  std::lock_guard<std::mutex> guard(wait_gate);
  changed.notify_all();
}

int main() {
  VibeosMutex mutex;
  unsigned counter = 0;
  mutex.lock();
  std::vector<std::thread> workers;
  for (unsigned i = 0; i < 4; ++i) {
    workers.emplace_back([&] {
      for (unsigned n = 0; n < 10000; ++n) {
        std::lock_guard<VibeosMutex> guard(mutex);
        ++counter;
      }
    });
  }
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  while (parked.load() != 4 && std::chrono::steady_clock::now() < deadline) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  assert(parked.load() == 4);  // Contenders reach the blocking bridge.
  mutex.unlock();
  for (auto& worker : workers) worker.join();
  assert(counter == 40000);
  assert(parked.load() == 0);
  // Reuse the process-lifetime object after every caller has returned. There
  // is no invocation-owned semaphore handle left behind by this mutex.
  { std::lock_guard<VibeosMutex> guard(mutex); ++counter; }
  assert(counter == 40001);
  std::printf("native mutex adapter PASS: 40000 contended increments, %u waits, zero parked callers\n", waits.load());
}
