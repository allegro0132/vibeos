// The first port runs V8 through NewSingleThreadedDefaultPlatform.
#include "src/base/platform/platform.h"
#include "src/base/logging.h"
#include <cerrno>
#include <cstring>

namespace v8::base {
Thread::Thread(const Options& options)
    : data_(nullptr),
      stack_size_(options.stack_size()),
      priority_(options.priority()),
      start_semaphore_(nullptr) {
  set_name(options.name());
}

Thread::~Thread() { delete start_semaphore_; }

void Thread::set_name(const char* name) {
  std::strncpy(name_, name, sizeof(name_) - 1);
  name_[sizeof(name_) - 1] = '\0';
}

bool Thread::Start() {
  // StartSynchronously allocates a semaphore before calling Start. Returning
  // false must also release that handle, including across repeated attempts.
  delete start_semaphore_;
  start_semaphore_ = nullptr;
  errno = ENOTSUP;
  return false;
}

void Thread::Join() {
  FATAL("VibeOS: background V8 threads are unsupported");
}
}  // namespace v8::base
