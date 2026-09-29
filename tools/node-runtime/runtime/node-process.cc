#include "node-process.h"
#include "node.h"
#include "v8.h"
#include "cppgc/platform.h"
#include "libplatform/libplatform.h"
#include "vibeos-entropy.h"
#include "vibeos-process.h"
#include "vibeos-memory.h"
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <memory>

namespace {
// 0 cold, 1 initializing, 2 ready, 3 closed/failed. Reinitialization is invalid.
std::atomic<unsigned> state{0};
std::shared_ptr<node::InitializationResult> initialization;
std::unique_ptr<v8::Platform> platform;
struct ProcessPages {
  ProcessPages() { if (vibeos_native_process_pages_scope(1) != 0) std::abort(); }
  ~ProcessPages() { if (vibeos_native_process_pages_scope(0) != 0) std::abort(); }
};
bool Entropy(unsigned char* bytes, size_t length) {
  if (vibeos_native_entropy(bytes, length) != 0) std::abort();
  return true;
}
}
namespace vibeos {
int InitializeNodeProcess() {
  if (vibeos_native_runtime_initialize() != 0) return 3;
  unsigned expected = 0;
  if (!state.compare_exchange_strong(expected, 1)) return expected == 2 ? 0 : 2;
  ProcessPages process_pages;
  initialization = node::InitializeOncePerProcess({"node", "--jitless"},
      node::ProcessInitializationFlags::kLegacyInitializeNodeWithArgsBehavior);
  for (const auto& error : initialization->errors()) std::fprintf(stderr, "%s\n", error.c_str());
  if (initialization->early_return()) {
    state.store(3);
    return initialization->exit_code() ? initialization->exit_code() : 4;
  }
  v8::V8::SetFlagsFromString("--jitless --single-threaded --max-old-space-size=128");
  v8::V8::SetEntropySource(Entropy);
  platform = v8::platform::NewSingleThreadedDefaultPlatform();
  v8::V8::InitializePlatform(platform.get());
  if (!v8::V8::Initialize()) { state.store(3); return 5; }
  // The pinned V8 initializes cppgc itself.
  state.store(2);
  return 0;
}
v8::Platform* NodePlatform() {
  if (state.load() != 2) std::abort();
  return platform.get();
}
void ShutdownNodeProcess() {
  unsigned expected = 2;
  if (!state.compare_exchange_strong(expected, 3)) std::abort();
  // Caller has destroyed every environment, isolate and event loop normally.
  v8::V8::Dispose();
  v8::V8::DisposePlatform();
  cppgc::ShutdownProcess();
  node::TearDownOncePerProcess();
  platform.reset();
  initialization.reset();
}
}
