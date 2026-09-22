// One-shot, target-only V8 gate. Compile/link is NOT a passing execution gate.
#include "v8.h"
#include "libplatform/libplatform.h"
#include "vibeos-entropy.h"
#include "vibeos-process.h"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>

namespace {
std::atomic<bool> started{false};

bool Entropy(unsigned char* bytes, size_t length) {
  if (vibeos_native_entropy(bytes, length) != 0) {
    std::fputs("V8 SMOKE entropy unavailable\n", stderr);
    std::abort();
  }
  return true;
}

void CountGC(v8::Isolate*, v8::GCType, v8::GCCallbackFlags, void* data) {
  ++*static_cast<unsigned*>(data);
}

bool RunChecks(v8::Isolate* isolate) {
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope handles(isolate);
  auto context = v8::Context::New(isolate);
  if (context.IsEmpty()) return false;
  v8::Context::Scope context_scope(context);
  {
    v8::TryCatch caught(isolate);
    v8::Local<v8::Script> script;
    v8::Local<v8::Value> result;
    if (!v8::Script::Compile(context, v8::String::NewFromUtf8Literal(
            isolate, "6 * 7")).ToLocal(&script) ||
        !script->Run(context).ToLocal(&result) ||
        result->Int32Value(context).FromMaybe(-1) != 42) return false;
    std::puts("V8 SMOKE expression=42 PASS");
  }
  {
    v8::TryCatch caught(isolate);
    v8::Local<v8::Script> script;
    v8::Local<v8::Value> ignored;
    if (!v8::Script::Compile(context, v8::String::NewFromUtf8Literal(
            isolate, "throw new Error('vibeos-v8-smoke')")).ToLocal(&script))
      return false;
    if (script->Run(context).ToLocal(&ignored) || !caught.HasCaught())
      return false;
    v8::String::Utf8Value exception(isolate, caught.Exception());
    if (!*exception || !std::strstr(*exception, "vibeos-v8-smoke")) return false;
    std::puts("V8 SMOKE exception=Error:vibeos-v8-smoke PASS");
  }
  {
    v8::HandleScope temporary_handles(isolate);
    v8::TryCatch caught(isolate);
    v8::Local<v8::Script> script;
    v8::Local<v8::Value> result;
    if (!v8::Script::Compile(context, v8::String::NewFromUtf8Literal(isolate,
            "(() => { const a = []; for (let i = 0; i < 20000; ++i) "
            "a.push({i, text: String(i)}); return a.length; })()"))
             .ToLocal(&script) || !script->Run(context).ToLocal(&result) ||
        result->Int32Value(context).FromMaybe(-1) != 20000) return false;
  }
  unsigned collections = 0;
  isolate->AddGCPrologueCallback(CountGC, &collections);
  isolate->RequestGarbageCollectionForTesting(v8::Isolate::kFullGarbageCollection);
  isolate->RemoveGCPrologueCallback(CountGC, &collections);
  if (collections == 0) return false;
  v8::HeapStatistics heap;
  isolate->GetHeapStatistics(&heap);
  std::printf("V8 SMOKE gc_callbacks=%u heap_used=%zu PASS\n",
              collections, heap.used_heap_size());
  return true;
}
}  // namespace

// The kernel must call this on the protected native stack after setting up
// FP state, TLS, allocator, clocks, entropy, stdio and suspendable wait bridges.
// This one-shot gate disposes process-global V8 and cannot be used as a Node
// invocation implementation or for the later 100-invocation lifecycle test.
extern "C" int vibeos_v8_smoke() {
  if (started.exchange(true)) return 2;
  if (vibeos_native_runtime_initialize() != 0) return 4;
  v8::V8::SetFlagsFromString(
      "--jitless --single-threaded --expose-gc --max-old-space-size=128");
  v8::V8::SetEntropySource(Entropy);
  auto platform = v8::platform::NewSingleThreadedDefaultPlatform();
  v8::V8::InitializePlatform(platform.get());
  if (!v8::V8::Initialize()) {
    v8::V8::DisposePlatform();
    return 3;
  }
  auto allocator = std::unique_ptr<v8::ArrayBuffer::Allocator>(
      v8::ArrayBuffer::Allocator::NewDefaultAllocator());
  v8::Isolate::CreateParams parameters;
  parameters.array_buffer_allocator = allocator.get();
  auto* isolate = v8::Isolate::New(parameters);
  bool passed = false;
  if (isolate) {
    passed = RunChecks(isolate);
    v8::platform::NotifyIsolateShutdown(platform.get(), isolate);
    isolate->Dispose();
  }
  v8::V8::Dispose();
  v8::V8::DisposePlatform();
  std::puts(passed ? "V8 SMOKE teardown PASS" : "V8 SMOKE FAILED");
  std::fflush(stdout);
  std::fflush(stderr);
  return passed ? 0 : 1;
}
