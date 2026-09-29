#include "node-invocation.h"
#include "node-process.h"
#include "node.h"
#include "env-inl.h"
#include "uv.h"
#include "v8.h"
#include "v8-cppgc.h"
#include "libplatform/libplatform.h"
#include "vibeos-process.h"
#include <cstdio>
#include <string>
#include <vector>

namespace node { void SetIsolateCreateParamsForNode(v8::Isolate::CreateParams*); }
extern "C" int vibeos_node_run(unsigned argc, const char* const* argv,
                                const char* eval, size_t eval_length) {
  if (!argv || argc == 0 || argc > 128 || (!eval && eval_length) || eval_length > 1024 * 1024)
    return 64;
  const int initialized = vibeos::InitializeNodeProcess();
  if (initialized != 0) return initialized;
  std::vector<std::string> args;
  size_t argument_bytes = 0;
  for (unsigned i = 0; i < argc; ++i) {
    if (!argv[i]) return 64;
    size_t length = 0;
    while (length <= 65536 - argument_bytes && argv[i][length]) ++length;
    if (length > 65536 - argument_bytes) return 64;
    args.emplace_back(argv[i], length);
    argument_bytes += length;
  }
  auto* platform = vibeos::NodePlatform();
  uv_loop_t loop;
  if (uv_loop_init(&loop) != 0) return 70;
  auto allocator = node::ArrayBufferAllocator::Create();
  v8::Isolate::CreateParams params;
  params.array_buffer_allocator = allocator.get();
  params.cpp_heap = v8::CppHeap::Create(platform, v8::CppHeapCreateParams{{}}).release();
  node::SetIsolateCreateParamsForNode(&params);
  auto* isolate = v8::Isolate::New(params);
  if (!isolate) vibeos_native_fatal_exit(70);
  int result = 1;
  {
    v8::Isolate::Scope entered(isolate);
    v8::HandleScope handles(isolate);
    node::SetIsolateUpForNode(isolate);
    auto context = node::NewContext(isolate);
    v8::Context::Scope context_scope(context);
    auto* data = node::CreateIsolateData(isolate, &loop, nullptr, allocator.get());
    const auto flags = static_cast<node::EnvironmentFlags::Flags>(
        node::EnvironmentFlags::kNoNativeAddons |
        node::EnvironmentFlags::kNoGlobalSearchPaths |
        node::EnvironmentFlags::kTrackUnmanagedFds);
    std::vector<std::string> exec_args;
    if (eval) exec_args = {"-e", std::string(eval, eval_length)};
    auto* env = node::CreateEnvironment(data, context, args, exec_args, flags);
    if (env) {
      // Node's normal startup dispatch reads invocation-owned options. No
      // mutation of the shared process CLI options is needed for -e.
      if (eval) {
        env->options()->has_eval_string = true;
        env->options()->eval_string.assign(eval, eval_length);
      }
      bool exit_requested = false;
      node::SetProcessExitHandler(env, [&](node::Environment* current, int code) {
        result = code;
        exit_requested = true;
        node::Stop(current);
      });
      v8::TryCatch caught(isolate);
      auto loaded = node::LoadEnvironment(env, node::StartExecutionCallback{});
      if (!loaded.IsEmpty()) {
        for (;;) {
          if (exit_requested || vibeos_native_is_cancelled()) break;
          uv_run(&loop, UV_RUN_ONCE);
          if (exit_requested || vibeos_native_is_cancelled()) break;
          while (v8::platform::PumpMessageLoop(platform, isolate)) {
            if (vibeos_native_is_cancelled()) break;
          }
          if (vibeos_native_is_cancelled()) break;
          if (uv_loop_alive(&loop)) continue;
          if (node::EmitProcessBeforeExit(env).IsNothing()) break;
          if (!uv_loop_alive(&loop)) {
            result = node::EmitProcessExit(env).FromMaybe(1);
            break;
          }
        }
      }
      if (vibeos_native_is_cancelled()) {
        result = 130;
      } else if (caught.HasCaught() && !caught.HasTerminated() && !exit_requested) {
        node::FatalException(isolate, caught);
        if (!exit_requested) result = 1;
      }
      if (caught.HasTerminated() || isolate->IsExecutionTerminating()) {
        isolate->CancelTerminateExecution();
        caught.Reset();
      }
      node::Stop(env, node::StopFlags::kDoNotTerminateIsolate);
      node::FreeEnvironment(env);
    }
    node::FreeIsolateData(data);
  }
  v8::platform::NotifyIsolateShutdown(platform, isolate);
  isolate->Dispose();
  // A busy loop after full environment disposal is a trusted-runtime fault;
  // never return and release a stack still referenced by native callbacks.
  if (uv_loop_close(&loop) != 0) vibeos_native_fatal_exit(70);
  allocator.reset();
  return result;
}
