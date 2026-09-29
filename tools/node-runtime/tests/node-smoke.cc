// Target-only, one-shot Node embedding gate. Not the production launcher.
#include "node.h"
#include "node-process.h"
#include "node-invocation.h"
#include "uv.h"
#include "v8.h"
#include "v8-cppgc.h"
#include "cppgc/platform.h"
#include "libplatform/libplatform.h"
#include "vibeos-entropy.h"
#include "vibeos-process.h"
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <string>
#ifndef VIBEOS_NODE_EXPECTED_EXIT_CODE
#define VIBEOS_NODE_EXPECTED_EXIT_CODE 0
#endif
#ifndef VIBEOS_NODE_EXPLICIT_EXIT
#define VIBEOS_NODE_EXPLICIT_EXIT 0
#endif

#ifndef VIBEOS_NODE_ENTRY
#define VIBEOS_NODE_ENTRY 0
#endif
#ifndef VIBEOS_NODE_IDLE_CANCEL
#define VIBEOS_NODE_IDLE_CANCEL 0
#endif
#ifndef VIBEOS_NODE_REPEAT
#define VIBEOS_NODE_REPEAT 1
#endif
#ifndef VIBEOS_NODE_REVOKE
#define VIBEOS_NODE_REVOKE 0
#endif
#ifndef VIBEOS_NODE_MAIN
#define VIBEOS_NODE_MAIN 0
#endif
#ifndef VIBEOS_NODE_CANCEL
#define VIBEOS_NODE_CANCEL 0
#endif

// Locked Node internal helper used by its own NewIsolate. We supply a
// single-threaded V8 platform; no Node worker pool or user workers are created.
namespace node { void SetIsolateCreateParamsForNode(v8::Isolate::CreateParams*); }
namespace {
std::atomic<unsigned> invocations{0};

}
static bool result_equals(v8::Local<v8::Context> context, const char* name, int expected) {
  auto* isolate = context->GetIsolate();
  v8::Local<v8::Value> value;
  return context->Global()->Get(context,
      v8::String::NewFromUtf8(isolate, name).ToLocalChecked()).ToLocal(&value) &&
      value->Int32Value(context).FromMaybe(-1) == expected;
}
static bool script_completed(v8::Local<v8::Context> context) {
  return result_equals(context, "__vibeosNodeResult", 42) &&
         result_equals(context, "__vibeosNodeWorkResult", 1) &&
         result_equals(context, "__vibeosNodeProjectResult", 1) &&
         result_equals(context, "__vibeosNodeStdinResult", 1);
}
extern "C" void vibeos_node_probe_finished(int status, int exit_code, int explicit_exit, int cancelled);
extern "C" void vibeos_node_cancel_probe_arm();
extern "C" void vibeos_node_idle_cancel_probe_arm();
extern "C" void vibeos_node_cpu_cancel_probe_arm();
extern "C" void vibeos_node_probe_repeat(unsigned remaining);
extern "C" void vibeos_node_probe_revoke_files();
// Existing native gate ABI; a Node-specific QEMU verifier must check NODE
// markers. The V8-only verifier is deliberately insufficient for this image.
extern "C" int vibeos_v8_smoke() {
  const unsigned invocation = invocations.fetch_add(1);
  if (invocation >= VIBEOS_NODE_REPEAT) return 2;
  vibeos_node_probe_repeat(VIBEOS_NODE_REPEAT - invocation - 1);
  const int initialized = vibeos::InitializeNodeProcess();
  if (initialized != 0) return initialized;
  auto* platform = vibeos::NodePlatform();
  if (VIBEOS_NODE_ENTRY) {
    const std::string exit_code = std::to_string(VIBEOS_NODE_EXPECTED_EXIT_CODE);
    const std::string explicit_exit = std::to_string(VIBEOS_NODE_EXPLICIT_EXIT);
    const char* argv[] = {"node", VIBEOS_NODE_ENTRY == 2 ? "gate.js" : "/main.cjs",
                          exit_code.c_str(), explicit_exit.c_str()};
    std::string eval_source;
    if (VIBEOS_NODE_ENTRY == 2) {
      eval_source = "if (typeof require !== 'function' || process.argv[1] !== 'gate.js' || "
          "process.execArgv[0] !== '-e') throw Error('eval bootstrap');"
          "console.log('NODE EVAL require=1 argv=1 PASS');process.exitCode=" + exit_code +
          ";globalThis.__vibeosRequestExit=" + explicit_exit + ";\n" +
#include "node-project-smoke.inc"
      ;
    }
    if (VIBEOS_NODE_IDLE_CANCEL) {
      eval_source = "setTimeout(() => { throw Error('idle cancellation missed'); }, 60000);";
      vibeos_node_idle_cancel_probe_arm();
    }
    if (VIBEOS_NODE_CANCEL) {
      eval_source += R"JS(
        function enterInfinite() {
          if (__vibeosNodeResult !== 42 || __vibeosNodeWorkResult !== 1 ||
              __vibeosNodeProjectResult !== 1 || __vibeosNodeStdinResult !== 1) {
            setTimeout(enterInfinite, 2); return;
          }
          let announced = false;
          try {
            for (;;) {
              if (!announced) {
                console.log('NODE CPU CANCEL entered_loop=1');
                announced = true;
              }
            }
          } finally { console.log('NODE CPU CANCEL unexpected_finally=1'); }
          console.log('NODE CPU CANCEL unexpected_return=1');
        }
        setTimeout(enterInfinite, 2);
      )JS";
      vibeos_node_cpu_cancel_probe_arm();
    }
    const int result = vibeos_node_run(4, argv,
        VIBEOS_NODE_ENTRY == 2 ? eval_source.data() : nullptr, eval_source.size());
    if (invocation + 1 == VIBEOS_NODE_REPEAT) vibeos::ShutdownNodeProcess();
    vibeos_node_probe_finished(result == VIBEOS_NODE_EXPECTED_EXIT_CODE ? 0 : 1,
        result, VIBEOS_NODE_EXPLICIT_EXIT, VIBEOS_NODE_CANCEL);
    return result;
  }
  uv_loop_t loop;
  if (uv_loop_init(&loop) != 0) return 6;
  auto allocator = node::ArrayBufferAllocator::Create();
  v8::Isolate::CreateParams params;
  params.array_buffer_allocator = allocator.get();
  params.cpp_heap = v8::CppHeap::Create(platform, v8::CppHeapCreateParams{{}}).release();
  node::SetIsolateCreateParamsForNode(&params);
  auto* isolate = v8::Isolate::New(params);
  if (!isolate) return 7;
  bool passed = false;
  int observed_exit = -1;
  {
    v8::Isolate::Scope scope(isolate);
    v8::HandleScope handles(isolate);
    node::SetIsolateUpForNode(isolate);
    auto context = node::NewContext(isolate);
    v8::Context::Scope context_scope(context);
    auto* data = node::CreateIsolateData(isolate, &loop, nullptr, allocator.get());
    auto flags = static_cast<node::EnvironmentFlags::Flags>(
        node::EnvironmentFlags::kNoNativeAddons |
        node::EnvironmentFlags::kNoGlobalSearchPaths |
        node::EnvironmentFlags::kTrackUnmanagedFds);
    const std::vector<std::string> argv = VIBEOS_NODE_MAIN ?
        std::vector<std::string>{"node", "/main.cjs", std::to_string(VIBEOS_NODE_EXPECTED_EXIT_CODE),
                                 std::to_string(VIBEOS_NODE_EXPLICIT_EXIT)} :
        std::vector<std::string>{"node", "gate.js"};
    auto* env = node::CreateEnvironment(data, context, argv, {}, flags);
    if (env) {
      int exit_code = 0;
      bool exit_requested = false, exit_checks = false;
      node::SetProcessExitHandler(env, [&](node::Environment* current, int code) {
        exit_code = code;
        exit_requested = true;
        exit_checks = script_completed(context) && result_equals(context, "__vibeosExitEvent", code);
        node::Stop(current);
      });
      v8::TryCatch caught(isolate);
      const std::string script = "process.exitCode = " +
          std::to_string(VIBEOS_NODE_EXPECTED_EXIT_CODE) + ";globalThis.__vibeosRequestExit = " +
          std::to_string(VIBEOS_NODE_EXPLICIT_EXIT) + ";\n" +
#include "node-project-smoke.inc"
      ;
      auto loaded = VIBEOS_NODE_MAIN ?
          node::LoadEnvironment(env, node::StartExecutionCallback{}) :
          node::LoadEnvironment(env, script.c_str());
      if (!loaded.IsEmpty()) {
        do {
          uv_run(&loop, UV_RUN_DEFAULT);
          if (exit_requested) break;
          while (v8::platform::PumpMessageLoop(platform, isolate)) {}
          if (uv_loop_alive(&loop)) continue;
          if (node::EmitProcessBeforeExit(env).IsNothing()) break;
        } while (uv_loop_alive(&loop));
        if (exit_requested) {
          // Node RunTimers has an inner TryCatchScope which can consume the
          // termination before returning to this embedding scope. Verify the
          // exit handler/event and unreachable JS sentinel, not an exception
          // in a particular outer catcher. Clear any remaining termination
          // only after the native callback has returned normally.
          if (caught.HasTerminated() || isolate->IsExecutionTerminating()) {
            isolate->CancelTerminateExecution();
            caught.Reset();
          }
          observed_exit = exit_code;
          v8::Local<v8::Value> after_exit;
          passed = VIBEOS_NODE_EXPLICIT_EXIT && exit_checks &&
              observed_exit == VIBEOS_NODE_EXPECTED_EXIT_CODE &&
              context->Global()->Get(context,
                  v8::String::NewFromUtf8Literal(isolate, "__vibeosReturnedAfterExit")).ToLocal(&after_exit) &&
              after_exit->IsUndefined();
        } else if (VIBEOS_NODE_CANCEL) {
          passed = script_completed(context);
          auto source = v8::String::NewFromUtf8Literal(isolate,
              "try { for (;;) {} } finally { globalThis.__vibeosCancelFinally = 1; }"
              "globalThis.__vibeosCancelReturned = 1;");
          auto infinite = v8::Script::Compile(context, source).ToLocalChecked();
          vibeos_node_cancel_probe_arm();
          auto outcome = infinite->Run(context);
          passed = passed && outcome.IsEmpty() && caught.HasTerminated();
          isolate->CancelTerminateExecution();
          caught.Reset();
          v8::Local<v8::Value> after, finally_value;
          passed = passed && context->Global()->Get(context,
              v8::String::NewFromUtf8Literal(isolate, "__vibeosCancelReturned")).ToLocal(&after) &&
              after->IsUndefined() && context->Global()->Get(context,
              v8::String::NewFromUtf8Literal(isolate, "__vibeosCancelFinally")).ToLocal(&finally_value) &&
              finally_value->IsUndefined();
          node::Stop(env, node::StopFlags::kDoNotTerminateIsolate);
          observed_exit = 130;
        } else {
          passed = !VIBEOS_NODE_EXPLICIT_EXIT && script_completed(context);
          if (VIBEOS_NODE_REVOKE && passed) {
            auto prepare = v8::Script::Compile(context,
                v8::String::NewFromUtf8Literal(isolate, "globalThis.__vibeosPrepareRevoke()"));
            v8::Local<v8::Value> prepared;
            passed = !prepare.IsEmpty() && prepare.ToLocalChecked()->Run(context).ToLocal(&prepared);
            if (passed) {
              vibeos_node_probe_revoke_files();
              auto check = v8::Script::Compile(context,
                  v8::String::NewFromUtf8Literal(isolate, "globalThis.__vibeosCheckRevoke()"));
              v8::Local<v8::Value> checked;
              passed = !check.IsEmpty() && check.ToLocalChecked()->Run(context).ToLocal(&checked) &&
                  checked->Int32Value(context).FromMaybe(0) == 2;
            }
          }
          observed_exit = node::EmitProcessExit(env).FromMaybe(-1);
          passed = passed && observed_exit == VIBEOS_NODE_EXPECTED_EXIT_CODE &&
              result_equals(context, "__vibeosExitEvent", observed_exit);
        }
      }
      if (caught.HasCaught()) {
        v8::String::Utf8Value message(isolate, caught.Exception());
        std::fprintf(stderr, "NODE SMOKE exception: %s\n", *message ? *message : "unknown");
      }
      node::FreeEnvironment(env);
    }
    node::FreeIsolateData(data);
  }
  v8::platform::NotifyIsolateShutdown(platform, isolate);
  isolate->Dispose();
  if (uv_loop_close(&loop) != 0) passed = false;
  allocator.reset();
  if (invocation + 1 == VIBEOS_NODE_REPEAT) vibeos::ShutdownNodeProcess();
  // FreeEnvironment closed the granted stdio handles. Report test completion
  // through the kernel probe channel only after all normal teardown returned.
  vibeos_node_probe_finished(passed ? 0 : 1, observed_exit, VIBEOS_NODE_EXPLICIT_EXIT, VIBEOS_NODE_CANCEL);
  return passed ? observed_exit : 1;
}
