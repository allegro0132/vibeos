#include "node-esbuild.h"
#ifdef VIBEOS_NODE_TOOLKIT
#include "node.h"
#include "env-inl.h"
#include "uv.h"
#include "v8.h"
#include "vibeos-esbuild.h"
#include "vibeos-process.h"
#include <cstdio>
#include <cstring>
#include <deque>
#include <vector>

namespace vibeos {
struct EsbuildBridge::Impl {
  struct Job {
    uint64_t id = 0;
    std::vector<uint8_t> input;
    v8::Global<v8::Promise::Resolver> resolver;
  };
  node::Environment* env;
  v8::Isolate* isolate;
  uv_loop_t* loop;
  uv_prepare_t prepare{};
  v8::Global<v8::Context> context;
  std::deque<std::unique_ptr<Job>> queue;
  bool closing = false;
  bool closed = false;

  Impl(node::Environment* e, uv_loop_t* l) : env(e), isolate(e->isolate()), loop(l) {
    auto ctx = env->context();
    context.Reset(isolate, ctx);
    if (uv_prepare_init(loop, &prepare)) vibeos_native_fatal_exit(70);
    prepare.data = this;
    auto object = v8::Object::New(isolate);
    auto data = v8::External::New(isolate, this);
    object->Set(ctx, v8::String::NewFromUtf8Literal(isolate, "transformSync"),
        v8::Function::New(ctx, Sync, data).ToLocalChecked()).Check();
    object->Set(ctx, v8::String::NewFromUtf8Literal(isolate, "transform"),
        v8::Function::New(ctx, Async, data).ToLocalChecked()).Check();
    object->SetIntegrityLevel(ctx, v8::IntegrityLevel::kFrozen).Check();
    ctx->Global()->DefineOwnProperty(ctx,
        v8::Symbol::For(isolate, v8::String::NewFromUtf8Literal(isolate, "vibeos.esbuild")),
        object, static_cast<v8::PropertyAttribute>(v8::ReadOnly | v8::DontDelete)).Check();
  }
  v8::Local<v8::Value> Error(int status) {
    char text[96];
    std::snprintf(text, sizeof(text), "VibeOS esbuild transform failed (native status %d)", status);
    return v8::Exception::Error(v8::String::NewFromUtf8(isolate, text).ToLocalChecked());
  }
  static Impl* Self(const v8::FunctionCallbackInfo<v8::Value>& args) {
    return static_cast<Impl*>(args.Data().As<v8::External>()->Value());
  }
  bool Input(const v8::FunctionCallbackInfo<v8::Value>& args, std::vector<uint8_t>* out) {
    if (closing || args.Length() != 1 || !args[0]->IsUint8Array()) {
      isolate->ThrowException(Error(-9)); return false;
    }
    auto view = args[0].As<v8::Uint8Array>();
    const size_t size = view->ByteLength();
    auto backing = view->Buffer()->GetBackingStore();
    if (size == 0 || size > 1024 * 1024 + 65536 || backing->IsShared()) {
      isolate->ThrowException(Error(-9)); return false;
    }
    auto* data = static_cast<const uint8_t*>(backing->Data()) + view->ByteOffset();
    out->assign(data, data + size);
    return true;
  }
  v8::Local<v8::Value> Bytes(const uint8_t* bytes, size_t length) {
    auto store = v8::ArrayBuffer::NewBackingStore(isolate, length);
    if (!store) vibeos_native_fatal_exit(70);
    if (length) std::memcpy(store->Data(), bytes, length);
    auto buffer = v8::ArrayBuffer::New(isolate, std::move(store));
    return v8::Uint8Array::New(buffer, 0, length);
  }
  void Start() {
    if (queue.empty() || queue.front()->id) return;
    auto& job = queue.front();
    int64_t id = vibeos_esbuild_begin(job->input.data(), job->input.size());
    if (id > 0) { job->id = id; job->input.clear(); }
    else Finish(static_cast<int>(id), nullptr, 0);
  }
  void Finish(int status, const uint8_t* output, size_t length) {
    auto job = std::move(queue.front()); queue.pop_front();
    auto result = status == 0 ? Bytes(output, length) : Error(status);
    if (job->id) vibeos_esbuild_release(job->id);
    auto resolver = job->resolver.Get(isolate);
    auto ctx = context.Get(isolate);
    if (status == 0) (void) resolver->Resolve(ctx, result).FromMaybe(false);
    else (void) resolver->Reject(ctx, result).FromMaybe(false);
    if (queue.empty()) uv_prepare_stop(&prepare);
    // Admit the next request before libuv can park without a timer. In
    // particular, completion may be observed during prepare rather than by
    // the earlier readiness check. The bounded queue also bounds recursion
    // when successive requests fail admission immediately.
    else Start();
  }
  void DrainOne(bool wait) {
    Start();
    if (queue.empty() || !queue.front()->id) return;
    const uint64_t id = queue.front()->id;
    if (wait) {
      int status = vibeos_esbuild_wait(id);
      if (status) { Finish(status, nullptr, 0); return; }
    }
    const uint8_t* output = nullptr;
    size_t length = 0;
    int status = vibeos_esbuild_poll(id, &output, &length);
    if (status != -15) Finish(status, output, length);
  }
  static void Tick(uv_prepare_t* handle) {
    auto* self = static_cast<Impl*>(handle->data);
    if (self->closing || self->queue.empty()) return;
    v8::HandleScope handles(self->isolate);
    auto ctx = self->context.Get(self->isolate);
    v8::Context::Scope entered(ctx);
    node::CallbackScope callback(self->env, ctx->Global(), {0, 0});
    self->DrainOne(false);
  }
  static void Sync(const v8::FunctionCallbackInfo<v8::Value>& args) {
    auto* self = Self(args);
    std::vector<uint8_t> input;
    if (!self->Input(args, &input)) return;
    // Preserve submission order if synchronous work follows Promise requests.
    while (!self->queue.empty()) self->DrainOne(true);
    int64_t id = vibeos_esbuild_begin(input.data(), input.size());
    if (id < 0) { self->isolate->ThrowException(self->Error(id)); return; }
    int status = vibeos_esbuild_wait(id);
    const uint8_t* output = nullptr;
    size_t length = 0;
    if (!status) status = vibeos_esbuild_poll(id, &output, &length);
    if (!status) args.GetReturnValue().Set(self->Bytes(output, length));
    else self->isolate->ThrowException(self->Error(status));
    vibeos_esbuild_release(id);
  }
  static void Async(const v8::FunctionCallbackInfo<v8::Value>& args) {
    auto* self = Self(args);
    auto job = std::make_unique<Job>();
    if (!self->Input(args, &job->input)) return;
    auto ctx = self->context.Get(self->isolate);
    auto resolver = v8::Promise::Resolver::New(ctx).ToLocalChecked();
    args.GetReturnValue().Set(resolver->GetPromise());
    if (self->queue.size() >= 16) {
      (void) resolver->Reject(ctx, self->Error(-14)).FromMaybe(false); return;
    }
    job->resolver.Reset(self->isolate, resolver);
    self->queue.push_back(std::move(job));
    uv_prepare_start(&self->prepare, Tick);
    self->Start();
  }
  void Close() {
    if (closed) return;
    closing = true;
    uv_prepare_stop(&prepare);
    for (auto& job : queue) {
      if (job->id) {
        vibeos_esbuild_cancel(job->id);
        vibeos_esbuild_wait(job->id); // Join audited WASI cleanup before C++ teardown.
        vibeos_esbuild_release(job->id);
      }
    }
    queue.clear();
    uv_close(reinterpret_cast<uv_handle_t*>(&prepare), [](uv_handle_t* h) {
      static_cast<Impl*>(h->data)->closed = true;
    });
    // Stop may have left libuv's stop flag set; at most two nonblocking turns
    // are needed to process this handle's close callback.
    for (unsigned i = 0; i < 2 && !closed; ++i) uv_run(loop, UV_RUN_NOWAIT);
    if (!closed) vibeos_native_fatal_exit(70);
    context.Reset();
  }
};
EsbuildBridge::EsbuildBridge(node::Environment* env, uv_loop_s* loop)
    : impl_(std::make_unique<Impl>(env, loop)) {}
EsbuildBridge::~EsbuildBridge() { Close(); }
void EsbuildBridge::Close() { impl_->Close(); }
}
#endif
