/* VibeOS libuv event-loop backend. Runs only on an admitted native stack.
 * Timers and prepare/check/idle phases retain upstream implementations.
 * No poll descriptor, host thread, or ambient operating-system service exists.
 * Stream and filesystem completion queues are added by their own backends.
 */
#include "uv.h"
#include "uv-common.h"
#include "vibeos-time.h"
#include "vibeos-sync.h"
#include "vibeos-process.h"
#include "vibeos-requests.h"
#include <stdlib.h>

void uv__run_prepare(uv_loop_t* loop);
void uv__vibeos_stream_close(uv_stream_t* stream);
void uv__vibeos_stream_finish_close(uv_stream_t* stream);
int uv__vibeos_poll_streams(uv_loop_t* loop);
void uv__vibeos_run_streams(uv_loop_t* loop);
void uv__run_check(uv_loop_t* loop);
void uv__run_idle(uv_loop_t* loop);

/* Invocation metadata and serial CPU work belong to TLS/the loop. These
 * cleanup hooks own no process-global thread, signal, or title resources. */
void uv__process_title_cleanup(void) {}
void uv__signal_cleanup(void) {}
void uv__threadpool_cleanup(void) {}

uint64_t uv_hrtime(void) {
  int64_t us = vibeos_native_monotonic_us();
  if (us < 0 || (uint64_t) us > UINT64_MAX / 1000) abort();
  return (uint64_t) us * 1000;
}

void uv_update_time(uv_loop_t* loop) {
  loop->time = uv_hrtime() / 1000000;
}

static struct uv__queue* cpu_queue(uv_loop_t* loop) {
  return &((struct vibeos_loop_internal*) loop->internal_fields)->cpu_work;
}
/* State tags, never scheduler callbacks. Work runs only on the protected native
 * stack in uv_run, not in a readiness predicate or a Rust executor poll. */
static void cpu_queued(struct uv__work* work) { (void) work; }
static void cpu_running(struct uv__work* work) { (void) work; }
int uv_queue_work(uv_loop_t* loop, uv_work_t* req, uv_work_cb work_cb,
                   uv_after_work_cb after_work_cb) {
  if (!loop || !req || !work_cb) return UV_EINVAL;
  uv__req_init(loop, req, UV_WORK);
  req->loop = loop;
  req->work_cb = work_cb;
  req->after_work_cb = after_work_cb;
  req->work_req.loop = loop;
  req->work_req.work = cpu_queued;
  req->work_req.done = NULL;
  uv__queue_insert_tail(cpu_queue(loop), &req->work_req.wq);
  return 0;
}
int uv__vibeos_cancel_work(uv_work_t* req) {
  if (!req->work_req.loop || req->work_req.work != cpu_queued) return UV_EBUSY;
  req->work_req.work = NULL;
  return 0;
}
static void run_cpu_work(uv_loop_t* loop) {
  struct uv__queue* queue = cpu_queue(loop);
  if (uv__queue_empty(queue)) return;
  struct uv__queue* first = uv__queue_head(queue);
  struct uv__work* work = uv__queue_data(first, struct uv__work, wq);
  uv_work_t* req = container_of(work, uv_work_t, work_req);
  int status = work->work ? 0 : UV_ECANCELED;
  uv__queue_remove(first);
  work->work = cpu_running;
  if (!status) req->work_cb(req);
  work->loop = NULL;
  work->work = NULL;
  uv__req_unregister(loop);
  /* The callback may free or resubmit req. No access after this call. */
  if (req->after_work_cb) req->after_work_cb(req, status);
}

int uv_loop_init(uv_loop_t* loop) {
  void* data = loop->data;
  memset(loop, 0, sizeof(*loop));
  loop->data = data;
  loop->backend_fd = -1;
  loop->async_wfd = -1;
  loop->emfile_fd = -1;
  loop->signal_pipefd[0] = loop->signal_pipefd[1] = -1;
  uv__queue_init(&loop->handle_queue);
  uv__queue_init(&loop->pending_queue);
  uv__queue_init(&loop->watcher_queue);
  uv__queue_init(&loop->wq);
  uv__queue_init(&loop->process_handles);
  uv__queue_init(&loop->prepare_handles);
  uv__queue_init(&loop->check_handles);
  uv__queue_init(&loop->idle_handles);
  uv__queue_init(&loop->async_handles);
  loop->internal_fields = uv__calloc(1, sizeof(struct vibeos_loop_internal));
  if (loop->internal_fields == NULL) return UV_ENOMEM;
  uv__queue_init(cpu_queue(loop));
  int error = uv_mutex_init(&uv__get_loop_metrics(loop)->lock);
  if (error) {
    uv__free(loop->internal_fields);
    loop->internal_fields = NULL;
    return error;
  }
  uv_update_time(loop);
  return 0;
}

void uv__loop_close(uv_loop_t* loop) {
  assert(!uv__has_active_reqs(loop));
  assert(uv__queue_empty(&loop->handle_queue));
  assert(uv__queue_empty(&loop->async_handles));
  assert(uv__queue_empty(&loop->wq));
  assert(uv__queue_empty(cpu_queue(loop)));
  uv_mutex_destroy(&uv__get_loop_metrics(loop)->lock);
  uv__free(loop->internal_fields);
  loop->internal_fields = NULL;
}

int uv__loop_configure(uv_loop_t* loop, uv_loop_option option, va_list ap) {
  (void) ap;
  if (option == UV_METRICS_IDLE_TIME) {
    uv__get_internal_fields(loop)->flags |= UV_METRICS_IDLE_TIME;
    return 0;
  }
  return UV_ENOTSUP;
}

int uv_loop_fork(uv_loop_t* loop) {
  (void) loop;
  return UV_ENOTSUP;
}

int uv_backend_fd(const uv_loop_t* loop) {
  (void) loop;
  return -1;
}

int uv_loop_alive(const uv_loop_t* loop) {
  return uv__has_active_handles(loop) || uv__has_active_reqs(loop) ||
         !uv__queue_empty(&loop->pending_queue) || loop->closing_handles != NULL;
}

static int ready(void* arg) {
  uv_loop_t* loop = arg;
  struct uv__queue* q;
  if (vibeos_native_is_cancelled() || loop->stop_flag || loop->closing_handles ||
      !uv__queue_empty(&loop->pending_queue)) return 1;
  if (!uv__queue_empty(cpu_queue(loop))) return 1;
  if (uv__vibeos_poll_requests(loop)) return 1;
  if (uv__vibeos_poll_streams(loop)) return 1;
  uv__queue_foreach(q, &loop->async_handles) {
    uv_async_t* h = uv__queue_data(q, uv_async_t, queue);
    if (atomic_load_explicit((_Atomic int*) &h->pending,
                             memory_order_acquire)) return 1;
  }
  return 0;
}

int uv_backend_timeout(const uv_loop_t* loop) {
  if (!uv_loop_alive(loop) || !uv__queue_empty(&loop->idle_handles) ||
      ready((void*) loop)) return 0;
  return uv__next_timeout(loop);
}

int uv_async_init(uv_loop_t* loop, uv_async_t* handle, uv_async_cb cb) {
  uv__handle_init(loop, (uv_handle_t*) handle, UV_ASYNC);
  handle->async_cb = cb;
  handle->pending = 0;
  uv__queue_insert_tail(&loop->async_handles, &handle->queue);
  uv__handle_start(handle);
  return 0;
}

int uv_async_send(uv_async_t* handle) {
  /* As in upstream libuv, callers must synchronize lifetime with uv_close.
   * Native wake-key admission currently limits senders to this invocation.
   */
  atomic_store_explicit((_Atomic int*) &handle->pending, 1, memory_order_release);
  vibeos_native_wake_all(handle->loop);
  return 0;
}

static void run_async(uv_loop_t* loop) {
  struct uv__queue queue;
  uv__queue_move(&loop->async_handles, &queue);
  while (!uv__queue_empty(&queue)) {
    struct uv__queue* q = uv__queue_head(&queue);
    uv_async_t* h = uv__queue_data(q, uv_async_t, queue);
    uv__queue_remove(q);
    uv__queue_insert_tail(&loop->async_handles, q);
    if (atomic_exchange_explicit((_Atomic int*) &h->pending, 0,
                                 memory_order_acq_rel) && h->async_cb)
      h->async_cb(h);
  }
}

void uv_close(uv_handle_t* handle, uv_close_cb cb) {
  assert(!uv__is_closing(handle));
  handle->flags |= UV_HANDLE_CLOSING;
  handle->close_cb = cb;
  switch (handle->type) {
    case UV_NAMED_PIPE: uv__vibeos_stream_close((uv_stream_t*) handle); break;
    case UV_TIMER: uv__timer_close((uv_timer_t*) handle); break;
    case UV_PREPARE: uv_prepare_stop((uv_prepare_t*) handle); break;
    case UV_CHECK: uv_check_stop((uv_check_t*) handle); break;
    case UV_IDLE: uv_idle_stop((uv_idle_t*) handle); break;
    case UV_ASYNC:
      uv__queue_remove(&((uv_async_t*) handle)->queue);
      uv__handle_stop(handle);
      break;
    default: abort(); /* Only backend-admitted handle types may reach here. */
  }
  handle->next_closing = handle->loop->closing_handles;
  handle->loop->closing_handles = handle;
}

int uv_is_closing(const uv_handle_t* handle) {
  return uv__is_closing(handle);
}

int uv_is_active(const uv_handle_t* handle) {
  return uv__is_active(handle);
}

static void run_closing(uv_loop_t* loop) {
  uv_handle_t* handle = loop->closing_handles;
  loop->closing_handles = NULL;
  while (handle) {
    uv_handle_t* next = handle->next_closing;
    if (handle->type == UV_NAMED_PIPE)
      uv__vibeos_stream_finish_close((uv_stream_t*) handle);
    handle->flags |= UV_HANDLE_CLOSED;
    uv__handle_unref(handle);
    uv__queue_remove(&handle->handle_queue);
    if (handle->close_cb) handle->close_cb(handle);
    handle = next;
  }
}

int uv_run(uv_loop_t* loop, uv_run_mode mode) {
  int alive = uv_loop_alive(loop);
  assert(mode == UV_RUN_DEFAULT || mode == UV_RUN_ONCE || mode == UV_RUN_NOWAIT);
  if (!alive) uv_update_time(loop);
  if (mode == UV_RUN_DEFAULT && alive && !loop->stop_flag) {
    uv_update_time(loop);
    uv__run_timers(loop);
  }
  while (alive && !loop->stop_flag) {
    int timeout;
    int had_pending = ready(loop);
    run_cpu_work(loop); /* At most one job per iteration; preserve timer/IO turns. */
    uv__vibeos_run_requests(loop);
    uv__vibeos_run_streams(loop);
    run_async(loop);
    uv__run_idle(loop);
    uv__run_prepare(loop);
    timeout = mode == UV_RUN_NOWAIT || had_pending ? 0 : uv_backend_timeout(loop);
    if (timeout != 0) {
      uv__metrics_set_provider_entry_time(loop);
      int result = vibeos_native_wait_until_context(
          loop, ready, loop, timeout < 0 ? -1 : (int64_t) timeout * 1000);
      uv__metrics_update_idle_time(loop);
      if (result < 0) abort(); /* Platform failure cannot look like polling. */
    }
    run_async(loop);
    uv__run_check(loop);
    uv__vibeos_run_requests(loop);
    uv__vibeos_run_streams(loop);
    run_closing(loop);
    uv_update_time(loop);
    uv__run_timers(loop);
    uv__metrics_inc_loop_count(loop);
    alive = uv_loop_alive(loop);
    if (mode != UV_RUN_DEFAULT || vibeos_native_is_cancelled()) break;
  }
  loop->stop_flag = 0;
  return alive;
}
