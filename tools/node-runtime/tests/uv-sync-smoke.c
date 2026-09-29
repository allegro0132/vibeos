/* Target-only mutex ownership, semaphore accounting and parked timeout check. */
#include "uv.h"
#include "uv-common.h"
#include "vibeos-stdio.h"
#include "vibeos-memory.h"
#include "vibeos-process.h"
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
static void metric_timer(uv_timer_t* timer) {
  uv_close((uv_handle_t*) timer, NULL);
}
static unsigned excluded_callbacks;
static void excluded_event(uv_fs_event_t* h, const char* p, int events, int status) {
  (void) h; (void) p; (void) events; (void) status; excluded_callbacks++;
}
static void excluded_poll(uv_fs_poll_t* h, int status, const uv_stat_t* p, const uv_stat_t* c) {
  (void) h; (void) status; (void) p; (void) c; excluded_callbacks++;
}
static void excluded_signal(uv_signal_t* h, int signum) {
  (void) h; (void) signum; excluded_callbacks++;
}
static int zeroed(const void* value, size_t size) {
  const unsigned char* bytes = value;
  for (size_t i = 0; i < size; i++) if (bytes[i]) return 0;
  return 1;
}
static int exclusions(void) {
  uv_loop_t loop;
  uv_process_t process;
  uv_process_options_t options;
  uv_fs_event_t event;
  uv_fs_poll_t poll;
  uv_signal_t signal;
  memset(&process, 0, sizeof(process));
  memset(&options, 0, sizeof(options));
  memset(&event, 0, sizeof(event));
  memset(&poll, 0, sizeof(poll));
  memset(&signal, 0, sizeof(signal));
  options.file = "unsupported-child";
  if (uv_loop_init(&loop)) return 50;
  if (uv_spawn(&loop, &process, &options) != UV_ENOTSUP ||
      uv_process_kill(&process, 0) != UV_ENOTSUP || uv_kill(42, 0) != UV_ENOTSUP) return 51;
  if (uv_fs_event_init(&loop, &event) != UV_ENOTSUP ||
      uv_fs_event_start(&event, excluded_event, "/", 0) != UV_ENOTSUP ||
      uv_fs_event_stop(&event) != UV_ENOTSUP) return 52;
  char path[] = "sentinel";
  size_t size = sizeof(path);
  if (uv_fs_poll_init(&loop, &poll) != UV_ENOTSUP ||
      uv_fs_poll_start(&poll, excluded_poll, "/", 1) != UV_ENOTSUP ||
      uv_fs_poll_stop(&poll) != UV_ENOTSUP ||
      uv_fs_poll_getpath(&poll, path, &size) != UV_ENOTSUP ||
      size != sizeof(path) || strcmp(path, "sentinel")) return 53;
  if (uv_signal_init(&loop, &signal) != UV_ENOTSUP ||
      uv_signal_start(&signal, excluded_signal, 2) != UV_ENOTSUP ||
      uv_signal_start_oneshot(&signal, excluded_signal, 2) != UV_ENOTSUP ||
      uv_signal_stop(&signal) != UV_ENOTSUP) return 54;
  if (!zeroed(&process, sizeof(process)) || !zeroed(&event, sizeof(event)) ||
      !zeroed(&poll, sizeof(poll)) || !zeroed(&signal, sizeof(signal))) return 55;
  if (uv_spawn(NULL, &process, &options) != UV_EINVAL ||
      uv_fs_event_init(&loop, NULL) != UV_EINVAL ||
      uv_fs_poll_getpath(&poll, path, NULL) != UV_EINVAL ||
      uv_signal_start(&signal, NULL, 2) != UV_EINVAL) return 56;
  if (uv_loop_alive(&loop) || uv_run(&loop, UV_RUN_NOWAIT) ||
      excluded_callbacks || uv_loop_close(&loop)) return 57;
  puts("UV EXCLUDED operations=14 untouched=1 callbacks=0 handles=0 PASS");
  return 0;
}

static int network_exclusions(void) {
  uv_loop_t loop;
  uv_tcp_t tcp;
  uv_udp_t udp;
  uv_connect_t connect;
  uv_udp_send_t send;
  struct sockaddr address;
  memset(&tcp, 0, sizeof(tcp)); memset(&udp, 0, sizeof(udp));
  memset(&connect, 0, sizeof(connect)); memset(&send, 0, sizeof(send));
  memset(&address, 0xa5, sizeof(address));
  int length = sizeof(address);
  unsigned checks = 0;
  if (uv_loop_init(&loop)) return 60;
#define DENIED(call) do { if ((call) != UV_ENOTSUP) return 61; checks++; } while (0)
  DENIED(uv_tcp_init(&loop, &tcp));
  DENIED(uv_tcp_init_ex(&loop, &tcp, 0));
  DENIED(uv_tcp_open(&tcp, 42));
  DENIED(uv_tcp_nodelay(&tcp, 1));
  DENIED(uv_tcp_keepalive(&tcp, 1, 5));
  DENIED(uv_tcp_simultaneous_accepts(&tcp, 1));
  DENIED(uv_tcp_getsockname(&tcp, &address, &length));
  DENIED(uv_tcp_getpeername(&tcp, &address, &length));
  DENIED(uv_tcp_close_reset(&tcp, NULL));
  DENIED(uv__tcp_bind(&tcp, &address, sizeof(address), 0));
  DENIED(uv__tcp_connect(&connect, &tcp, &address, sizeof(address), NULL));
  DENIED(uv__udp_init_ex(&loop, &udp, 0, AF_INET));
  DENIED(uv_udp_open(&udp, 42));
  DENIED(uv_udp_getsockname(&udp, &address, &length));
  DENIED(uv_udp_getpeername(&udp, &address, &length));
  DENIED(uv_udp_set_membership(&udp, "224.0.0.1", NULL, UV_JOIN_GROUP));
  DENIED(uv_udp_set_source_membership(&udp, "224.0.0.1", NULL, "127.0.0.1", UV_JOIN_GROUP));
  DENIED(uv_udp_set_multicast_loop(&udp, 1));
  DENIED(uv_udp_set_multicast_ttl(&udp, 1));
  DENIED(uv_udp_set_multicast_interface(&udp, "127.0.0.1"));
  DENIED(uv_udp_set_broadcast(&udp, 1));
  DENIED(uv_udp_set_ttl(&udp, 1));
  DENIED(uv__udp_bind(&udp, &address, sizeof(address), 0));
  DENIED(uv__udp_connect(&udp, &address, sizeof(address)));
  DENIED(uv__udp_disconnect(&udp));
  uv_buf_t buffer = uv_buf_init("x", 1);
  DENIED(uv__udp_send(&send, &udp, &buffer, 1, &address, sizeof(address), NULL));
  DENIED(uv__udp_try_send(&udp, &buffer, 1, &address, sizeof(address)));
  uv_buf_t* buffers[] = {&buffer};
  unsigned counts[] = {1};
  struct sockaddr* addresses[] = {&address};
  DENIED(uv__udp_try_send2(&udp, 1, buffers, counts, addresses));
  DENIED(uv__udp_recv_start(&udp, NULL, NULL));
  DENIED(uv__udp_recv_stop(&udp));
  DENIED(uv_listen((uv_stream_t*) &tcp, 1, NULL));
  DENIED(uv_accept((uv_stream_t*) &tcp, (uv_stream_t*) &tcp));
#undef DENIED
  if (checks != 32 || length != sizeof(address) ||
      !zeroed(&tcp, sizeof(tcp)) || !zeroed(&udp, sizeof(udp)) ||
      !zeroed(&connect, sizeof(connect)) || !zeroed(&send, sizeof(send))) return 62;
  for (size_t i = 0; i < sizeof(address); i++)
    if (((unsigned char*) &address)[i] != 0xa5) return 63;
  if (uv_loop_alive(&loop) || uv_run(&loop, UV_RUN_NOWAIT) || uv_loop_close(&loop)) return 64;
  puts("UV NETWORK denied=32 untouched=1 handles=0 PASS");
  return 0;
}

static unsigned stream_closed;
static void ipc_connect_done(uv_connect_t* req, int status) {
  (void) req; (void) status; excluded_callbacks++;
}
static int ipc_tty_exclusions(void) {
  uv_loop_t loop = {0};
  uv_pipe_t pipe = {0};
  uv_tty_t tty = {0};
  uv_connect_t connect = {0};
  char name[16] = "untouched";
  size_t size = sizeof(name);
  int width = 123, height = 456;
  excluded_callbacks = 0;
  if (uv_loop_init(&loop) || uv_pipe_init(&loop, &pipe, 0)) return 130;
  uv_pipe_t original;
  memcpy(&original, &pipe, sizeof(pipe));
  if (uv_pipe_bind2(&pipe, "ipc", 3, 0) != UV_ENOTSUP ||
      uv_pipe_connect2(&connect, &pipe, "ipc", 3, 0, ipc_connect_done) != UV_ENOTSUP ||
      uv_pipe_chmod(&pipe, UV_READABLE | UV_WRITABLE) != UV_ENOTSUP ||
      uv_pipe_getsockname(&pipe, name, &size) != UV_ENOTSUP ||
      uv_pipe_getpeername(&pipe, name, &size) != UV_ENOTSUP ||
      strcmp(name, "untouched") || size != sizeof(name) ||
      memcmp(&original, &pipe, sizeof(pipe)) || !zeroed(&connect, sizeof(connect))) return 131;
  if (uv_tty_init(&loop, &tty, 1, 0) != UV_ENOTSUP ||
      uv_tty_set_mode(&tty, UV_TTY_MODE_RAW) != UV_ENOTSUP ||
      uv_tty_get_winsize(&tty, &width, &height) != UV_ENOTSUP ||
      width != 123 || height != 456 || !zeroed(&tty, sizeof(tty))) return 132;
  uv_close((uv_handle_t*) &pipe, NULL);
  if (uv_run(&loop, UV_RUN_DEFAULT) || excluded_callbacks || uv_loop_close(&loop)) return 133;
  puts("UV IPC TTY denied=8 untouched=1 callbacks=0 PASS");
  return 0;
}
static void stream_close_done(uv_handle_t* handle) {
  if (handle->data == &stream_closed) stream_closed++;
}
struct stream_input_state {
  char buffer[3], received[12];
  unsigned bytes, reads, enobufs, eof;
  int failed;
};
static void stream_input_alloc(uv_handle_t* handle, size_t suggested, uv_buf_t* buf) {
  struct stream_input_state* s = handle->loop->data;
  if (!suggested) s->failed = 1;
  *buf = s->enobufs ? uv_buf_init(s->buffer, sizeof(s->buffer)) : uv_buf_init(NULL, 0);
}
static void stream_input_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
  struct stream_input_state* s = stream->loop->data;
  if (nread == UV_ENOBUFS) {
    if (s->enobufs++ || s->bytes || uv_read_stop(stream)) s->failed = 1;
  } else if (nread == UV_EOF) {
    if (s->eof++ || s->bytes != 12 || uv_is_active((uv_handle_t*) stream)) s->failed = 1;
  } else if (nread > 0 && nread <= 3 && (size_t) nread <= sizeof(s->received) - s->bytes) {
    memcpy(s->received + s->bytes, buf->base, (size_t) nread);
    s->bytes += (unsigned) nread;
    s->reads++;
    if (s->bytes == 3 && uv_read_stop(stream)) s->failed = 1;
  } else {
    s->failed = 1;
    uv_read_stop(stream);
  }
}
static int stream_input(uv_loop_t* loop, uv_stream_t* stream) {
  struct stream_input_state s = {0};
  loop->data = &s;
  if (uv_read_start(stream, NULL, stream_input_read) != UV_EINVAL ||
      uv_read_start(stream, stream_input_alloc, stream_input_read) ||
      uv_read_start(stream, stream_input_alloc, stream_input_read) != UV_EALREADY) return 96;
  if (uv_run(loop, UV_RUN_DEFAULT) || s.failed || s.enobufs != 1 || s.bytes ||
      uv_is_active((uv_handle_t*) stream)) return 97;
  if (uv_read_start(stream, stream_input_alloc, stream_input_read) ||
      uv_run(loop, UV_RUN_DEFAULT) || s.failed || s.bytes != 3 || s.reads != 1) return 98;
  if (uv_run(loop, UV_RUN_NOWAIT) || s.bytes != 3 || uv_read_stop(stream)) return 99;
  if (uv_read_start(stream, stream_input_alloc, stream_input_read) ||
      uv_run(loop, UV_RUN_DEFAULT) || s.failed || s.bytes != 12 || s.reads != 4 ||
      s.eof != 1 || memcmp(s.received, "stream-ready", 12) ||
      uv_is_readable(stream) || uv_is_active((uv_handle_t*) stream) ||
      uv_read_start(stream, stream_input_alloc, stream_input_read) != UV_ENOTCONN) return 100;
  loop->data = NULL;
  puts("UV STREAM READ bytes=12 chunks=4 paused=1 enobufs=1 eof=1 PASS");
  return 0;
}
static int stream_handles(void) {
  uv_loop_t loop;
  uv_pipe_t pipe, ipc;
  memset(&loop, 0, sizeof(loop));
  memset(&pipe, 0, sizeof(pipe));
  memset(&ipc, 0, sizeof(ipc));
  stream_closed = 0;
  pipe.data = &stream_closed;
  if (uv_guess_handle(0) != UV_NAMED_PIPE || uv_guess_handle(1) != UV_NAMED_PIPE ||
      uv_guess_handle(2) != UV_NAMED_PIPE || uv_guess_handle(-1) != UV_UNKNOWN_HANDLE) return 70;
  if (uv_loop_init(&loop)) return 71;
  if (uv_pipe_init(&loop, &ipc, 1) != UV_ENOTSUP || !zeroed(&ipc, sizeof(ipc))) return 72;
  if (uv_pipe_init(&loop, &pipe, 0) || pipe.data != &stream_closed) return 73;
  uv_os_fd_t fd = 123;
  if (uv_fileno((uv_handle_t*) &pipe, &fd) != UV_EBADF || fd != 123 ||
      uv_is_readable((uv_stream_t*) &pipe) || uv_is_writable((uv_stream_t*) &pipe)) return 74;
  if (uv_pipe_open(&pipe, -1) != UV_EBADF || uv_pipe_open(&pipe, 0)) return 75;
  if (uv_stream_set_blocking((uv_stream_t*) &pipe, 1) != UV_ENOTSUP ||
      uv_stream_set_blocking((uv_stream_t*) &pipe, 0)) return 134;
  uv_buf_t denied = uv_buf_init("must-not-write", 14);
  if (uv_try_write((uv_stream_t*) &pipe, &denied, 1) != UV_EBADF) return 82;
  if (uv_fileno((uv_handle_t*) &pipe, &fd) || fd != 0 ||
      !uv_is_readable((uv_stream_t*) &pipe) || uv_is_writable((uv_stream_t*) &pipe)) return 76;
  if (uv_pipe_open(&pipe, 1) != UV_EBUSY || uv_pipe_pending_count(&pipe) ||
      uv_pipe_pending_type(&pipe) != UV_UNKNOWN_HANDLE) return 77;
  if (uv_loop_close(&loop) != UV_EBUSY) return 78;
  int read_status = stream_input(&loop, (uv_stream_t*) &pipe);
  if (read_status) return read_status;
  uv_close((uv_handle_t*) &pipe, stream_close_done);
  if (stream_closed || !uv_is_closing((uv_handle_t*) &pipe) ||
      uv_is_readable((uv_stream_t*) &pipe) || uv_guess_handle(0) != UV_UNKNOWN_HANDLE) return 79;
  fd = 123;
  if (uv_fileno((uv_handle_t*) &pipe, &fd) != UV_EBADF || fd != 123) return 80;
  if (uv_run(&loop, UV_RUN_DEFAULT) || stream_closed != 1 || uv_loop_close(&loop)) return 81;
  puts("UV STREAM HANDLE stdio=3 open=1 modes=1 close=1 ipc_denied=1 PASS");
  return 0;
}

/* Run after the final C stdio flush: closing this pipe owns and closes fd 1. */
struct stream_output_state {
  uv_write_t data, marker, cancelled;
  uv_shutdown_t shutdown;
  unsigned callbacks;
  unsigned shutdown_callbacks;
  int failed;
};
static void cancelled_shutdown(uv_shutdown_t* req, int status) {
  struct stream_output_state* s = req->handle->loop->data;
  if (status != UV_ECANCELED || s->callbacks != 3 || stream_closed ||
      s->shutdown_callbacks++) s->failed = 1;
}
static void stream_output_done(uv_write_t* req, int status) {
  struct stream_output_state* s = req->handle->loop->data;
  unsigned expected = req == &s->data ? 0 : req == &s->marker ? 1 : 2;
  if (s->callbacks++ != expected || status != (expected == 2 ? UV_ECANCELED : 0))
    s->failed = 1;
  if (expected == 1) {
    uv_buf_t cancelled = uv_buf_init("MUST-NOT-BE-WRITTEN", 19);
    if (uv_write(&s->cancelled, req->handle, &cancelled, 1, stream_output_done))
      s->failed = 1;
    if (uv_shutdown(&s->shutdown, req->handle, cancelled_shutdown)) s->failed = 1;
    uv_close((uv_handle_t*) req->handle, stream_close_done);
  }
  if (stream_closed) s->failed = 1;
}

struct shutdown_state { unsigned written, shutdown, closed; int failed; };
static void shutdown_closed(uv_handle_t* handle) {
  struct shutdown_state* s = handle->loop->data;
  if (s->written != 1 || s->shutdown != 1 || s->closed++) s->failed = 1;
}
static void shutdown_written(uv_write_t* req, int status) {
  struct shutdown_state* s = req->handle->loop->data;
  if (status || s->written++ || s->shutdown || s->closed) s->failed = 1;
}
static void shutdown_done(uv_shutdown_t* req, int status) {
  struct shutdown_state* s = req->handle->loop->data;
  uv_os_fd_t fd = -1;
  if (status || s->written != 1 || s->shutdown++ || s->closed ||
      uv_fileno((uv_handle_t*) req->handle, &fd) || fd != 2 ||
      uv_guess_handle(2) != UV_NAMED_PIPE ||
      vibeos_native_try_write(2, "denied", 6) != -4) s->failed = 1;
  uv_close((uv_handle_t*) req->handle, shutdown_closed);
}
static int stream_shutdown(void) {
  uv_loop_t loop = {0};
  uv_pipe_t pipe = {0};
  uv_write_t write = {0}, denied = {0};
  uv_shutdown_t shutdown = {0}, duplicate = {0};
  struct shutdown_state s = {0};
  loop.data = &s;
  if (uv_loop_init(&loop) || uv_pipe_init(&loop, &pipe, 0) || uv_pipe_open(&pipe, 2)) return 92;
  uv_stream_t* stream = (uv_stream_t*) &pipe;
  uv_buf_t data = uv_buf_init("UV SHUTDOWN DATA\n", 17);
  if (uv_write(&write, stream, &data, 1, shutdown_written) ||
      uv_shutdown(&shutdown, stream, shutdown_done) || s.written || s.shutdown ||
      uv_is_writable(stream)) return 93;
  if (uv_shutdown(&duplicate, stream, shutdown_done) != UV_ENOTCONN ||
      !zeroed(&duplicate, sizeof(duplicate)) ||
      uv_write(&denied, stream, &data, 1, shutdown_written) != UV_EBADF ||
      !zeroed(&denied, sizeof(denied))) return 94;
  if (uv_run(&loop, UV_RUN_DEFAULT) || s.failed || s.written != 1 ||
      s.shutdown != 1 || s.closed != 1 || uv_loop_close(&loop)) return 95;
  puts("UV SHUTDOWN drained=1 order=1 descriptor=1 denied=1 PASS");
  return 0;
}
int vibeos_uv_stream_output_smoke(void) {
  int shutdown_status = stream_shutdown();
  if (shutdown_status) return shutdown_status;
  uv_loop_t loop = {0};
  uv_pipe_t pipe = {0};
  struct stream_output_state state = {0};
  char data[16384];
  memset(data, 'Y', sizeof(data));
  loop.data = &state;
  stream_closed = 0;
  pipe.data = &stream_closed;
  if (uv_loop_init(&loop) || uv_pipe_init(&loop, &pipe, 0) ||
      uv_pipe_open(&pipe, 1)) return 83;
  uv_stream_t* stream = (uv_stream_t*) &pipe;
  uv_buf_t bufs[] = {uv_buf_init(NULL, 0), uv_buf_init("UV STREAM ", 10),
                    uv_buf_init("WRITE vectors=3 PASS\n", 21)};
  uv_buf_t invalid[] = {bufs[1], uv_buf_init(NULL, 1)};
  if (uv_try_write(stream, invalid, 2) != UV_EINVAL ||
      uv_try_write(stream, bufs, 0) != UV_EINVAL) return 84;
  if (uv_try_write(stream, bufs, 3) != 31) return 85;
  uv_buf_t vectors[5] = {uv_buf_init(NULL, 0)};
  for (unsigned i = 1; i < 5; i++) vectors[i] = uv_buf_init(data + (i - 1) * 4096, 4096);
  char marker[] = "\nUV ASYNC STREAM bytes=16384 callbacks=3 PASS\n";
  uv_buf_t tail = uv_buf_init(marker, sizeof(marker) - 1);
  if (uv_write2(&state.data, stream, vectors, 5, stream, stream_output_done) != UV_ENOTSUP ||
      !zeroed(&state.data, sizeof(state.data))) return 88;
  if (uv_write(&state.data, stream, vectors, 5, stream_output_done) ||
      uv_write(&state.marker, stream, &tail, 1, stream_output_done) || state.callbacks) return 89;
  /* The array is caller-owned; only its data buffers remain live until cb. */
  memset(vectors, 0, sizeof(vectors));
  if (uv_try_write(stream, bufs, 3) != UV_EAGAIN ||
      !uv_is_active((uv_handle_t*) stream) ||
      stream->write_queue_size != sizeof(data) + tail.len) return 90;
  if (uv_run(&loop, UV_RUN_NOWAIT) != 1 || state.callbacks ||
      !stream->write_queue_size || stream->write_queue_size >= sizeof(data) + tail.len) return 91;
  if (uv_run(&loop, UV_RUN_DEFAULT) || state.failed || state.callbacks != 3 ||
      state.shutdown_callbacks != 1 ||
      stream_closed != 1 || uv_is_active((uv_handle_t*) stream) ||
      stream->write_queue_size || uv_loop_close(&loop)) return 87;
  if (uv_try_write(stream, bufs, 3) != UV_EBADF) return 86;
  return 0;
}

static int environment_smoke(void) {
  char buffer[32] = "untouched";
  size_t size = sizeof(buffer);
  uv_env_item_t* entries = NULL;
  int count = -1;
  if (uv_os_getenv("VIBEOS_TEST_SEED", buffer, &size) || size != 13 ||
      strcmp(buffer, "from-launcher") || !getenv("VIBEOS_TEST_SEED") ||
      strcmp(getenv("VIBEOS_TEST_SEED"), "from-launcher")) return 110;
  if (getenv("PREVIOUS_INVOCATION") || uv_os_environ(&entries, &count) || count != 1 ||
      strcmp(entries[0].name, "VIBEOS_TEST_SEED")) return 111;
  uv_os_free_environ(entries, count);
  strcpy(buffer, "untouched"); size = 2;
  if (uv_os_getenv("VIBEOS_TEST_SEED", buffer, &size) != UV_ENOBUFS ||
      size != 14 || strcmp(buffer, "untouched")) return 112;
  if (setenv("VIBEOS_TEST_SEED", "ignored", 0) || strcmp(getenv("VIBEOS_TEST_SEED"), "from-launcher") ||
      uv_os_setenv("VIBEOS_TEST_SEED", "updated") || strcmp(getenv("VIBEOS_TEST_SEED"), "updated")) return 113;
  if (setenv("EMPTY", "", 1) || uv_os_environ(&entries, &count) || count != 2) return 114;
  if (uv_os_setenv("VIBEOS_TEST_SEED", "again") || strcmp(entries[0].value, "updated")) return 115;
  uv_os_free_environ(entries, count);
  size = sizeof(buffer);
  if (uv_os_getenv("EMPTY", buffer, &size) || size != 0 || buffer[0] ||
      uv_os_setenv("bad=name", "x") != UV_EINVAL || uv_os_setenv("", "x") != UV_EINVAL) return 116;
  char huge[4098]; memset(huge, 'x', sizeof(huge)); huge[sizeof(huge)-1] = 0;
  if (uv_os_setenv("VIBEOS_TEST_SEED", huge) != UV_E2BIG || strcmp(getenv("VIBEOS_TEST_SEED"), "again")) return 117;
  if (unsetenv("EMPTY") || uv_os_unsetenv("VIBEOS_TEST_SEED") || uv_os_unsetenv("absent")) return 118;
  strcpy(buffer, "untouched"); size = sizeof(buffer);
  if (uv_os_getenv("VIBEOS_TEST_SEED", buffer, &size) != UV_ENOENT ||
      strcmp(buffer, "untouched") || size != sizeof(buffer) ||
      uv_os_environ(&entries, &count) || entries != NULL || count != 0) return 119;
  uv_os_free_environ(entries, count);
  for (unsigned i = 0; i < 64; i++) {
    char name[16]; snprintf(name, sizeof(name), "BOUND_%u", i);
    if (uv_os_setenv(name, "v")) return 120;
  }
  if (uv_os_setenv("BOUND_OVERFLOW", "v") != UV_E2BIG || uv_os_setenv("BOUND_0", "replace")) return 121;
  for (unsigned i = 0; i < 64; i++) {
    char name[16]; snprintf(name, sizeof(name), "BOUND_%u", i);
    if (uv_os_unsetenv(name)) return 122;
  }
  huge[4096] = 0;
  for (unsigned i = 0; i < 15; i++) {
    char name[16]; snprintf(name, sizeof(name), "BIG_%u", i);
    if (uv_os_setenv(name, huge)) return 123;
  }
  if (uv_os_setenv("BIG_OVERFLOW", huge) != UV_E2BIG) return 124;
  for (unsigned i = 0; i < 15; i++) {
    char name[16]; snprintf(name, sizeof(name), "BIG_%u", i);
    if (uv_os_unsetenv(name)) return 125;
  }
  char long_name[257]; memset(long_name, 'N', 256); long_name[256] = 0;
  if (uv_os_setenv(long_name, "v") != UV_E2BIG ||
      uv_os_environ(&entries, &count) || count || entries) return 126;
  puts("UV ENV seeded=1 isolated=1 shared_libc=1 snapshot=1 bounded=1 empty=1 PASS");
  return 0;
}

static int system_information(void) {
  uv_utsname_t info;
  if (uv_os_uname(&info) || strcmp(info.sysname, "VibeOS") || strcmp(info.machine, "riscv64") ||
      strcmp(info.release, vibeos_native_system_label(1)) || strcmp(info.version, vibeos_native_system_label(2)) ||
      !info.release[0] || uv_os_uname(NULL) != UV_EINVAL || vibeos_native_system_label(4)) return 200;
  uv_cpu_info_t dummy;
  uv_cpu_info_t* cpus = &dummy;
  int count = 234;
  if (uv_cpu_info(&cpus, &count) != UV_ENOTSUP || cpus != &dummy || count != 234 ||
      uv_cpu_info(NULL, &count) != UV_EINVAL || uv_cpu_info(&cpus, NULL) != UV_EINVAL) return 201;
  double load[3] = { 1, 2, 3 };
  uv_loadavg(load);
  for (int i = 0; i < 3; i++) if (load[i] == load[i]) return 202;
  char host[32] = "untouched";
  size_t size = sizeof(host);
  if (uv_os_gethostname(host, &size) != UV_ENOTSUP || strcmp(host, "untouched") || size != sizeof(host)) return 203;
  if (uv_os_setenv("HOSTNAME", "vibeos-qemu")) return 204;
  size = 3;
  if (uv_os_gethostname(host, &size) != UV_ENOBUFS || size != 12 || strcmp(host, "untouched")) return 205;
  size = sizeof(host);
  if (uv_os_gethostname(host, &size) || size != 11 || strcmp(host, "vibeos-qemu") ||
      uv_os_gethostname(NULL, &size) != UV_EINVAL || uv_os_gethostname(host, NULL) != UV_EINVAL ||
      uv_os_unsetenv("HOSTNAME")) return 206;
  puts("UV SYSTEM image_labels=1 hostname_explicit=1 cpu_unsupported=1 load_unavailable=1 PASS");
  return 0;
}

static int os_boundaries(void) {
  uv_rusage_t usage, original_usage;
  uv_passwd_t password, original_password;
  memset(&usage, 0x5a, sizeof(usage)); memcpy(&original_usage, &usage, sizeof(usage));
  memset(&password, 0x5a, sizeof(password)); memcpy(&original_password, &password, sizeof(password));
  int priority = 123, count = 456;
  uv_interface_address_t dummy;
  uv_interface_address_t* addresses = &dummy;
  char buffer[32] = "untouched";
  size_t size = sizeof(buffer);
  if (uv_getrusage(&usage) != UV_ENOTSUP || memcmp(&usage, &original_usage, sizeof(usage)) ||
      uv_getrusage_thread(&usage) != UV_ENOTSUP || memcmp(&usage, &original_usage, sizeof(usage)) ||
      uv_os_get_passwd(&password) != UV_ENOTSUP || memcmp(&password, &original_password, sizeof(password)) ||
      uv_os_getpriority(uv_os_getpid(), &priority) != UV_ENOTSUP || priority != 123 ||
      uv_os_setpriority(uv_os_getpid(), 0) != UV_ENOTSUP ||
      uv_interface_addresses(&addresses, &count) != UV_ENOTSUP || addresses != &dummy || count != 456 ||
      uv_if_indextoiid(1, buffer, &size) != UV_ENOTSUP || strcmp(buffer, "untouched") || size != sizeof(buffer)) return 190;
  if (uv_getrusage(NULL) != UV_EINVAL || uv_getrusage_thread(NULL) != UV_EINVAL ||
      uv_os_get_passwd(NULL) != UV_EINVAL || uv_os_getpriority(0, NULL) != UV_EINVAL ||
      uv_interface_addresses(NULL, &count) != UV_EINVAL || uv_interface_addresses(&addresses, NULL) != UV_EINVAL ||
      uv_if_indextoiid(1, NULL, &size) != UV_EINVAL || uv_if_indextoiid(1, buffer, NULL) != UV_EINVAL) return 191;
  uv_free_interface_addresses(NULL, 0);
  if (uv_os_homedir(buffer, &size) != UV_ENOTSUP || strcmp(buffer, "untouched") || size != sizeof(buffer)) return 192;
  if (uv_os_setenv("HOME", "/src")) return 193;
  size = 2;
  if (uv_os_homedir(buffer, &size) != UV_ENOBUFS || size != 5 || strcmp(buffer, "untouched")) return 194;
  size = sizeof(buffer);
  if (uv_os_homedir(buffer, &size) || size != 4 || strcmp(buffer, "/src") ||
      uv_os_homedir(NULL, &size) != UV_EINVAL || uv_os_homedir(buffer, NULL) != UV_EINVAL) return 195;
  if (uv_os_unsetenv("HOME")) return 196;
  size = sizeof(buffer);
  if (uv_os_homedir(buffer, &size) != UV_ENOTSUP || strcmp(buffer, "/src")) return 197;
  puts("UV OS denied=7 untouched=1 home_explicit=1 no_account_fallback=1 PASS");
  return 0;
}

struct work_test {
  uv_loop_t loop;
  uv_work_t job, cancelled, no_after;
  uv_fs_t fs;
  uv_timer_t timer;
  unsigned worked, after, cancelled_count, no_after_count, file_count, ticks, freed;
  int failed;
  uv_thread_t identity;
};
static void cpu_test_work(uv_work_t* req) {
  struct work_test* s = req->data;
  s->worked++;
  if (uv_thread_self() != s->identity || uv_cancel((uv_req_t*) req) != UV_EBUSY ||
      uv_loop_close(&s->loop) != UV_EBUSY) s->failed = 1;
  uv_sleep(1);
  if (uv_thread_self() != s->identity) s->failed = 1;
}
static void cpu_test_after(uv_work_t* req, int status) {
  struct work_test* s = req->data;
  if (status || s->worked != ++s->after || uv_cancel((uv_req_t*) req) != UV_EBUSY) s->failed = 1;
  if (s->after < 3 && uv_queue_work(&s->loop, req, cpu_test_work, cpu_test_after)) s->failed = 1;
}
static void cpu_test_never(uv_work_t* req) { ((struct work_test*) req->data)->failed = 1; }
static void cpu_test_cancelled(uv_work_t* req, int status) {
  struct work_test* s = req->data;
  if (status != UV_ECANCELED) s->failed = 1;
  s->cancelled_count++;
}
static void cpu_test_no_after(uv_work_t* req) { ((struct work_test*) req->data)->no_after_count++; }
static void cpu_test_free(uv_work_t* req, int status) {
  struct work_test* s = req->data;
  if (status) s->failed = 1;
  s->freed++;
  free(req);
}
static void cpu_test_file(uv_fs_t* req) {
  struct work_test* s = req->data;
  if (req->result) s->failed = 1;
  s->file_count++;
  uv_fs_req_cleanup(req);
}
static void cpu_test_timer(uv_timer_t* timer) {
  struct work_test* s = timer->data;
  s->ticks++;
  if (s->after == 3) uv_close((uv_handle_t*) timer, NULL);
}
static int work_queue_smoke(void) {
  struct work_test s = {0};
  if (uv_loop_init(&s.loop)) return 180;
  s.identity = uv_thread_self();
  s.job.data = s.cancelled.data = s.no_after.data = s.fs.data = &s;
  if (uv_queue_work(NULL, &s.job, cpu_test_work, NULL) != UV_EINVAL ||
      uv_queue_work(&s.loop, NULL, cpu_test_work, NULL) != UV_EINVAL ||
      uv_queue_work(&s.loop, &s.job, NULL, NULL) != UV_EINVAL || uv_loop_alive(&s.loop)) return 181;
  if (uv_timer_init(&s.loop, &s.timer)) return 182;
  s.timer.data = &s;
  if (uv_timer_start(&s.timer, cpu_test_timer, 0, 1) ||
      uv_queue_work(&s.loop, &s.cancelled, cpu_test_never, cpu_test_cancelled) ||
      uv_cancel((uv_req_t*) &s.cancelled) || uv_cancel((uv_req_t*) &s.cancelled) != UV_EBUSY ||
      uv_queue_work(&s.loop, &s.job, cpu_test_work, cpu_test_after) ||
      uv_queue_work(&s.loop, &s.no_after, cpu_test_no_after, NULL) ||
      uv_fs_access(&s.loop, &s.fs, "/", 0, cpu_test_file)) return 183;
  uv_work_t* released = malloc(sizeof(*released));
  if (!released) return 184;
  released->data = &s;
  if (uv_queue_work(&s.loop, released, cpu_test_no_after, cpu_test_free) ||
      s.worked || s.after || s.cancelled_count || s.no_after_count || s.file_count || s.freed) return 185;
  if (uv_loop_close(&s.loop) != UV_EBUSY || !uv_run(&s.loop, UV_RUN_NOWAIT) ||
      s.cancelled_count != 1 || s.worked || s.file_count != 1 || s.failed) return 186;
  if (uv_run(&s.loop, UV_RUN_DEFAULT) || s.worked != 3 || s.after != 3 ||
      s.cancelled_count != 1 || s.no_after_count != 2 || s.file_count != 1 ||
      s.freed != 1 || s.ticks < 3 || s.failed || uv_loop_alive(&s.loop) || uv_loop_close(&s.loop)) return 187;
  puts("UV WORK deferred=1 worked=3 requeued=2 cancelled=1 busy=1 fs=1 timers=1 freed=1 PASS");
  return 0;
}

static unsigned thread_entries;
static void excluded_thread(void* arg) { (void) arg; thread_entries++; }
static int thread_exclusions(void) {
  uv_thread_t tid = 12345;
  uv_thread_options_t options = { UV_THREAD_HAS_STACK_SIZE, 65536 };
  if (uv_thread_create(&tid, excluded_thread, NULL) != UV_ENOTSUP || tid != 12345 ||
      uv_thread_create_ex(&tid, &options, excluded_thread, NULL) != UV_ENOTSUP || tid != 12345 ||
      uv_thread_join(&tid) != UV_ENOTSUP || tid != 12345 ||
      uv_thread_setname("unsupported-thread") != UV_ENOTSUP || thread_entries) return 170;
  if (uv_thread_create(NULL, excluded_thread, NULL) != UV_EINVAL ||
      uv_thread_create(&tid, NULL, NULL) != UV_EINVAL ||
      uv_thread_create_ex(&tid, NULL, excluded_thread, NULL) != UV_EINVAL ||
      uv_thread_create_ex(&tid, &options, NULL, NULL) != UV_EINVAL ||
      uv_thread_create_ex(NULL, &options, excluded_thread, NULL) != UV_EINVAL ||
      uv_thread_join(NULL) != UV_EINVAL || uv_thread_setname(NULL) != UV_EINVAL) return 171;
  uv_thread_t current = uv_thread_self();
  uv_sleep(1);
  if (thread_entries || tid != 12345 || uv_thread_self() != current ||
      options.flags != UV_THREAD_HAS_STACK_SIZE || options.stack_size != 65536) return 172;
  puts("UV THREAD denied=4 untouched=1 entries=0 identity=1 PASS");
  return 0;
}

static int process_metadata(void) {
  char title[32] = {0};
  if (uv_get_process_title(title, sizeof(title)) || strcmp(title, "gate-v8")) return 150;
  uv_pid_t pid = uv_os_getpid();
  if (pid <= 0 || (uv_thread_t) pid != uv_thread_self() || uv_os_getppid() != 0) return 151;
  uv_sleep(1);
  if (uv_os_getpid() != pid) return 152;
  char name[] = "native-node";
  char arg[] = "--jitless";
  char* args[] = { name, arg, NULL };
  if (uv_setup_args(2, args) != args || strcmp(name, "native-node") || strcmp(arg, "--jitless")) return 153;
  memset(name, 'x', sizeof(name) - 1);
  if (uv_get_process_title(title, sizeof(title)) || strcmp(title, "native-node")) return 154;
  char small[4] = "old";
  if (uv_get_process_title(small, sizeof(small)) != UV_ENOBUFS || strcmp(small, "old") ||
      uv_get_process_title(NULL, 2) != UV_EINVAL || uv_get_process_title(small, 0) != UV_EINVAL ||
      uv_set_process_title(NULL) != UV_EINVAL) return 155;
  char huge[4098];
  memset(huge, 'a', sizeof(huge));
  huge[sizeof(huge) - 1] = 0;
  if (uv_set_process_title(huge) != UV_E2BIG ||
      uv_get_process_title(title, sizeof(title)) || strcmp(title, "native-node")) return 156;
  if (uv_set_process_title("") || uv_get_process_title(title, sizeof(title)) || title[0]) return 157;
  if (uv_set_process_title("gate-v8") || uv_get_process_title(title, sizeof(title)) || strcmp(title, "gate-v8")) return 158;
  size_t size = sizeof(small);
  if (uv_exepath(small, &size) != UV_ENOTSUP || size != sizeof(small) || strcmp(small, "old") ||
      uv_exepath(NULL, &size) != UV_EINVAL || uv_exepath(small, NULL) != UV_EINVAL) return 159;
  uv_disable_stdio_inheritance();
  if (uv_guess_handle(0) != UV_NAMED_PIPE || uv_guess_handle(1) != UV_NAMED_PIPE ||
      uv_guess_handle(2) != UV_NAMED_PIPE) return 160;
  puts("UV PROCESS title_owned=1 isolation=1 bounds=1 identity=1 exepath_unsupported=1 stdio=1 PASS");
  return 0;
}

static int memory_queries(void) {
  uint64_t total = uv_get_total_memory();
  uint64_t before = uv_get_free_memory();
  if (!total || !before || before > total || uv_get_constrained_memory() != 0 ||
      !uv_get_available_memory() || uv_get_available_memory() > total) return 140;
  size_t rss = 123;
  if (uv_resident_set_memory(&rss) != UV_ENOTSUP || rss != 123 ||
      uv_resident_set_memory(NULL) != UV_EINVAL) return 141;
  void* page = vibeos_native_pages_allocate(NULL, 4096, 4096, VIBEOS_PAGE_READ_WRITE);
  if (!page) return 142;
  uint64_t after = uv_get_free_memory();
  if (after >= before || before - after < 4096 || uv_get_total_memory() != total ||
      vibeos_native_pages_release(page, 4096)) return 143;
  /* The page pool keeps its physical backing for subsequent V8 allocations. */
  puts("UV MEMORY measured=1 allocation_visible=1 quota_unknown=1 rss_unsupported=1 PASS");
  return 0;
}

int vibeos_uv_sync_smoke(void) {
  int system = system_information();
  if (system) return system;
  int os = os_boundaries();
  if (os) return os;
  int work = work_queue_smoke();
  if (work) return work;
  int threads = thread_exclusions();
  if (threads) return threads;
  int process = process_metadata();
  if (process) return process;
  int memory = memory_queries();
  if (memory) return memory;
  int ipc_tty = ipc_tty_exclusions();
  if (ipc_tty) return ipc_tty;
  int environment = environment_smoke();
  if (environment) return environment;
  int stream = stream_handles();
  if (stream) return stream;
  int network = network_exclusions();
  if (network) return network;
  int excluded = exclusions();
  if (excluded) return excluded;
  uv_timespec64_t mono, realtime, after;
  uv_timeval64_t wall;
  double uptime;
  if (uv_clock_gettime(UV_CLOCK_MONOTONIC, &mono) ||
      uv_clock_gettime(UV_CLOCK_REALTIME, &realtime) || uv_gettimeofday(&wall) ||
      uv_uptime(&uptime)) return 30;
  if (mono.tv_nsec < 0 || mono.tv_nsec >= 1000000000 ||
      realtime.tv_nsec < 0 || realtime.tv_nsec >= 1000000000 ||
      wall.tv_usec < 0 || wall.tv_usec >= 1000000) return 31;
  if (uptime < (double) mono.tv_sec || wall.tv_sec < realtime.tv_sec ||
      wall.tv_sec - realtime.tv_sec > 1) return 32;
  after = mono;
  if (uv_clock_gettime((uv_clock_id) 999, &after) != UV_EINVAL ||
      after.tv_sec != mono.tv_sec || after.tv_nsec != mono.tv_nsec ||
      uv_gettimeofday(NULL) != UV_EINVAL || uv_uptime(NULL) != UV_EINVAL) return 33;
  uv_thread_t identity = uv_thread_self();
  if (!identity || !uv_thread_equal(&identity, &identity) ||
      uv_available_parallelism() != 1) return 34;
  uint64_t clock_before = uv_hrtime();
  uv_sleep(0);
  uv_sleep(3);
  if (uv_hrtime() - clock_before < 3000000 || uv_thread_self() != identity ||
      uv_clock_gettime(UV_CLOCK_MONOTONIC, &after) || after.tv_sec < mono.tv_sec)
    return 35;
  puts("UV CLOCK realtime=1 monotonic=1 sleep=1 identity=1 PASS");
  uv_mutex_t mutex;
  uv_sem_t sem;
  uv_cond_t cond;
  if (uv_sem_init(&sem, UINT_MAX) != UV_EINVAL) return 1;
  if (uv_sem_init(&sem, 2)) return 2;
  if (uv_sem_trywait(&sem) || uv_sem_trywait(&sem) ||
      uv_sem_trywait(&sem) != UV_EAGAIN) return 3;
  uv_sem_post(&sem);
  uv_sem_wait(&sem);
  if (uv_sem_trywait(&sem) != UV_EAGAIN) return 4;
  uv_sem_destroy(&sem);
  if (uv_mutex_init_recursive(&mutex)) return 5;
  uv_mutex_lock(&mutex);
  if (uv_mutex_trylock(&mutex)) return 6;
  uv_mutex_unlock(&mutex);
  uv_mutex_unlock(&mutex);
  uv_mutex_destroy(&mutex);
  if (uv_mutex_init(&mutex) || uv_cond_init(&cond)) return 7;
  uv_mutex_lock(&mutex);
  if (uv_mutex_trylock(&mutex) != UV_EBUSY) return 8;
  uint64_t before = uv_hrtime();
  if (uv_cond_timedwait(&cond, &mutex, 2000000) != UV_ETIMEDOUT) return 9;
  if (uv_hrtime() - before < 2000000) return 10;
  /* A timed-out wait must return owning the mutex again. */
  if (uv_mutex_trylock(&mutex) != UV_EBUSY) return 11;
  uv_cond_signal(&cond);
  uv_cond_broadcast(&cond);
  uv_mutex_unlock(&mutex);
  uv_cond_destroy(&cond);
  uv_mutex_destroy(&mutex);
  uv_rwlock_t rw;
  if (uv_rwlock_init(&rw)) return 20;
  uv_rwlock_rdlock(&rw);
  if (uv_rwlock_tryrdlock(&rw)) return 21;
  if (uv_rwlock_trywrlock(&rw) != UV_EBUSY) return 22;
  uv_rwlock_rdunlock(&rw);
  if (uv_rwlock_trywrlock(&rw) != UV_EBUSY) return 23;
  uv_rwlock_rdunlock(&rw);
  uv_rwlock_wrlock(&rw);
  if (uv_rwlock_tryrdlock(&rw) != UV_EBUSY ||
      uv_rwlock_trywrlock(&rw) != UV_EBUSY) return 24;
  uv_rwlock_wrunlock(&rw);
  if (uv_rwlock_trywrlock(&rw)) return 25;
  uv_rwlock_wrunlock(&rw);
  uv_rwlock_destroy(&rw);
  puts("UV RWLOCK readers=2 exclusive=1 busy=4 PASS");
  for (unsigned i = 0; i < 8; i++) {
    uv_loop_t loop = {0};
    uv_timer_t timer;
    uv_metrics_t metrics;
    if (uv_loop_init(&loop)) return 12;
    if (uv_metrics_idle_time(&loop) != 0) return 13;
    if (uv_loop_configure(&loop, UV_METRICS_IDLE_TIME)) return 14;
    if (uv_timer_init(&loop, &timer) ||
        uv_timer_start(&timer, metric_timer, 3, 0)) return 15;
    uint64_t start = uv_hrtime();
    if (uv_run(&loop, UV_RUN_DEFAULT)) return 16;
    uint64_t idle = uv_metrics_idle_time(&loop);
    if (!idle || idle > uv_hrtime() - start) return 17;
    if (uv_metrics_info(&loop, &metrics) || !metrics.loop_count) return 18;
    if (uv_loop_close(&loop)) return 19;
  }
  puts("UV METRICS loops=8 idle_measured=1 closed=8 PASS");
  puts("UV SYNC recursive=2 permits=3 timeout_relocked=1 PASS");
  return 0;
}
