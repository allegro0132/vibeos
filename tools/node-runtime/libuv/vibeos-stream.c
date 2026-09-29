/* Invocation-local standard-stream handles. There is no ambient fd import. */
#include "uv.h"
#include "uv-common.h"
#include "vibeos-stdio.h"
#include <limits.h>

/* queued_fds is unused because this backend never admits IPC. It owns this
 * read-ahead buffer instead; no caller allocation enters a readiness poll. */
struct stream_read {
  char bytes[1024];
  ptrdiff_t result;
  size_t offset;
  int deliver;
};

static int stream_error(ptrdiff_t result) {
  return result == -15 ? UV_EAGAIN : result == -3 ? UV_EACCES :
         result == -4 ? UV_EPIPE : result == -1 ? UV_EBADF : UV_EIO;
}

int uv__read_start(uv_stream_t* stream, uv_alloc_cb alloc_cb, uv_read_cb read_cb) {
  uv_os_fd_t fd;
  if (!stream || !alloc_cb || !read_cb) return UV_EINVAL;
  int error = uv_fileno((uv_handle_t*) stream, &fd);
  if (error) return error;
  if (!(stream->flags & UV_HANDLE_READABLE)) return UV_ENOTCONN;
  if (!stream->queued_fds) {
    struct stream_read* state = uv__calloc(1, sizeof(*state));
    if (!state) return UV_ENOMEM;
    state->result = -15;
    stream->queued_fds = state;
  }
  stream->alloc_cb = alloc_cb;
  stream->read_cb = read_cb;
  stream->flags |= UV_HANDLE_READING;
  stream->flags &= ~UV_HANDLE_READ_EOF;
  uv__handle_start(stream);
  return 0;
}

int uv_read_stop(uv_stream_t* stream) {
  if (!stream) return UV_EINVAL;
  if (stream->type != UV_NAMED_PIPE) return UV_ENOTSUP;
  stream->flags &= ~UV_HANDLE_READING;
  stream->alloc_cb = NULL;
  stream->read_cb = NULL;
  if (stream->queued_fds) ((struct stream_read*) stream->queued_fds)->deliver = 0;
  if (uv__queue_empty(&stream->write_queue)) uv__handle_stop(stream);
  return 0;
}

static void read_callback(uv_stream_t* stream) {
  struct stream_read* state = stream->queued_fds;
  uv_read_cb cb = stream->read_cb;
  uv_alloc_cb alloc_cb = stream->alloc_cb;
  uv_buf_t buf = {NULL, 0};
  uv_os_fd_t fd;
  state->deliver = 0;
  int error = uv_fileno((uv_handle_t*) stream, &fd);
  if (error || state->result <= 0) {
    int status = error ? error : state->result ? stream_error(state->result) : UV_EOF;
    state->result = -15;
    state->offset = 0;
    uv_read_stop(stream);
    if (status == UV_EOF) {
      stream->flags |= UV_HANDLE_READ_EOF;
      stream->flags &= ~UV_HANDLE_READABLE;
    }
    cb(stream, status, &buf);
    return;
  }
  alloc_cb((uv_handle_t*) stream, 65536, &buf);
  /* Allocation callbacks may stop/close the handle. Return their buffer for
   * release without dereferencing the possibly freed backend read state. */
  if (uv__is_closing(stream) || !(stream->flags & UV_HANDLE_READING)) {
    cb(stream, 0, &buf);
    return;
  }
  error = uv_fileno((uv_handle_t*) stream, &fd);
  if (error) {
    state->result = -15;
    state->offset = 0;
    uv_read_stop(stream);
    cb(stream, error, &buf);
    return;
  }
  if (!buf.base || !buf.len) {
    cb(stream, UV_ENOBUFS, &buf);
    return;
  }
  size_t count = (size_t) state->result - state->offset;
  if (count > buf.len) count = buf.len;
  memcpy(buf.base, state->bytes + state->offset, count);
  state->offset += count;
  if (state->offset == (size_t) state->result) {
    state->offset = 0;
    state->result = -15;
  }
  cb(stream, (ssize_t) count, &buf);
}

int uv_try_write(uv_stream_t* stream, const uv_buf_t bufs[], unsigned int nbufs) {
  uv_os_fd_t fd;
  if (!stream || !bufs || !nbufs) return UV_EINVAL;
  int error = uv_fileno((const uv_handle_t*) stream, &fd);
  if (error) return error;
  if (!(stream->flags & UV_HANDLE_WRITABLE)) return UV_EBADF;
  if (stream->connect_req || !uv__queue_empty(&stream->write_queue)) return UV_EAGAIN;
  /* Validate all vectors before delivering any bytes. Never retain buffers. */
  for (unsigned int i = 0; i < nbufs; i++)
    if (bufs[i].len && !bufs[i].base) return UV_EINVAL;
  int written = 0;
  for (unsigned int i = 0; i < nbufs; i++) {
    if (!bufs[i].len) continue;
    size_t count = bufs[i].len;
    if (count > (size_t) (INT_MAX - written)) count = INT_MAX - written;
    ptrdiff_t result = vibeos_native_try_write(fd, bufs[i].base, count);
    if (result < 0) {
      error = stream_error(result);
      return written ? written : error;
    }
    written += (int) result;
    if ((size_t) result < count || written == INT_MAX) break;
  }
  return written;
}

int uv_write2(uv_write_t* req, uv_stream_t* stream, const uv_buf_t bufs[],
              unsigned int nbufs, uv_stream_t* send_handle, uv_write_cb cb) {
  uv_os_fd_t fd;
  size_t total = 0;
  if (!req || !stream || !bufs || !nbufs) return UV_EINVAL;
  if (send_handle) return UV_ENOTSUP;
  int error = uv_fileno((const uv_handle_t*) stream, &fd);
  if (error) return error;
  if (!(stream->flags & UV_HANDLE_WRITABLE)) return UV_EBADF;
  for (unsigned int i = 0; i < nbufs; i++) {
    if (bufs[i].len && !bufs[i].base) return UV_EINVAL;
    if (bufs[i].len > SIZE_MAX - total) return UV_EINVAL;
    total += bufs[i].len;
  }
  if (total > SIZE_MAX - stream->write_queue_size ||
      sizeof(*bufs) > SIZE_MAX / nbufs) return UV_EINVAL;
  uv_buf_t* copy = req->bufsml;
  if (nbufs > ARRAY_SIZE(req->bufsml)) {
    copy = uv__malloc(nbufs * sizeof(*bufs));
    if (!copy) return UV_ENOMEM;
  }
  memcpy(copy, bufs, nbufs * sizeof(*bufs));
  uv__req_init(stream->loop, req, UV_WRITE);
  req->handle = stream;
  req->send_handle = NULL;
  req->cb = cb;
  req->bufs = copy;
  req->nbufs = nbufs;
  req->write_index = 0;
  req->error = 0;
  stream->write_queue_size += total;
  uv__queue_insert_tail(&stream->write_queue, &req->queue);
  uv__handle_start(stream);
  return 0;
}

int uv_write(uv_write_t* req, uv_stream_t* stream, const uv_buf_t bufs[],
             unsigned int nbufs, uv_write_cb cb) {
  return uv_write2(req, stream, bufs, nbufs, NULL, cb);
}

int uv_shutdown(uv_shutdown_t* req, uv_stream_t* stream, uv_shutdown_cb cb) {
  uv_os_fd_t fd;
  if (!req || !stream) return UV_EINVAL;
  if (stream->type != UV_NAMED_PIPE) return UV_ENOTSUP;
  if (!(stream->flags & UV_HANDLE_WRITABLE) || stream->shutdown_req ||
      (stream->flags & UV_HANDLE_SHUT) || uv__is_closing(stream)) return UV_ENOTCONN;
  int error = uv_fileno((uv_handle_t*) stream, &fd);
  if (error) return error;
  uv__req_init(stream->loop, req, UV_SHUTDOWN);
  req->handle = stream;
  req->cb = cb;
  stream->shutdown_req = req;
  stream->flags &= ~UV_HANDLE_WRITABLE;
  return 0;
}

static void shutdown_callback(uv_stream_t* stream) {
  uv_shutdown_t* req = stream->shutdown_req;
  uv_shutdown_cb cb = req->cb;
  int result = UV_ECANCELED;
  if (!uv__is_closing(stream)) {
    int status = vibeos_native_shutdown_write(stream->io_watcher.fd);
    result = status ? stream_error(status) : 0;
    if (!result) stream->flags |= UV_HANDLE_SHUT;
  }
  stream->shutdown_req = NULL;
  uv__req_unregister(stream->loop);
  if (cb) cb(req, result);
}

static void write_complete(uv_write_t* req, int error) {
  uv_stream_t* stream = req->handle;
  for (unsigned int i = req->write_index; i < req->nbufs; i++)
    stream->write_queue_size -= req->bufs[i].len;
  req->error = error;
  uv__queue_remove(&req->queue);
  uv__queue_insert_tail(&stream->write_completed_queue, &req->queue);
  if (uv__queue_empty(&stream->write_queue) && !(stream->flags & UV_HANDLE_READING))
    uv__handle_stop(stream);
}

/* One bounded native transfer per handle per poll. Progress requests another
 * loop iteration; a full pipe arms the native notification and permits sleep. */
int uv__vibeos_poll_streams(uv_loop_t* loop) {
  struct uv__queue* q;
  int ready = 0;
  uv__queue_foreach(q, &loop->handle_queue) {
    uv_handle_t* handle = uv__queue_data(q, uv_handle_t, handle_queue);
    if (handle->type != UV_NAMED_PIPE) continue;
    uv_stream_t* stream = (uv_stream_t*) handle;
    if (!uv__is_closing(handle) && (stream->flags & UV_HANDLE_READING)) {
      struct stream_read* state = stream->queued_fds;
      if (state->result == -15)
        state->result = vibeos_native_try_read(stream->io_watcher.fd, state->bytes, sizeof(state->bytes));
      if (state->result != -15) {
        state->deliver = 1;
        ready = 1;
      }
    }
    if (!uv__queue_empty(&stream->write_completed_queue)) ready = 1;
    if (stream->shutdown_req && uv__queue_empty(&stream->write_queue)) ready = 1;
    if (uv__is_closing(handle) || uv__queue_empty(&stream->write_queue)) continue;
    uv_write_t* req = uv__queue_data(uv__queue_head(&stream->write_queue), uv_write_t, queue);
    while (req->write_index < req->nbufs && !req->bufs[req->write_index].len)
      req->write_index++;
    if (req->write_index == req->nbufs) {
      write_complete(req, 0);
      ready = 1;
      continue;
    }
    uv_buf_t* buf = &req->bufs[req->write_index];
    ptrdiff_t n = vibeos_native_try_write(stream->io_watcher.fd, buf->base, buf->len);
    if (n == -15) continue;
    ready = 1;
    if (n <= 0) {
      write_complete(req, n ? stream_error(n) : UV_EIO);
      continue;
    }
    assert((size_t) n <= buf->len);
    buf->base += n;
    buf->len -= n;
    stream->write_queue_size -= n;
  }
  return ready;
}

static void write_callback(uv_write_t* req) {
  uv_write_cb cb = req->cb;
  int error = req->error;
  uv__queue_remove(&req->queue);
  uv__req_unregister(req->handle->loop);
  if (req->bufs != req->bufsml) uv__free(req->bufs);
  req->bufs = NULL;
  req->nbufs = 0;
  if (cb) cb(req, error); /* May free or reuse req and close any handle. */
}

void uv__vibeos_run_streams(uv_loop_t* loop) {
  for (;;) {
    struct uv__queue* q;
    uv_write_t* completed = NULL;
    uv_stream_t* shutdown = NULL;
    uv_stream_t* readable = NULL;
    uv__queue_foreach(q, &loop->handle_queue) {
      uv_handle_t* handle = uv__queue_data(q, uv_handle_t, handle_queue);
      if (handle->type != UV_NAMED_PIPE) continue;
      uv_stream_t* stream = (uv_stream_t*) handle;
      if (!uv__is_closing(handle) && (stream->flags & UV_HANDLE_READING) &&
          ((struct stream_read*) stream->queued_fds)->deliver) {
        readable = stream;
        break;
      }
      if (!uv__queue_empty(&stream->write_completed_queue)) {
        completed = uv__queue_data(uv__queue_head(&stream->write_completed_queue), uv_write_t, queue);
        break;
      }
      if (stream->shutdown_req && uv__queue_empty(&stream->write_queue)) {
        shutdown = stream;
        break;
      }
    }
    if (readable) read_callback(readable);
    else if (completed) write_callback(completed);
    else if (shutdown) shutdown_callback(shutdown);
    else return;
  }
}

void uv__vibeos_stream_finish_close(uv_stream_t* stream) {
  while (!uv__queue_empty(&stream->write_completed_queue))
    write_callback(uv__queue_data(uv__queue_head(&stream->write_completed_queue), uv_write_t, queue));
  if (stream->shutdown_req) shutdown_callback(stream);
}

uv_handle_type uv_guess_handle(uv_file fd) {
  int kind = vibeos_native_fd_kind(fd);
  return kind == 1 ? UV_NAMED_PIPE : kind == 2 ? UV_FILE : UV_UNKNOWN_HANDLE;
}

int uv_pipe_init(uv_loop_t* loop, uv_pipe_t* pipe, int ipc) {
  if (!loop || !pipe) return UV_EINVAL;
  if (ipc) return UV_ENOTSUP;
  void* data = pipe->data;
  memset(pipe, 0, sizeof(*pipe));
  pipe->data = data;
  pipe->io_watcher.fd = -1;
  pipe->accepted_fd = -1;
  uv__queue_init(&pipe->write_queue);
  uv__queue_init(&pipe->write_completed_queue);
  uv__handle_init(loop, (uv_handle_t*) pipe, UV_NAMED_PIPE);
  return 0;
}

int uv_pipe_open(uv_pipe_t* pipe, uv_file fd) {
  if (!pipe || pipe->type != UV_NAMED_PIPE || uv__is_closing(pipe)) return UV_EINVAL;
  if (pipe->io_watcher.fd != -1) return UV_EBUSY;
  int kind = vibeos_native_fd_kind(fd);
  if (kind < 0) return kind == -3 ? UV_EACCES : UV_EBADF;
  if (kind != 1 || fd < 0 || fd > 2) return UV_EINVAL;
  pipe->io_watcher.fd = fd;
  pipe->flags |= fd == 0 ? UV_HANDLE_READABLE : UV_HANDLE_WRITABLE;
  return 0;
}

int uv_fileno(const uv_handle_t* handle, uv_os_fd_t* fd) {
  if (!handle || !fd) return UV_EINVAL;
  if (handle->type != UV_NAMED_PIPE) return UV_ENOTSUP;
  const uv_stream_t* stream = (const uv_stream_t*) handle;
  if (uv__is_closing(handle) || stream->io_watcher.fd < 0) return UV_EBADF;
  int kind = vibeos_native_fd_kind(stream->io_watcher.fd);
  if (kind < 0) return kind == -3 ? UV_EACCES : UV_EBADF;
  *fd = stream->io_watcher.fd;
  return 0;
}

int uv_is_readable(const uv_stream_t* stream) {
  uv_os_fd_t fd;
  return stream && (stream->flags & UV_HANDLE_READABLE) &&
         uv_fileno((const uv_handle_t*) stream, &fd) == 0;
}
int uv_is_writable(const uv_stream_t* stream) {
  uv_os_fd_t fd;
  return stream && (stream->flags & UV_HANDLE_WRITABLE) &&
         uv_fileno((const uv_handle_t*) stream, &fd) == 0;
}
int uv_stream_set_blocking(uv_stream_t* stream, int blocking) {
  uv_os_fd_t fd;
  int error = uv_fileno((const uv_handle_t*) stream, &fd);
  if (error) return error;
  // This backend implements only notification-driven, nonblocking stream IO.
  return blocking ? UV_ENOTSUP : 0;
}
int uv_pipe_pending_count(uv_pipe_t* handle) {
  (void) handle;
  return 0; /* IPC handles cannot be admitted by uv_pipe_init. */
}
uv_handle_type uv_pipe_pending_type(uv_pipe_t* handle) {
  (void) handle;
  return UV_UNKNOWN_HANDLE;
}

void uv__vibeos_stream_close(uv_stream_t* stream) {
  uv_read_stop(stream);
  uv__free(stream->queued_fds);
  stream->queued_fds = NULL;
  while (!uv__queue_empty(&stream->write_queue))
    write_complete(uv__queue_data(uv__queue_head(&stream->write_queue), uv_write_t, queue), UV_ECANCELED);
  assert(stream->write_queue_size == 0);
  uv__handle_stop(stream);
  stream->flags &= ~(UV_HANDLE_READABLE | UV_HANDLE_WRITABLE);
  if (stream->io_watcher.fd >= 0) {
    vibeos_native_close(stream->io_watcher.fd);
    stream->io_watcher.fd = -1;
  }
}
