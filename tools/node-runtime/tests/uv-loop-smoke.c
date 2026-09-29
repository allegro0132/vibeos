/* Real-target libuv loop prerequisite, not Node execution acceptance. */
#include "uv.h"
#include <stdio.h>
#include <string.h>

struct state {
  uv_loop_t loop;
  uv_timer_t timer;
  uv_async_t async;
  uv_prepare_t prepare;
  uv_check_t check;
  uv_fs_t read;
  uv_fs_t writes[9];
  char output[1024];
  unsigned written, write_callbacks;
  char input[16];
  unsigned read_bytes;
  unsigned timers, notifications, closed, prepared, checked;
  uint64_t last;
  int failed;
};

static void write_done(uv_fs_t* req) {
  struct state* s = req->loop->data;
  if (req->result != sizeof(s->output)) s->failed = 1;
  else s->written += (unsigned) req->result;
  s->write_callbacks++;
  /* The ninth chunk exceeds the bounded pipe while its reader is delayed. */
  if (s->write_callbacks == 9 && s->timers != 3) s->failed = 1;
  uv_fs_req_cleanup(req);
}

static void read_done(uv_fs_t* req) {
  struct state* s = req->loop->data;
  if (req->result != 8 || memcmp(s->input, "uv-ready", 8) || s->timers != 3)
    s->failed = 1;
  else s->read_bytes = 8;
  uv_fs_req_cleanup(req);
}

static void closed(uv_handle_t* h) {
  struct state* s = h->loop->data;
  s->closed++;
}

static void prepare(uv_prepare_t* h) {
  struct state* s = h->loop->data;
  s->prepared++;
}

static void check(uv_check_t* h) {
  struct state* s = h->loop->data;
  if (s->checked >= s->prepared) s->failed = 1;
  s->checked++;
}

static void notified(uv_async_t* h) {
  struct state* s = h->loop->data;
  s->notifications++;
}

static void tick(uv_timer_t* h) {
  struct state* s = h->loop->data;
  uint64_t now = uv_now(h->loop);
  if (s->timers && now - s->last < 2) s->failed = 1;
  s->last = now;
  if (++s->timers == 3) {
    uv_close((uv_handle_t*) h, closed);
    uv_close((uv_handle_t*) &s->prepare, closed);
    uv_close((uv_handle_t*) &s->check, closed);
  }
}

int vibeos_uv_loop_smoke(void) {
  struct state s;
  memset(&s, 0, sizeof(s));
  s.loop.data = &s;
  if (uv_loop_init(&s.loop) || uv_timer_init(&s.loop, &s.timer)) return 1;
  if (uv_loop_close(&s.loop) != UV_EBUSY) return 2;
  if (uv_timer_start(&s.timer, tick, 100000, 0)) return 3;
  if (uv_run(&s.loop, UV_RUN_NOWAIT) != 1 || s.timers != 0) return 4;
  if (uv_timer_stop(&s.timer)) return 5;
  uv_buf_t input = { s.input, sizeof(s.input) };
  if (uv_fs_read(&s.loop, &s.read, 0, &input, 1, -1, read_done) ||
      s.read_bytes != 0) return 11;
  if (uv_async_init(&s.loop, &s.async, notified) ||
      uv_prepare_init(&s.loop, &s.prepare) ||
      uv_check_init(&s.loop, &s.check)) return 6;
  /* An async callback need not close its handle. ONCE must still return. */
  if (uv_async_send(&s.async) || uv_async_send(&s.async) ||
      uv_run(&s.loop, UV_RUN_ONCE) != 1 || s.notifications != 1 ||
      !uv_is_active((uv_handle_t*) &s.async)) return 10;
  if (uv_cancel((uv_req_t*) &s.read) != UV_EBUSY) return 14;
  uv_close((uv_handle_t*) &s.async, closed);
  if (uv_prepare_start(&s.prepare, prepare) ||
      uv_check_start(&s.check, check) ||
      uv_timer_start(&s.timer, tick, 10, 2)) return 7;
  memset(s.output, 'X', sizeof(s.output));
  uv_buf_t output = { s.output, sizeof(s.output) };
  for (unsigned i = 0; i < 9; ++i)
    if (uv_fs_write(&s.loop, &s.writes[i], 1, &output, 1, -1, write_done) ||
        s.write_callbacks != 0) return 12;
  if (uv_run(&s.loop, UV_RUN_DEFAULT) != 0 || s.failed ||
      s.timers != 3 || s.notifications != 1 || s.closed != 4 || s.read_bytes != 8 ||
      s.prepared == 0 || s.checked != s.prepared || uv_loop_alive(&s.loop))
    return 8;
  if (s.written != 9216 || s.write_callbacks != 9) return 13;
  if (uv_loop_close(&s.loop)) return 9;
  printf("UV LOOP timers=%u async=%u closed=%u phases=%u read=%u written=%u PASS\n",
         s.timers, s.notifications, s.closed, s.checked, s.read_bytes, s.written);
  puts("UV CANCEL started_busy=1 read_completed=1 PASS");
  return 0;
}
