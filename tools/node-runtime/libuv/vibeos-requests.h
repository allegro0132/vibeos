#ifndef VIBEOS_UV_REQUESTS_H
#define VIBEOS_UV_REQUESTS_H
#include "uv.h"
#include "uv-common.h"
/* Extend only the backend-owned allocation; preserve upstream common prefix. */
struct vibeos_loop_internal {
  uv__loop_internal_fields_t common;
  struct uv__queue cpu_work;
};
int uv__vibeos_cancel_work(uv_work_t* req);
/* Poll without callbacks, then deliver completed requests on the native stack. */
int uv__vibeos_poll_requests(uv_loop_t* loop);
void uv__vibeos_run_requests(uv_loop_t* loop);
#endif
