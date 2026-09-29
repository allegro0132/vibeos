/* Explicit first-port exclusions. No handles, requests, callbacks or backend
 * work are admitted on failure. This file does not emulate successful calls. */
#include "uv.h"
#include "uv-common.h"
#include <math.h>

int uv_spawn(uv_loop_t* loop, uv_process_t* handle,
             const uv_process_options_t* options) {
  return !loop || !handle || !options ? UV_EINVAL : UV_ENOTSUP;
}
int uv_process_kill(uv_process_t* handle, int signum) {
  (void) signum;
  return !handle ? UV_EINVAL : UV_ENOTSUP;
}
int uv_kill(int pid, int signum) {
  (void) pid; (void) signum;
  return UV_ENOTSUP;
}
int uv_fs_event_init(uv_loop_t* loop, uv_fs_event_t* handle) {
  return !loop || !handle ? UV_EINVAL : UV_ENOTSUP;
}
int uv_fs_event_start(uv_fs_event_t* handle, uv_fs_event_cb cb,
                      const char* path, unsigned int flags) {
  (void) flags;
  return !handle || !cb || !path ? UV_EINVAL : UV_ENOTSUP;
}
int uv_fs_event_stop(uv_fs_event_t* handle) {
  return !handle ? UV_EINVAL : UV_ENOTSUP;
}
int uv_fs_poll_init(uv_loop_t* loop, uv_fs_poll_t* handle) {
  return !loop || !handle ? UV_EINVAL : UV_ENOTSUP;
}
int uv_fs_poll_start(uv_fs_poll_t* handle, uv_fs_poll_cb cb,
                     const char* path, unsigned int interval) {
  (void) interval;
  return !handle || !cb || !path ? UV_EINVAL : UV_ENOTSUP;
}
int uv_fs_poll_stop(uv_fs_poll_t* handle) {
  return !handle ? UV_EINVAL : UV_ENOTSUP;
}
int uv_fs_poll_getpath(uv_fs_poll_t* handle, char* buffer, size_t* size) {
  return !handle || !buffer || !size ? UV_EINVAL : UV_ENOTSUP;
}
int uv_signal_init(uv_loop_t* loop, uv_signal_t* handle) {
  return !loop || !handle ? UV_EINVAL : UV_ENOTSUP;
}
int uv_signal_start(uv_signal_t* handle, uv_signal_cb cb, int signum) {
  (void) signum;
  return !handle || !cb ? UV_EINVAL : UV_ENOTSUP;
}
int uv_signal_start_oneshot(uv_signal_t* handle, uv_signal_cb cb, int signum) {
  return uv_signal_start(handle, cb, signum);
}
int uv_signal_stop(uv_signal_t* handle) {
  return !handle ? UV_EINVAL : UV_ENOTSUP;
}

/* This invocation has no network capability. Pure address conversion remains
 * upstream; every socket operation fails without creating/importing a socket. */
int uv_tcp_init(uv_loop_t* loop, uv_tcp_t* handle) {
  (void) loop; (void) handle;
  return UV_ENOTSUP;
}
int uv_tcp_init_ex(uv_loop_t* loop, uv_tcp_t* handle, unsigned int flags) {
  (void) loop; (void) handle; (void) flags;
  return UV_ENOTSUP;
}
int uv_tcp_open(uv_tcp_t* handle, uv_os_sock_t socket) {
  (void) handle; (void) socket;
  return UV_ENOTSUP;
}
int uv_tcp_nodelay(uv_tcp_t* handle, int enable) {
  (void) handle; (void) enable;
  return UV_ENOTSUP;
}
int uv_tcp_keepalive(uv_tcp_t* handle, int enable, unsigned int delay) {
  (void) handle; (void) enable; (void) delay;
  return UV_ENOTSUP;
}
int uv_tcp_simultaneous_accepts(uv_tcp_t* handle, int enable) {
  (void) handle; (void) enable;
  return UV_ENOTSUP;
}
int uv_tcp_getsockname(const uv_tcp_t* handle, struct sockaddr* name, int* length) {
  (void) handle; (void) name; (void) length;
  return UV_ENOTSUP;
}
int uv_tcp_getpeername(const uv_tcp_t* handle, struct sockaddr* name, int* length) {
  (void) handle; (void) name; (void) length;
  return UV_ENOTSUP;
}
int uv_tcp_close_reset(uv_tcp_t* handle, uv_close_cb cb) {
  (void) handle; (void) cb;
  return UV_ENOTSUP;
}
int uv__tcp_bind(uv_tcp_t* handle, const struct sockaddr* address, unsigned int length, unsigned int flags) {
  (void) handle; (void) address; (void) length; (void) flags;
  return UV_ENOTSUP;
}
int uv__tcp_connect(uv_connect_t* request, uv_tcp_t* handle, const struct sockaddr* address, unsigned int length, uv_connect_cb cb) {
  (void) request; (void) handle; (void) address; (void) length; (void) cb;
  return UV_ENOTSUP;
}
int uv__udp_init_ex(uv_loop_t* loop, uv_udp_t* handle, unsigned flags, int domain) {
  (void) loop; (void) handle; (void) flags; (void) domain;
  return UV_ENOTSUP;
}
int uv_udp_open(uv_udp_t* handle, uv_os_sock_t socket) {
  (void) handle; (void) socket;
  return UV_ENOTSUP;
}
int uv_udp_getsockname(const uv_udp_t* handle, struct sockaddr* name, int* length) {
  (void) handle; (void) name; (void) length;
  return UV_ENOTSUP;
}
int uv_udp_getpeername(const uv_udp_t* handle, struct sockaddr* name, int* length) {
  (void) handle; (void) name; (void) length;
  return UV_ENOTSUP;
}
int uv_udp_set_membership(uv_udp_t* handle, const char* multicast, const char* interface, uv_membership membership) {
  (void) handle; (void) multicast; (void) interface; (void) membership;
  return UV_ENOTSUP;
}
int uv_udp_set_source_membership(uv_udp_t* handle, const char* multicast, const char* interface, const char* source, uv_membership membership) {
  (void) handle; (void) multicast; (void) interface; (void) source; (void) membership;
  return UV_ENOTSUP;
}
int uv_udp_set_multicast_loop(uv_udp_t* handle, int on) {
  (void) handle; (void) on;
  return UV_ENOTSUP;
}
int uv_udp_set_multicast_ttl(uv_udp_t* handle, int ttl) {
  (void) handle; (void) ttl;
  return UV_ENOTSUP;
}
int uv_udp_set_multicast_interface(uv_udp_t* handle, const char* interface) {
  (void) handle; (void) interface;
  return UV_ENOTSUP;
}
int uv_udp_set_broadcast(uv_udp_t* handle, int on) {
  (void) handle; (void) on;
  return UV_ENOTSUP;
}
int uv_udp_set_ttl(uv_udp_t* handle, int ttl) {
  (void) handle; (void) ttl;
  return UV_ENOTSUP;
}
int uv__udp_bind(uv_udp_t* handle, const struct sockaddr* address, unsigned int length, unsigned int flags) {
  (void) handle; (void) address; (void) length; (void) flags;
  return UV_ENOTSUP;
}
int uv__udp_connect(uv_udp_t* handle, const struct sockaddr* address, unsigned int length) {
  (void) handle; (void) address; (void) length;
  return UV_ENOTSUP;
}
int uv__udp_disconnect(uv_udp_t* handle) {
  (void) handle;
  return UV_ENOTSUP;
}
int uv__udp_send(uv_udp_send_t* request, uv_udp_t* handle, const uv_buf_t buffers[], unsigned int count, const struct sockaddr* address, unsigned int length, uv_udp_send_cb cb) {
  (void) request; (void) handle; (void) buffers; (void) count; (void) address; (void) length; (void) cb;
  return UV_ENOTSUP;
}
int uv__udp_try_send(uv_udp_t* handle, const uv_buf_t buffers[], unsigned int count, const struct sockaddr* address, unsigned int length) {
  (void) handle; (void) buffers; (void) count; (void) address; (void) length;
  return UV_ENOTSUP;
}
int uv__udp_try_send2(uv_udp_t* handle, unsigned int count, uv_buf_t* buffers[], unsigned int sizes[], struct sockaddr* addresses[]) {
  (void) handle; (void) count; (void) buffers; (void) sizes; (void) addresses;
  return UV_ENOTSUP;
}
int uv__udp_recv_start(uv_udp_t* handle, uv_alloc_cb alloccb, uv_udp_recv_cb cb) {
  (void) handle; (void) alloccb; (void) cb;
  return UV_ENOTSUP;
}
int uv__udp_recv_stop(uv_udp_t* handle) {
  (void) handle;
  return UV_ENOTSUP;
}
int uv_listen(uv_stream_t* stream, int backlog, uv_connection_cb cb) {
  (void) stream; (void) backlog; (void) cb;
  return UV_ENOTSUP;
}
int uv_accept(uv_stream_t* server, uv_stream_t* client) {
  (void) server; (void) client;
  return UV_ENOTSUP;
}

/* Standard streams are unnamed invocation pipes, not filesystem IPC sockets
 * or terminal devices. Rejection never initializes a request or handle. */
int uv_pipe_bind2(uv_pipe_t* handle, const char* name, size_t length, unsigned int flags) {
  (void) flags;
  return !handle || !name || !length ? UV_EINVAL : UV_ENOTSUP;
}
int uv_pipe_connect2(uv_connect_t* req, uv_pipe_t* handle, const char* name,
                     size_t length, unsigned int flags, uv_connect_cb cb) {
  (void) flags;
  return !req || !handle || !name || !length || !cb ? UV_EINVAL : UV_ENOTSUP;
}
int uv_pipe_getsockname(const uv_pipe_t* handle, char* buffer, size_t* size) {
  return !handle || !buffer || !size ? UV_EINVAL : UV_ENOTSUP;
}
int uv_pipe_getpeername(const uv_pipe_t* handle, char* buffer, size_t* size) {
  return !handle || !buffer || !size ? UV_EINVAL : UV_ENOTSUP;
}
int uv_pipe_chmod(uv_pipe_t* handle, int flags) {
  (void) flags;
  return !handle ? UV_EINVAL : UV_ENOTSUP;
}
int uv_tty_init(uv_loop_t* loop, uv_tty_t* handle, uv_file fd, int readable) {
  (void) fd; (void) readable;
  return !loop || !handle ? UV_EINVAL : UV_ENOTSUP;
}
int uv_tty_set_mode(uv_tty_t* handle, uv_tty_mode_t mode) {
  (void) mode;
  return !handle ? UV_EINVAL : UV_ENOTSUP;
}
int uv_tty_get_winsize(uv_tty_t* handle, int* width, int* height) {
  return !handle || !width || !height ? UV_EINVAL : UV_ENOTSUP;
}

/* Only the admitted native task exists. No user/native worker thread can be
 * created, joined, or renamed through an ambient OS thread service. */
int uv_thread_create(uv_thread_t* tid, uv_thread_cb entry, void* arg) {
  (void) arg;
  return !tid || !entry ? UV_EINVAL : UV_ENOTSUP;
}
int uv_thread_create_ex(uv_thread_t* tid, const uv_thread_options_t* options,
                        uv_thread_cb entry, void* arg) {
  (void) arg;
  return !tid || !options || !entry ? UV_EINVAL : UV_ENOTSUP;
}
int uv_thread_join(uv_thread_t* tid) {
  return !tid ? UV_EINVAL : UV_ENOTSUP;
}
int uv_thread_setname(const char* name) {
  return !name ? UV_EINVAL : UV_ENOTSUP;
}

/* There is no per-invocation CPU accounting, Unix account database, process
 * priority control, or granted network-interface enumeration service. */
int uv_getrusage(uv_rusage_t* usage) {
  return !usage ? UV_EINVAL : UV_ENOTSUP;
}
int uv_getrusage_thread(uv_rusage_t* usage) {
  return !usage ? UV_EINVAL : UV_ENOTSUP;
}
int uv_os_get_passwd(uv_passwd_t* password) {
  return !password ? UV_EINVAL : UV_ENOTSUP;
}
int uv_os_getpriority(uv_pid_t pid, int* priority) {
  (void) pid;
  return !priority ? UV_EINVAL : UV_ENOTSUP;
}
int uv_os_setpriority(uv_pid_t pid, int priority) {
  (void) pid; (void) priority;
  return UV_ENOTSUP;
}
int uv_interface_addresses(uv_interface_address_t** addresses, int* count) {
  return !addresses || !count ? UV_EINVAL : UV_ENOTSUP;
}
void uv_free_interface_addresses(uv_interface_address_t* addresses, int count) {
  /* No snapshots are currently produced. Keep the single-allocation cleanup
   * contract and permit the usual NULL cleanup without retaining state. */
  (void) count;
  uv__free(addresses);
}
int uv_if_indextoiid(unsigned int index, char* buffer, size_t* size) {
  (void) index;
  return !buffer || !size || !*size ? UV_EINVAL : UV_ENOTSUP;
}

int uv_cpu_info(uv_cpu_info_t** information, int* count) {
  return !information || !count ? UV_EINVAL : UV_ENOTSUP;
}
void uv_loadavg(double averages[3]) {
  /* The C API has no error return; mark every sample unavailable. Node's
   * binding throws ENOTSUP instead of presenting these as measured load. */
  if (averages) averages[0] = averages[1] = averages[2] = NAN;
}
