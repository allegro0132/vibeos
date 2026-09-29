# IPC/TTY exclusion and nonblocking standard streams

Filesystem IPC pipe bind/connect/name/chmod operations and TTY initialization,
mode changes and window-size queries return ENOTSUP. Missing pointer arguments
return EINVAL. No endpoint, request, handle registration or callback is created
by rejection. The standard-stream backend accepts nonblocking mode after fresh
fd validation and rejects blocking mode. Named-pipe handle type continues to
represent the invocation's granted byte streams, not ambient IPC sockets.

Node's PipeWrap IPC constructor now throws ERR_VIBEOS_UNSUPPORTED before its
upstream constructor can CHECK a failed uv_pipe_init. Non-IPC constructors remain
available. The Node static archive builds and patch 52 applies with zero fuzz
to the previous freshly prepared source. A prospective Node JS assertion is
added, but has not executed. TTYWrap already handles an initialization error
by marking its wrapper uninitialized; no new Node TTY guard is needed here.

QEMU verifies eight libuv rejection APIs preserve handles/requests/name buffer/
size/window dimensions, create no connection callback and permit clean loop
closure. It checks blocking-mode rejection and nonblocking-mode admission on an
actual granted stdin pipe; subsequent stream read/write/shutdown tests pass.
Cumulative real-V8/libuv tests return zero with 101 parks, zero waiters, normal
shutdown and a 305733248-byte allocator peak.

No IPC/TTY functionality is implemented or claimed. Node JS error behavior,
complete Node execution and the full TypeScript toolchain remain unaccepted.
