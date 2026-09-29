QEMU passes nine concurrent libuv fs-write requests against the actual bounded
stdout transport. Each request submits a 1024-byte buffer; the pipe holds eight
chunks, while its Rust reader sleeps for 100 ms. The ninth completion must see
all three timer callbacks already executed. The consumer checks every byte and
exactly 9216 bytes before draining normal V8 output. Completion is not inline.
The same loop also reads delayed stdin; the subsequent real V8 gate passes.
The native runner returns with 12 parks and zero stream waiters.

The new Rust try-write bridge stages at most 1024 bytes and polls once. A full
pipe retains only the notification waker, never the input pointer or a native
callback. Libuv retains the user buffer according to its ordinary request
lifetime and re-polls from the protected native stack. Sync writes still use
the existing suspendable bridge. Short writes are explicit and legal.

Scope: uv_fs_read/write with offset=-1 on granted standard streams, plus the
existing timer/async prerequisites. This does not establish uv_stream/pipe,
regular-file async IO, positioned IO, request cancellation, outstanding-write
revocation, all buffer-vector semantics or Node execution. Memory figures are
whole-kernel accounting, not repeated invocation leak qualification. Kernel
probe input/output delays exist only under native-uv-probe. These passing
prerequisites are not a new completed Node milestone.
