# Queued standard-stream writes

`uv_write` and non-IPC `uv_write2` copy the buffer descriptor array, register
requests on the event loop and retain caller data buffers until completion.
The backend advances one bounded native transfer per handle per poll. A short
transfer updates the current vector and write_queue_size; a full pipe registers
a native notification and allows the native task to suspend. Callbacks execute
only in the loop completion phase, with request storage released beforehand.
No callback runs on the Rust scheduler stack. Handles track active write work.

Closing a stream cancels remaining queued requests, releases queued-byte
accounting and closes the native endpoint. Completion callbacks precede the
handle close callback. Previously completed requests retain their result.
Attempting to pass another handle through uv_write2 returns ENOTSUP without
initializing the request. uv_try_write cannot overtake queued writes.

QEMU run 2 passes the cumulative V8/libuv gate. The stream fixture submits
16 KiB across five vectors (one empty), overwrites the submitted descriptor
array, observes partial progress without callbacks in UV_RUN_NOWAIT, and then
verifies exactly 16 KiB of ordered data followed by a second request's marker.
A completion callback queues another write and closes the stream: its callback
receives ECANCELED before the deferred close callback, and its data is absent
from the UART log. Queue size and active state return to zero. The transport
has eight 1024-byte slots, so the transfer exceeds its capacity; the cumulative
gate uses 71 parks, zero remaining waiters, normal shutdown and a 305729152-byte
global allocator peak. Run 1 predates the active-state accounting adjustment;
run 2 includes it and removes the target compiler type-limits warning.

These checks do not establish full Node execution, read_start/read_stop,
shutdown, duplicate-descriptor ownership, revocation during stream writes or
100-invocation lifecycle isolation. Existing fs IO and V8 gates also pass, but
Node firmware linking and TypeScript toolchain acceptance remain incomplete.
