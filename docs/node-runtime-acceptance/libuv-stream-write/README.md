# Nonblocking standard-stream writes

`uv_try_write` uses the invocation-local native nonblocking writer. It validates
all vectors before output, refuses input-only/closed handles, preserves queued
write ordering, permits bounded short transfers, and maps pending to EAGAIN.
It retains neither buffers nor callbacks and never parks the native stack.

Run 3 passes the cumulative QEMU V8/libuv gate: actual three-vector output
(including an empty vector), invalid vectors, input direction rejection,
post-close rejection and deferred close completion. The handle owns stdout and
is closed after the final V8/newlib stdio flush. There are 69 parks, zero waiters,
normal shutdown, and a 305729152-byte global allocator peak.

Runs 1 and 2 returned zero in firmware but failed the output assertion because
VSH inserts prompt redraws between vector deliveries. Run 3 strips only the
exact redraw sequence (with read_text newline normalization) for this assertion.
Raw UART logs and all three reports are retained.

This does not qualify short transfers or EAGAIN through stream handles under
backpressure yet. Queued uv_write, stream reads/shutdown, duplicate descriptor
ownership and full Node execution remain pending. No Node milestone is claimed.
