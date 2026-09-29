# Libuv queued filesystem cancellation

uv_cancel now recognizes backend-admitted filesystem requests. A queued-work
trampoline distinguishes never-started work from backend-owned operations.
Cancel before first polling records UV_ECANCELED while retaining registration,
path/buffer storage and the original completion callback. The loop delivers
that callback exactly once before cleanup. Started, completed or already
cancelled requests return UV_EBUSY. Other request types return UV_EINVAL.
Already-started mutation publication is never falsely represented as rolled back.

QEMU verifies queued unlink cancellation is deferred, the loop stays busy until
completion, exactly one cancelled callback occurs, repeated/late cancel returns
busy, and the file remains intact. The same request storage is reused by the
subsequent successful async unlink test. A stdin read is first polled while
waiting for its delayed producer; cancellation then returns busy and the read
later completes normally. All earlier gates pass with 35 parks and zero waiters.

This is request cancellation, NOT JavaScript execution cancellation. Infinite
loop interruption, Node Stop/cleanup, mid-publication mutation handling and
full Node runtime/lifecycle acceptance remain pending.
