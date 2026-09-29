# Invocation-local standard-stream handle lifecycle

The new stream backend implements descriptor classification, non-IPC pipe
initialization, standard-stream attachment, descriptor queries, direction checks
and empty IPC pending queries. Pipe attachment admits only the invocation's
live standard descriptors 0/1/2; no ambient socket/fd import exists. Successful
attachment transfers close ownership to the handle. uv_close removes stream
directions, closes the native endpoint and dispatches its close callback through
the existing loop closing phase. An initialized but unattached handle can also
be closed; no write/read requests have been admitted by this backend yet.

QEMU verifies all three standard descriptors classify as pipes, invalid and
closed descriptors classify unknown, and an open regular file classifies as a
file. It attaches stdin after the earlier IO fixture consumes input, verifies
read-only direction, preserves handle data, rejects duplicate attachment and
IPC initialization, preserves failed fileno output, observes EBUSY loop close
while a handle remains, and checks one deferred close callback and native fd
closure. Cumulative V8/libuv checks pass with 69 parks, zero waiters, normal
shutdown and 305729152-byte allocator peak.

This is handle lifecycle evidence. Stream read_start/write/shutdown, output
backpressure through stream handles, duplicate-fd ownership, cancellation with
active stream requests and complete Node stdio still require implementation and
qualification. No new Node/TypeScript runtime milestone is established.
