# Standard-stream shutdown

`uv_shutdown` registers an asynchronous request, rejects subsequent writes,
and waits for the queued writes and their callbacks before invoking the native
output shutdown. This marks the unidirectional standard-stream pipe closed,
allowing its reader to drain buffered data then observe EOF; descriptor ownership
remains until uv_close. Shutdown completion runs on the native event-loop stack.
A close cancels unfinished shutdown with ECANCELED after pending write callbacks
and before the close callback. There is no socket or bidirectional pipe support.

QEMU run 2 passes the cumulative V8/libuv gate. The stderr fixture queues output
then shutdown, checks deferred write/shutdown/close callback order, rejects a
second shutdown and further writes without initializing rejected requests,
checks the live descriptor at shutdown completion, and confirms native writes
return the closed-pipe error. The existing 16 KiB stdout fixture also queues a
shutdown immediately before close; it checks one cancelled shutdown callback,
after all three write callbacks and before the close callback. Both loops close.
The run returns zero with 72 parks and zero waiters, a 305729152-byte global
allocator peak, and the actual stderr payload and exact stdout data present.

Run 1 also returned zero but its stdout assertion failed because stderr payload
arrived in the middle of stdout vector delivery. Run 2 verifies that exact stderr
payload occurs once and excludes it from the stdout sequence comparison; the
streams do not promise global output ordering. Both raw logs are retained.
The rebuilt fs object reports its existing type-limits warning; no new stream
compiler warning was reported.

This is a libuv prerequisite, not Node execution acceptance. Stream reads,
duplicate-fd ownership, write/shutdown authority revocation, sustained lifecycle
stress and the full Node/TypeScript milestones remain outstanding.
