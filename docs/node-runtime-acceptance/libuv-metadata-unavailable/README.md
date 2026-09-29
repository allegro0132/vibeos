# Explicitly unavailable Unix file metadata operations

The current capability filesystem has no Unix owner/group, mutable mode bits
or mutable wall-clock timestamps. chmod/fchmod, chown/fchown/lchown and
utime/futime/lutime therefore return ENOTSUP instead of pretending to apply
unrepresented metadata. This is an explicit port compatibility limitation,
not implementation of Unix metadata semantics.

These APIs use the normal filesystem request initialization and ownership path.
Synchronous calls set req.result and return ENOTSUP. Async calls retain owned
path strings, register with the loop and dispatch the error through one deferred
callback. Queued cancellation uses the existing filesystem cancellation boundary.
No native filesystem operation is admitted by this branch.

QEMU checks all eight synchronous request types/results and all eight asynchronous
callbacks, one additional queued cancellation, EBUSY loop close with requests
outstanding, normal cleanup, unchanged native file identity/link count/size/type/
generation and unchanged contents. The cumulative V8/libuv gate passes with
95 parks, zero waiters, normal shutdown, 305733248-byte allocator peak and
36162176-byte post-run live memory.

Node JavaScript exceptions/promises have not executed yet. Complete Node linking,
TypeScript and tools depending on mutable Unix metadata remain unqualified.
