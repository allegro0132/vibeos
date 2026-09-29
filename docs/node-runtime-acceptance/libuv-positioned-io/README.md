# Positioned synchronous/asynchronous regular-file IO

Native read/write bridges now accept offset=-1 for cursor-based IO or a
nonnegative explicit offset. Reads and successful writes with explicit offsets
do not advance the descriptor cursor. Owned async reads retain whether cursor
advancement is required; async writes update it only for offset=-1. Libuv keeps
its requested offset separate from the native pending-request ID, so repeated
polls preserve the original positioning intent. Existing nonpositioned callers
continue through wrappers using -1. Append writes still select end-of-file
under the writer claim; explicit-offset append behavior is not qualified here.

QEMU checks a synchronous positioned read/write pair, a deferred positioned
write/read pair, byte values and an unchanged cursor. Offsets below -1 return
EINVAL; an overflowing write at INT64_MAX returns EINVAL without extending the
file; positioning stdio returns ESPIPE. Existing async read/write, revocation,
file lifecycle, excluded operations and real V8 gates continue to pass.
The run exits normally with 67 parks, zero waiters and peak allocator usage
305729152 bytes.

This volatile fixture does not qualify persistent storage latency, concurrent
cursor-based IO, full multi-buffer vector operations, unlinked-open lifetime or
explicit-offset append. Async create-open and complete Node/TypeScript execution
remain pending. This prerequisite does not establish a new runtime milestone.
