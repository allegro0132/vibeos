# Rooted mkdir, rename and rmdir

These libuv APIs use a fresh WRITE capability lease and real file-tree
transactions. Synchronous publication parks the native task; asynchronous
requests retain the transaction and lease in Rust, and the event loop polls
publication with a Rust waker before dispatching the callback. Rename owns both
path strings until completion. No C buffers remain borrowed across suspension.

rmdir checks the final inode without following a symlink, because the underlying
store's generic remove operation can also remove ordinary files. Rename maps
file/directory replacement mismatches to EISDIR or ENOTDIR. Existing names map
to EEXIST and nonempty directories to ENOTEMPTY. Unix mkdir permission bits do
not alter capability authority or install Unix credential checks; special mode
bits return ENOTSUP.

QEMU verifies synchronous mkdir, rmdir and file renaming; three deferred
callbacks (directory rename, child rmdir, mkdir); descendant preservation after
rename; missing old path; existing-directory, nonempty-directory and type
errors; escaped creation and rename destinations; read-only admission refusal
for all three operations; and denial after revocation. The fixture returns to
its original names, then passes all cumulative scandir, V8 and libuv tests.
The run returns zero with 45 parks, zero waiters and normal shutdown. Peak
allocator usage is 305727104 bytes.

This volatile fixture does not qualify slow durable publication, concurrent
writers, all POSIX rename corner cases, mid-publication revocation, permission
bit emulation, or Node execution. Full Node and TypeScript acceptance remain
pending; this is not a new runtime milestone.
