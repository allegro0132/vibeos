# Capability-backed link operations

uv_fs_link and relative uv_fs_symlink use native tree transactions with fresh
WRITE authority. The source and destination of hard links are cwd-aware paths;
the source of a symlink is literal target text, interpreted relative to its
link parent. Synchronous publication parks the native task. Asynchronous
publication retains an owned transaction and lease, and completes through the
existing filesystem request loop. The libuv adapter copies both input strings.
Queued uv_cancel prevents transaction admission; started work keeps the existing
EBUSY cancellation boundary. Hard links do not follow the final source symlink.

QEMU verifies a relative symlink's readlink text and resolved inode, hard-link
inode identity and link counts, existing-destination error, symlink-target and
hard-link destination escape denial, async symlink and hard-link completion,
mutation of submitted caller strings without changing the request, queued
cancellation leaving no destination, read-only admission denial and rejection
after capability revocation. All fixture entries are removed afterward.
Cumulative V8/libuv checks pass with 93 parks, zero waiters, normal shutdown,
305733248-byte allocator peak and 36162176-byte post-run live memory.

Absolute symlink targets and nonzero platform-specific symlink flags return
ENOTSUP: the current FileTreeRoot stores relative targets. Dangling/directory
links, hard links to symlinks, durable publication latency and concurrent
namespace mutation require further qualification. This is not Node module or
TypeScript execution acceptance; complete Node still has unresolved interfaces.
