# Synchronous create, exclusive-open, truncate-open and append

Native open now admits explicit CREATE, EXCL, TRUNC and APPEND ABI bits. The
newlib/libuv adapters normalize libc flags and reject unknown bits. Creating or
mutating a file requires READ+WRITE authority. Descriptor capacity is reserved
before publication; a transaction resolves the new inode identity before commit
so a reused path cannot silently retarget the returned descriptor. Exclusive
creation tests the final entry without following a symlink. Append chooses its
position under the file tree's writer claim, ignoring a previous seek position.
Ordinary mode bits do not create Unix credential authority; libuv rejects
unsupported special mode bits. Async create/truncate remains ENOTSUP until its
retained-future path is implemented.

Run 2 passes QEMU creation and byte-for-byte readback of a generated JS file,
append after seeking to zero, exclusive collision for regular files and
symlinks, escaped creation denial, truncate-open observed by an existing fd,
read-only authority denial, and revocation denial. It also checks newlib _open
reports EEXIST. All cumulative V8/libuv checks pass: 60 parks, zero waiters,
normal shutdown, peak allocator usage 305728128 bytes.

Host libc contracts pass after extending stale mock linkage for previously
added stat/sleep bridges and correcting a mock signature. The earlier failed
host logs are retained. These mocks only qualify flag/error translation.
Run 1 predates the newlib EEXIST fix and check; both target runs are retained.

Async file IO, dangling-symlink creation semantics, unlinked-open lifetime,
positioned writes, efficient large-file publication, resource limits and durable
create/truncate testing remain pending. Node startup and official TypeScript
execution have not passed; this prerequisite does not establish a milestone.
