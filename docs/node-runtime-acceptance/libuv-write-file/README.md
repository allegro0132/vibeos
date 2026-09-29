# Existing-file native writable descriptors

Native open admits read-only, write-only and read/write modes for existing
regular files. Writable opens require WRITE in addition to READ authority;
unsupported flags remain rejected. Newlib and libuv translate each supported
mode explicitly, so create/append/truncate flags cannot silently become a
plain write-open. Descriptor identity is a root-scoped file ID, and reads,
metadata and seek-to-end resolve its current generation.

Synchronous native/libuv writes copy at most 1024 bytes into native-owned
storage, retain a fresh WRITE lease, park through the range edit and authoritative
transaction commit, and update the cursor only after success. Synchronous
uv_fs_ftruncate similarly publishes through the file tree without changing the
cursor. Async file writes and ftruncate still return ENOTSUP rather than parking
an event-loop callback. Stdio async writes retain their existing implementation.

QEMU passes writable open, rename followed by descriptor write, reading abXYef
through the same descriptor, truncation followed by zero-extension, live fstat
size, read-only descriptor write/truncate denial, write-only read denial,
read-only capability refusal at open, and write/truncate refusal after capability
revocation. All handles close and cumulative V8/libuv checks pass: 53 parks,
zero waiters, normal shutdown, allocator peak 305728128 bytes. File-store host
tests also pass (31 passed, 5 ignored).

Creation, open-time truncation, append, positioned/asynchronous file IO, efficient
large-file staging, full resource accounting, and unlinked-open inode lifetime
remain pending. An identity removed from the root is currently unavailable to
subsequent descriptor reads; POSIX unlink-while-open is not claimed. The fixture
uses volatile storage and does not qualify durable write publication. This is
not Node execution, complete compiler output support or a new milestone.
