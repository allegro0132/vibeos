# Capability-backed access checks

QEMU passes synchronous and deferred asynchronous libuv access checks on the
invocation root. F_OK and R_OK require a fresh READ lease; W_OK additionally
requires WRITE authority. A read-only invocation can read but is denied W_OK.
Checks cover a followed symlink, missing files, path escape, invalid mode bits,
revoked authority, and exactly one deferred callback. X_OK returns ENOTSUP.
W_OK establishes authority only; file-content writing is not yet implemented.

The cumulative real V8 and libuv gate passes with 37 parks, zero waiters and
normal shutdown. Peak allocator usage is 305727104 bytes for this fixture.
This is prerequisite evidence, not Node execution or TypeScript acceptance.
