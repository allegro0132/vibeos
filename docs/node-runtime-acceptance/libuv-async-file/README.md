# Async regular-file writes and truncate

libuv file writes and ftruncate now begin Rust-owned pending transactions and
poll them through the existing event-loop request queue. Begin validates a
fresh WRITE lease and descriptor mode. Writes copy a bounded 1024-byte chunk
before returning, retain only owned data/descriptor/transaction state, and
advance the cursor only after successful publication. The lease remains held
through publication. No synchronous native park is invoked from these async
operations. Pending backend futures register the native notification waker.

QEMU verifies deferred write completion, EBUSY loop-close while queued, modified
file content, deferred truncation and resulting size. Cancelling a queued write
or truncate produces one ECANCELED callback and preserves bytes/length. The
cumulative V8/libuv gate passes: 62 parks, zero waiters, normal shutdown and
305728128-byte allocator peak.

The fixture is volatile: delayed durable publication, timer progress during
that delay, concurrent writers and mid-publication revocation are unqualified.
Async file reads and create/truncate-open remain pending, as do positioned IO,
full Node execution and the official TypeScript toolchain. This prerequisite
does not establish a new milestone.
