QEMU run 2 passes actual capability-rooted libuv open, synchronous read,
regular-file fstat and close. It checks missing paths, traversal, unsupported
write flags, stale descriptors, deferred open/close callbacks, busy-loop
rejection and request reuse from a completion callback. Revocation denies
subsequent metadata/open while close remains permitted for cleanup. The same
image passes stream backpressure and V8 expression/exception/GC/teardown,
returning with 14 native parks and zero stream waiters.

The fixture grants READ|REVOKE, never WRITE. Run 1 is retained: its READ-only
fixture attempted revoke and correctly failed with InsufficientRights; the
fatal test was explicitly interrupted. REVOKE is only used by the trusted
fixture hook, not a new public libuv operation.

Descriptor metadata is the snapshot captured by the existing FileTreeRoot
reader (FileId, size, link count, change generation). The libuv adapter marks
it as a read-only regular file; unavailable POSIX ownership/timestamps are
zero, not synthesized from host state. This does not establish live metadata
after mutation, path stat/lstat, realpath, symlink resolution, positioned reads,
ordinary-file async read/write, or durable-storage execution. The fixture tree
is volatile. Open/close/stat use resident metadata and do not park the loop;
ordinary reads use the existing suspendable bridge. Production Node modules
and TypeScript tools remain unimplemented.
