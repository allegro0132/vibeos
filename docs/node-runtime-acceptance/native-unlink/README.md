# Capability-native unlink prerequisite

QEMU RV64GC/LP64D, four harts, 128 MiB: PASS. A real in-device FileTreeRoot is
populated transactionally. Native calls verify missing grant, read-only root,
parent escape and directory deletion rejection, successful deletion of a file,
ENOENT-equivalent result for a repeat, and rejection after CSpace revocation.
The directory remains intact. Previous native probes also pass.

FileGrant retains the invocation Space and root capability handle, never an
ambient filesystem. Each unlink acquires a fresh WRITE InvocationLease. Paths
are bounded UTF-8, parsed relative to that root; absolute paths refer to the
invocation's virtual root. A file transaction uses commit_authoritative through
the native parking bridge. No CSpace lock is held during suspension.

Current revocation semantics follow existing CSpace InvocationLease rules:
revocation rejects subsequent admission, but an already admitted transaction
may complete. Mid-publication persistent-storage revocation, tool/project mount
separation, symlink cases and the complete user-requested revocation contract
are NOT qualified. The test uses the volatile real file-tree backend; it does
not prove durable storage behavior.

The newlib _unlink adapter passes target compilation and mock errno checks.
QEMU invokes the Rust C ABI directly; actual libc file IO, V8 and Node are not
executed. M1 remains incomplete.
