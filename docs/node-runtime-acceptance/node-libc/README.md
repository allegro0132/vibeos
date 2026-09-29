# Newlib calls needed by Node filesystem code

The native newlib bridge adds _stat using the existing capability-rooted
metadata service, preserving the caller's output on failure and reporting
EOVERFLOW if newlib's fields cannot represent metadata. This follows symlinks
inside the granted root. Ownership/timestamps remain zero because the backing
file store has no POSIX ownership/timestamp model; modes reflect the current
read-only native bridge. _link explicitly returns ENOTSUP: no hard-link creation
operation is granted through this native bridge yet. sleep uses the existing
monotonic deadline and parked native stack rather than blocking the executor.

The QEMU gate calls the actual newlib stat/link wrappers and sleep: file via
symlink, root directory, escape with unchanged output, symlink loop, missing
path, denied hard-link with absent destination, permission revocation, zero
sleep and a one-second monotonic sleep. All pass, alongside existing V8 and
libuv checks. Native return: 29 parks, zero waiters; normal QEMU exit. Archive
members and test inputs are hashed in the linker and execution reports.

This closes the three newlib names seen in Node link attempt 2, but a new Node
firmware link is still required to measure the remaining symbol set. No Node
execution, interruption of sleep, large metadata overflow injection, or full
POSIX filesystem compatibility is claimed.
