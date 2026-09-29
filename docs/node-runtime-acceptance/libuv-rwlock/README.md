# Libuv read/write lock prerequisite

The native backend adds a shared-reader count and exclusive-writer bit with
atomic acquisition and the existing parked native wait bridge. Readiness
callbacks run on the native stack, never in the Rust scheduler. Writers record
the native task identity for owner validation on unlock. No pthreads or native
busy wait are introduced.

QEMU checks two simultaneous read acquisitions, busy write acquisition until
both readers release, rejection of read/write try-lock while exclusively held,
and successful write acquisition after release. Existing mutex/semaphore,
condition timeout, eight metrics loops, V8 expression/exception/GC and rooted
file/backpressure gates all pass with zero remaining waiters.

Concurrent contention, fairness and full Node execution remain unqualified.
Only one native context is admitted by the current platform. This prerequisite
is not a Node compatibility or repeated Node invocation milestone.
