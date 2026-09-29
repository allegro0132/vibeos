# Native libuv synchronization prerequisite

The dedicated backend implements regular/recursive mutexes, counting
semaphores and condition-variable waits through the admitted native task's
semaphore/wait bridges. Contention parks the C/C++ stack; no pthread or busy
scheduler loop is used. Timed condition waits reacquire the mutex. Signal may
wake extra waiters, as allowed by condition-variable spurious wake semantics.
The current contract remains one active native task; concurrent Node instances
and process-global locks across repeated invocation lifetimes are NOT qualified.

Run 1 failed because the new sync marker preceded the fixture's required
9 KiB stdout pattern. It was stopped after the fatal fixture assertion; raw
failure evidence is preserved. Run 2 moves sync checks after the IO fixture.
It passes recursive depth 2, three semaphore permit consumptions, empty
trywait, regular-lock busy status, and a 2 ms parked condition timeout with
ownership reacquired. Existing V8 expression/exception/GC/teardown, timer,
stdio backpressure, rooted file/path and revocation checks also pass. Native
return: 17 parks, zero waiters; QEMU exits normally. Actual GYP libuv archive
and all thin members are hashed by the linker harness.

Signal delivery to a concurrently waiting native task, indefinite waits,
rwlocks, full Node startup and safe JavaScript cancellation remain unqualified.
Node metrics uses an internal loop mutex that still needs initialization in
vibeos-loop.c before its metrics API can be used. No Node milestone is claimed.
