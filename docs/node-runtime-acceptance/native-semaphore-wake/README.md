# Native semaphore backend wake and owner checks

Four-hart QEMU passed using the recorded kernel/source hashes. C++ obtains a
semaphore, grants a posting right to a test backend, then parks in an indefinite
wait. A same-hart kernel task posts after a 2 ms timer; the native caller resumes
and consumes exactly one permit (the next zero-timeout acquisition fails).
The runner records four parks: two predicate timeouts, one semaphore timeout,
and this indefinite semaphore wait. Normal C++ return and prior checks pass.

Two separately admitted native contexts also test handle authority. A foreign
context's post is rejected; the owning context posts successfully and destroys
the handle. The backend's posting right is explicitly resolved while its owner
is admitted; the backend does not look up raw handles later.

This does not qualify cross-hart completion, outstanding-right cancellation or
revocation, libuv backend integration, V8 semaphores, or real V8/Node execution.
