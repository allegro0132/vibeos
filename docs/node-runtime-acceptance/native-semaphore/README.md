# Native semaphore C ABI prerequisite

Four-hart QEMU passed with the recorded kernel/source hashes. The actual C++
fixture consumes an initial permit, observes an empty zero-timeout result,
parks for an empty 3000-us wait, posts a permit and consumes it, then destroys
the handle. Subsequent signal/wait operations reject the stale handle. Negative
initial count and signed-count overflow are rejected. The runner now observes
three parks (two predicate waits plus one semaphore timeout), same-hart peer
progress, and at least 9000 us elapsed. Other native/VSH checks also passed.

This does not yet qualify cross-context foreign-handle rejection, handle-table
exhaustion, a post waking an already parked semaphore, external backend wake
routing, active-wait destruction, or cooperative cancellation. These paths
must be tested as integration progresses. Real Abseil/V8/Node use remains
unqualified.
