# Native C++ timed-wait bridge prerequisite

Four-hart QEMU execution passed with the recorded kernel/source hashes. Real
C++ frames call the timed wait C ABI twice with a 3000-us never-ready predicate.
The native runner parks exactly twice and polls Rust timer/notification futures
on the executor. Same-hart peer progress is observed; elapsed monotonic time
is at least 6000 us. The C++ guard remains alive across both parks, destroys
once on normal return, and task identity remains stable. Immediate readiness,
zero-timeout and invalid-negative-timeout checks also pass.

This validates the timed normal-return path, not arbitrary C++ cancellation,
V8 termination, semaphore handles, external readiness wake routing, untimed
park completion, or wake/deadline races. The current private runner treats
active-future cancellation as fatal and must not be exposed through VSH until
cooperative termination is implemented. Other prior native/VSH checks pass.
Real V8/Node execution remains unqualified.
