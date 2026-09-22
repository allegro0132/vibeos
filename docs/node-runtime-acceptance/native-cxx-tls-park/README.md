# C++ TLS across native executor parking

The native suspension fixture now owns a real GCC emutls context instead of
using a synthetic tp. Its initialized and zero-filled, 64-byte-aligned C++
thread_local values are checked and incremented before the first yield and
after each of three resumptions. Both direct context switching and executor
parking execute this fixture. C ABI context arguments use opaque void pointers.

Before each resume, the caller registers the context, then enters its protected
stack with tp pointing at it. After yielding back and restoring the caller's
tp/FCSR, registration is released while the TLS owner stays alive inside the
pinned control block. Actual TLS storage survives the wait. The same-hart peer
must advance during each of the three timer waits, and C++/Rust destructors
run only on normal final return. The known finite fixture is drained before
stack/TLS destruction if its future is dropped.

Four-hart QEMU passes these checks and the existing page/cache/VSH probes.
This run also used nonidentical physical/logical hart numbering. The exact
kernel and source hashes are retained in results.json. It is not arbitrary
V8 cancellation, dynamic TLS initialization, thread-exit TLS destructors,
libc runtime integration, capability admission, or V8/Node execution.
