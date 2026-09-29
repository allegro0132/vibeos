# Node link attempt 17

Complete firmware linking still fails with 18 unresolved libuv symbols. The four
thread exclusion APIs resolve since run 16. Archive inputs remained unchanged
during linking. Node Worker rejection compiles, but JavaScript has not executed.
Separate cumulative real-V8/libuv QEMU evidence is in libuv-thread-excluded.
No Node execution milestone is claimed.
