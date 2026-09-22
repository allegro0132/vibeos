# Native clock ABI prerequisite

QEMU four-hart RV64GC execution passed using the kernel and source hashes in
results.json. The actual C++ fixture calls both Rust clock ABI functions before
and after each of three native yields, requires positive Unix time and
nonnegative monotonic time, and rejects backwards readings. The same fixture
also runs with executor parking and same-hart peer progress. Existing TLS,
RAII, page reclamation and VSH checks passed.

No absolute accuracy, timezone isolation, unsupported-board clock behavior,
or clock failure injection is qualified here. Nondecreasing readings do not
prove a minimum elapsed interval. The shared WASI RTC lock prevents native
reads from racing its two-register latch sequence. No real V8/Node execution
is claimed; their acceptance remains open.
