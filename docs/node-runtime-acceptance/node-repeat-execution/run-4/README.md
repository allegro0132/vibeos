# 100 sequential real Node executions on QEMU

All 100 invocations pass the shared main-file project fixture (CJS/ESM,
sync/Promise files, stdin, Buffer/timers/zlib and subtree isolation), their
normal Node teardown and Rust invocation release. The verifier requires all
100 main execution sequences, teardown markers, return-0/released markers
and memory samples. Each raw invocation reports zero standard-stream waiters.
The Node/V8 process initializes once and shuts down after invocation 100;
each invocation has fresh stack/TLS, page admission, files, environment,
project capability projection and I/O. Process synchronization is explicitly
shared for upstream global locks.

Host QEMU wall time: 64.5674 seconds. Global kernel heap peak: 305765120 bytes.
At the recorded cleanup point live bytes range from 36186624 to 36186880
(256-byte variation). Bump remaining is 720679040 after the first iteration,
452243584 after the second, then remains unchanged through iteration 100.
Freed large regions are therefore reused under this workload; bump consumption
is not interpreted as a proportional live-memory leak. These are whole-kernel
fixture heap measurements, not per-Node RSS.

The native page owner destructor asserts zero live allocations before unregistering
each owner. The fixture also drops its capability spaces between iterations.
This run does not provide individual handle/capability inventory counts or
qualify repeated cancellation/failure cycles, every libuv resource, durable
filesystems, production VSH pipelines/SSH, or complete M4 acceptance.
