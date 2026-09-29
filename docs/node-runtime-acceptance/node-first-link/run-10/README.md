# Node link attempt 10

The complete Node firmware link fails with 64 unresolved libuv
symbols. Stream reads, queued writes and shutdown resolve 5 names since
run 9. Inputs remained unchanged during the link:
True. Exact symbols and diagnostics are preserved.

The separate real-V8/libuv QEMU gate passes in libuv-stream-read. Node itself
has not linked or executed; no CJS/ESM/TypeScript acceptance is established.
