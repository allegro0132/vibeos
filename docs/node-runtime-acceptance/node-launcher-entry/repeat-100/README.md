# Launcher ABI: 100 serial invocations

Link 61 runs upstream Node main-file startup through vibeos_node_run 100 times,
with one process platform and a shared native synchronization domain. Each run
has fresh Node environment/isolate, native TLS, project grants and stdio.

All 100 project/stream/CJS/ESM/timer/Promise/zlib/boundary checks pass. Each
native return is 0, each waiter count is 0, and each invocation is released.
The QEMU verifier validates all 100 execution/teardown/memory markers; the
saved serial log was additionally checked for all 100 zero-waiter returns.
Elapsed host wall time: 66.726 seconds.
Post-cleanup live heap: 36186624–36186880 bytes.
Peak global heap: 305765120 bytes.

This is ordinary-success lifecycle evidence with patch 0057. It does not
qualify repeated failure/cancellation cycles, production VSH launch admission,
or a complete capability/handle inventory audit. The pre-existing embedding
100-cycle test does not substitute for this launcher-entry test.
