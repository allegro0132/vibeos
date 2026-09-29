# Libuv loop metrics on the target

Loop initialization now creates the internal metrics mutex and frees the
internal fields if mutex creation fails. Loop close destroys this lock before
freeing its storage. UV_METRICS_IDLE_TIME is supported; native parking is
bracketed by upstream provider entry/update functions. Zero-duration polling
is not counted as idle time.

The QEMU gate passes eight independent loop init/configure/timer/close cycles.
Each checks idle time starts at zero, becomes positive while waiting, does not
exceed elapsed time, and reports a nonzero loop count. Existing sync, V8 and
capability file/IO gates remain passing. Native return: 26 parks, zero waiters.
The memory samples match the preceding sync run. Allocation-failure injection
and Node lifecycle execution are not covered by this test.
