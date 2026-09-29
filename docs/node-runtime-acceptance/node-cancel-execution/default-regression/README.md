# Non-cancelled Node regression with cooperative checkpoints

Uses the same patched V8 archive and native checkpoint bridge as the cancellation
gate, with cancellation disabled. The same-hart peer is joined normally without
requesting cancellation. All CJS/ESM, sync/Promise file, stdin, Buffer/timer,
zlib and exit/teardown checks pass on QEMU. Native return is 0 and waiters=0.
