# Node link attempt 9

The complete Node firmware link still fails with 69 unresolved
libuv symbols. The stdio handle lifecycle and nonblocking stream writer resolve
9 names since run 8. Inputs remained unchanged during the link:
True. See results.json and raw link.log.

The separate V8/libuv QEMU gate passes in libuv-stream-write/run-3. Node itself
has not linked or executed; no CJS/ESM/TypeScript acceptance is established.
