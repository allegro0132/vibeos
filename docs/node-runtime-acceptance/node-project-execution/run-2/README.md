# Passing project CJS/ESM and file execution

Real Node reads a private capability-granted project tree in QEMU. Its upstream
createRequire loads dep.cjs, which requires leaf.cjs (answer 42). A function in
the CJS module performs dynamic import of dep.mjs, which imports leaf.mjs
(answer 99). Module source is read/compiled/executed on VibeOS; the host only
prepares literal test fixture files in the firmware.

The script writes/reads a file synchronously, reads it with fs.promises, creates
and reads a second file with fs.promises.writeFile/readFile, then overwrites it
with a shorter value and verifies truncation. Existing Buffer/Promise/timer,
asynchronous zlib, supported metadata and unsupported-boundary checks also pass.
Every project completion flag must be set before the native entry returns zero.

Normal environment/isolate/platform/process teardown passes; the run returns 0
with 11 parks, zero waiters and normal QEMU shutdown. Shared allocator accounting:
live before 775168, live after 36160512, peak 305742336 bytes. This is not RSS or
100-cycle reclamation evidence. The previous asynchronous-open failure is kept.

Full M2 remains incomplete: stdin, nonzero exit, cancellation and production VSH/
SSH capability launcher integration still require acceptance. Package exports,
node_modules resolution, read-only tool mounts, TS/tsx and complete compatibility
qualification are not established by these four project modules.
