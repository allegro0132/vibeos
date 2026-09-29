# Node link attempt 11

The complete firmware link still fails with 58 unresolved libuv
symbols. Invocation cwd and environment resolve 6 names since run 10.
Inputs unchanged during linking: True.

The real-V8/libuv QEMU environment gate passes separately. Node itself has not
linked or executed; CJS/ESM and TypeScript acceptance remain pending.
